//! Stateless Solana Pay invoicing: derive, request, verify.
//!
//! A `wasm32-wasip2` tool component cannot persist anything, so nothing here
//! stores state. An invoice's reference is *derived* from the order, and the
//! chain is the only record that it was paid. See `docs/INVOICE-SPEC.md`.
//!
//! Design rules, same as the rest of the engine: deny by default, raw integer
//! amounts, no floats in the decision path, and evidence that cannot be fully
//! explained is `Unknown`, never a guess.

use crate::crypto::{ata_address, parse_pubkey, TOKEN_PROGRAM};
use crate::rpc::{fetch_classic_mint_decimals, RpcTransport};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;

#[cfg(test)]
mod tests;

/// Domain separator for the reference namespace. Hashed rather than written as
/// a base58 literal so the derivation is auditable from this source alone.
const NAMESPACE_SEED: &[u8] = b"safe-hands-invoice-namespace-v1";

/// Seed prefix for every invoice reference.
const REFERENCE_PREFIX: &[u8] = b"safe-hands-invoice";

/// Upper bound on free-text URL fields (label/message/memo), in bytes.
const MAX_TEXT_BYTES: usize = 200;

/// Upper bound on signatures examined for one reference. A reference is
/// invoice-scoped, so a legitimate invoice has one; anything beyond this is
/// griefing and is reported rather than silently truncated.
const MAX_SIGNATURES: usize = 20;

/// The namespace "program id" under which references are derived.
///
/// This is a hash, not a deployed program. Deriving under it guarantees every
/// reference is off-curve: no private key exists, so a reference can never
/// sign, own, or hold anything. It is an index and nothing else.
pub fn reference_namespace() -> Pubkey {
    Pubkey::new_from_array(Sha256::digest(NAMESPACE_SEED).into())
}

/// Derive the Solana Pay reference for an order.
///
/// Deterministic in `(merchant, order_id, salt)`, which is what removes the
/// need to store it. `order_id` and `salt` are hashed so any length is
/// accepted while respecting the 32-byte seed limit.
pub fn derive_reference(merchant: &Pubkey, order_id: &str, salt: &str) -> Result<Pubkey, String> {
    if order_id.trim().is_empty() {
        return Err("order_id must not be empty".to_string());
    }
    let order_hash: [u8; 32] = Sha256::digest(order_id.as_bytes()).into();
    let salt_hash: [u8; 32] = Sha256::digest(salt.as_bytes()).into();
    let merchant_bytes: &[u8] = merchant.as_ref();
    Pubkey::derive_program_address(
        &[REFERENCE_PREFIX, merchant_bytes, &order_hash, &salt_hash],
        &reference_namespace(),
    )
    .map(|(reference, _bump)| reference)
    .ok_or_else(|| "reference derivation found no off-curve address".to_string())
}

/// Render a raw smallest-unit amount as a Solana Pay decimal string.
///
/// Exact integer string manipulation — no floating point anywhere. Trailing
/// fractional zeros are trimmed and a whole amount emits no decimal point.
pub fn raw_to_decimal_string(raw: u64, decimals: u8) -> String {
    if decimals == 0 {
        return raw.to_string();
    }
    let decimals = decimals as usize;
    let digits = raw.to_string();
    let padded = if digits.len() <= decimals {
        format!("{}{}", "0".repeat(decimals + 1 - digits.len()), digits)
    } else {
        digits
    };
    let split = padded.len() - decimals;
    let (integer, fraction) = padded.split_at(split);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        integer.to_string()
    } else {
        format!("{integer}.{fraction}")
    }
}

/// Percent-encode a URL query value, keeping only RFC 3986 unreserved
/// characters literal. Rejects control characters outright rather than
/// encoding them, so untrusted text cannot smuggle framing into a rendered URL.
fn encode_query_value(input: &str, field: &str) -> Result<String, String> {
    if input.len() > MAX_TEXT_BYTES {
        return Err(format!(
            "{field} must be at most {MAX_TEXT_BYTES} bytes, got {}",
            input.len()
        ));
    }
    if input.chars().any(|c| c.is_control()) {
        return Err(format!("{field} must not contain control characters"));
    }
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    Ok(out)
}

/// An invoice request: everything needed to render a payment link and QR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvoiceRequest {
    pub merchant_owner: String,
    pub mint: String,
    pub reference: String,
    pub amount_raw: u64,
    pub decimals: u8,
    pub label: Option<String>,
    pub message: Option<String>,
    pub memo: Option<String>,
}

impl InvoiceRequest {
    /// Build the Solana Pay transfer-request URL.
    pub fn url(&self) -> Result<String, String> {
        if self.amount_raw == 0 {
            return Err("amount_raw must be greater than zero".to_string());
        }
        // Validate every address rather than trusting the caller's strings.
        parse_pubkey(&self.merchant_owner)?;
        parse_pubkey(&self.mint)?;
        parse_pubkey(&self.reference)?;

        let mut url = format!(
            "solana:{}?amount={}&spl-token={}&reference={}",
            self.merchant_owner,
            raw_to_decimal_string(self.amount_raw, self.decimals),
            self.mint,
            self.reference
        );
        for (key, value) in [
            ("label", &self.label),
            ("message", &self.message),
            ("memo", &self.memo),
        ] {
            if let Some(value) = value {
                if !value.is_empty() {
                    url.push_str(&format!("&{key}={}", encode_query_value(value, key)?));
                }
            }
        }
        Ok(url)
    }
}

/// What a payment must satisfy to count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentExpectation {
    pub merchant_owner: String,
    pub mint: String,
    pub reference: String,
    pub requested_amount_raw: u64,
    /// Unix seconds. A payment finalized after this is `Late`.
    pub expiry_unix: Option<i64>,
}

/// Chain evidence for one accepted payment. Requested and observed amounts are
/// always both present; observed never overwrites requested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentEvidence {
    pub signature: String,
    pub payer_owner: String,
    pub observed_amount_raw: u64,
    pub requested_amount_raw: u64,
    pub block_time: Option<i64>,
    pub slot: u64,
    /// Finalized after the invoice expiry. Carried on the evidence rather than
    /// collapsed into the verdict, because a payment can be late *and* the
    /// wrong amount, and hiding either from the operator is a real loss.
    pub late: bool,
}

/// The outcome of verifying one invoice against finalized chain evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentVerdict {
    /// No finalized transaction references this invoice.
    Unpaid,
    /// Exactly one owner-signed classic SPL transfer of the exact amount.
    Paid(PaymentEvidence),
    Underpaid(PaymentEvidence),
    Overpaid(PaymentEvidence),
    /// Otherwise valid, but finalized after expiry.
    Late(PaymentEvidence),
    /// Money moved but the structure is not unambiguous. Needs a human.
    Review {
        reason: String,
        signatures: Vec<String>,
    },
    /// Evidence could not be trusted. Fails closed.
    Unknown { reason: String },
}

impl PaymentVerdict {
    /// The evidence, when the verdict describes money actually received.
    pub fn evidence(&self) -> Option<&PaymentEvidence> {
        match self {
            Self::Paid(e) | Self::Underpaid(e) | Self::Overpaid(e) | Self::Late(e) => Some(e),
            _ => None,
        }
    }

    /// Short stable tag for logs, receipts, and operator copy.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Unpaid => "UNPAID",
            Self::Paid(_) => "PAID",
            Self::Underpaid(_) => "UNDERPAID",
            Self::Overpaid(_) => "OVERPAID",
            Self::Late(_) => "LATE",
            Self::Review { .. } => "REVIEW",
            Self::Unknown { .. } => "UNKNOWN",
        }
    }
}

fn rpc_error(response: &Value) -> Option<&Value> {
    response.get("error").filter(|error| !error.is_null())
}

/// One token-balance entry from `meta.pre/postTokenBalances`, strictly parsed.
#[derive(Clone, Debug)]
struct TokenBalance {
    account_index: u64,
    mint: String,
    owner: String,
    amount: u128,
    decimals: u8,
}

fn parse_token_balances(value: Option<&Value>) -> Result<Vec<TokenBalance>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let entries = value
        .as_array()
        .ok_or_else(|| "token balance list must be an array".to_string())?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let account_index = entry
            .get("accountIndex")
            .and_then(Value::as_u64)
            .ok_or_else(|| "token balance missing accountIndex".to_string())?;
        let mint = entry
            .get("mint")
            .and_then(Value::as_str)
            .ok_or_else(|| "token balance missing mint".to_string())?
            .to_string();
        // `owner` is what makes the payer attributable without a follow-up
        // account fetch that could race a closed account. Absent owner is not
        // guessable, so it is an error.
        let owner = entry
            .get("owner")
            .and_then(Value::as_str)
            .ok_or_else(|| "token balance missing owner".to_string())?
            .to_string();
        let amount_str = entry
            .pointer("/uiTokenAmount/amount")
            .and_then(Value::as_str)
            .ok_or_else(|| "token balance missing uiTokenAmount.amount".to_string())?;
        let amount = amount_str
            .parse::<u128>()
            .map_err(|_| format!("token balance amount is not an integer: {amount_str:?}"))?;
        let decimals = entry
            .pointer("/uiTokenAmount/decimals")
            .and_then(Value::as_u64)
            .and_then(|d| u8::try_from(d).ok())
            .ok_or_else(|| "token balance missing uiTokenAmount.decimals".to_string())?;
        out.push(TokenBalance {
            account_index,
            mint,
            owner,
            amount,
            decimals,
        });
    }
    Ok(out)
}

/// Net change for one account index in the expected mint.
fn delta_for(
    pre: &[TokenBalance],
    post: &[TokenBalance],
    index: u64,
    mint: &str,
) -> Option<i128> {
    let find = |list: &[TokenBalance]| {
        list.iter()
            .find(|b| b.account_index == index && b.mint == mint)
            .map(|b| b.amount)
    };
    let before = find(pre).unwrap_or(0);
    let after = find(post)?;
    Some(after as i128 - before as i128)
}

/// Outcome of examining one candidate transaction.
enum Candidate {
    /// No transfer to the merchant in the expected mint. Someone attached the
    /// reference to an unrelated transaction; ignoring it prevents griefing.
    Irrelevant,
    /// Money moved to the merchant but the structure is not unambiguous.
    Review(String),
    Accepted {
        payer_owner: String,
        observed_amount_raw: u64,
    },
}

/// Strictly examine one finalized transaction against the expectation.
fn examine_transaction(
    tx: &Value,
    expectation: &PaymentExpectation,
    merchant_ata: &str,
    mint_decimals: u8,
) -> Result<Candidate, String> {
    // A failed transaction moved no money.
    if tx.pointer("/meta/err").is_some_and(|e| !e.is_null()) {
        return Ok(Candidate::Irrelevant);
    }
    let account_keys = tx
        .pointer("/transaction/message/accountKeys")
        .and_then(Value::as_array)
        .ok_or_else(|| "transaction missing message.accountKeys".to_string())?;

    let key_at = |index: u64| -> Option<String> {
        account_keys.get(index as usize).and_then(|k| {
            k.as_str()
                .map(str::to_string)
                .or_else(|| k.get("pubkey").and_then(Value::as_str).map(str::to_string))
        })
    };

    // The reference must actually be in this transaction.
    let has_reference = account_keys.iter().any(|k| {
        let pubkey = k
            .as_str()
            .or_else(|| k.get("pubkey").and_then(Value::as_str));
        pubkey == Some(expectation.reference.as_str())
    });
    if !has_reference {
        return Ok(Candidate::Irrelevant);
    }

    let pre = parse_token_balances(tx.pointer("/meta/preTokenBalances"))?;
    let post = parse_token_balances(tx.pointer("/meta/postTokenBalances"))?;

    // Locate the merchant ATA by account index.
    let merchant_index = account_keys.iter().position(|k| {
        let pubkey = k
            .as_str()
            .or_else(|| k.get("pubkey").and_then(Value::as_str));
        pubkey == Some(merchant_ata)
    });
    let Some(merchant_index) = merchant_index else {
        return Ok(Candidate::Irrelevant);
    };
    let merchant_delta = delta_for(&pre, &post, merchant_index as u64, &expectation.mint);
    let Some(merchant_delta) = merchant_delta else {
        return Ok(Candidate::Irrelevant);
    };
    if merchant_delta <= 0 {
        return Ok(Candidate::Irrelevant);
    }

    // Every balance entry for this mint must agree with the on-chain mint.
    for entry in pre.iter().chain(post.iter()) {
        if entry.mint == expectation.mint && entry.decimals != mint_decimals {
            return Ok(Candidate::Review(format!(
                "token balance declares {} decimals but the mint account declares {mint_decimals}",
                entry.decimals
            )));
        }
    }

    // Exactly one distinct owner may fund this payment.
    let mut senders: Vec<(String, i128)> = Vec::new();
    for entry in post.iter().filter(|b| b.mint == expectation.mint) {
        if entry.account_index == merchant_index as u64 {
            continue;
        }
        let Some(delta) = delta_for(&pre, &post, entry.account_index, &expectation.mint) else {
            continue;
        };
        if delta < 0 && !senders.iter().any(|(owner, _)| owner == &entry.owner) {
            senders.push((entry.owner.clone(), delta));
        }
    }
    // A source account fully drained and closed appears only in `pre`.
    for entry in pre.iter().filter(|b| b.mint == expectation.mint) {
        if entry.account_index == merchant_index as u64 {
            continue;
        }
        let still_present = post
            .iter()
            .any(|b| b.account_index == entry.account_index && b.mint == entry.mint);
        if !still_present && entry.amount > 0 && !senders.iter().any(|(o, _)| o == &entry.owner) {
            senders.push((entry.owner.clone(), -(entry.amount as i128)));
        }
    }

    if senders.is_empty() {
        return Ok(Candidate::Review(
            "no source token account funded this transfer".to_string(),
        ));
    }
    if senders.len() > 1 {
        return Ok(Candidate::Review(format!(
            "split payment: {} distinct source owners",
            senders.len()
        )));
    }
    let payer_owner = senders[0].0.clone();

    // The authority on the transferring instruction must be the source owner:
    // a delegate is not the payer.
    let authority = find_transfer_authority(tx, merchant_ata)?;
    match authority {
        TransferAuthority::Missing => {
            return Ok(Candidate::Review(
                "no classic SPL transfer instruction to the merchant account".to_string(),
            ));
        }
        TransferAuthority::Unsupported(reason) => return Ok(Candidate::Review(reason)),
        TransferAuthority::Owner(authority) => {
            if authority != payer_owner {
                return Ok(Candidate::Review(format!(
                    "delegated transfer: authority {authority} is not the source owner {payer_owner}"
                )));
            }
        }
    }

    // The payer must have signed.
    let signer_count = tx
        .pointer("/transaction/message/header/numRequiredSignatures")
        .and_then(Value::as_u64);
    let payer_signed = match signer_count {
        Some(count) => (0..count).any(|i| key_at(i).as_deref() == Some(payer_owner.as_str())),
        None => account_keys.iter().any(|k| {
            k.get("pubkey").and_then(Value::as_str) == Some(payer_owner.as_str())
                && k.get("signer").and_then(Value::as_bool) == Some(true)
        }),
    };
    if !payer_signed {
        return Ok(Candidate::Review(format!(
            "source owner {payer_owner} did not sign this transaction"
        )));
    }

    let observed = u64::try_from(merchant_delta)
        .map_err(|_| "merchant balance delta exceeds u64".to_string())?;
    Ok(Candidate::Accepted {
        payer_owner,
        observed_amount_raw: observed,
    })
}

enum TransferAuthority {
    Owner(String),
    Unsupported(String),
    Missing,
}

/// Find the authority of the classic SPL transfer that credited the merchant.
fn find_transfer_authority(tx: &Value, merchant_ata: &str) -> Result<TransferAuthority, String> {
    let mut instructions: Vec<&Value> = Vec::new();
    if let Some(list) = tx
        .pointer("/transaction/message/instructions")
        .and_then(Value::as_array)
    {
        instructions.extend(list.iter());
    }
    if let Some(inner) = tx.pointer("/meta/innerInstructions").and_then(Value::as_array) {
        for group in inner {
            if let Some(list) = group.get("instructions").and_then(Value::as_array) {
                instructions.extend(list.iter());
            }
        }
    }

    let mut result = TransferAuthority::Missing;
    for instruction in instructions {
        if instruction.get("program").and_then(Value::as_str) != Some("spl-token") {
            continue;
        }
        if instruction.get("programId").and_then(Value::as_str) != Some(TOKEN_PROGRAM) {
            continue;
        }
        let Some(parsed) = instruction.get("parsed") else {
            continue;
        };
        let kind = parsed.get("type").and_then(Value::as_str).unwrap_or_default();
        if kind != "transfer" && kind != "transferChecked" {
            continue;
        }
        let Some(info) = parsed.get("info") else {
            continue;
        };
        if info.get("destination").and_then(Value::as_str) != Some(merchant_ata) {
            continue;
        }
        // `multisigAuthority` does not mean what it looks like here.
        //
        // Solana Pay attaches the invoice reference as an extra read-only
        // account on the transfer instruction. The SPL Token program ignores
        // it when the authority is an ordinary wallet, but the RPC's
        // jsonParsed formatter sees more accounts than TransferChecked needs
        // and renders the *multisig* variant: `multisigAuthority` holds the
        // real owner, and the reference is listed under `signers` despite
        // never having signed anything.
        //
        // So the field is read as the effective authority rather than
        // rejected. A genuine SPL multisig is still refused, one step later
        // and on stronger evidence: its token account is owned by a Multisig
        // account, and a Multisig account never appears in the transaction's
        // signer list, so the owner-must-have-signed check rejects it.
        let authority = info
            .get("authority")
            .or_else(|| info.get("multisigAuthority"))
            .and_then(Value::as_str);
        let Some(authority) = authority else {
            return Ok(TransferAuthority::Unsupported(
                "transfer instruction has no authority field".to_string(),
            ));
        };
        if let TransferAuthority::Owner(previous) = &result {
            if previous != authority {
                return Ok(TransferAuthority::Unsupported(
                    "multiple transfers to the merchant with differing authorities".to_string(),
                ));
            }
        }
        result = TransferAuthority::Owner(authority.to_string());
    }
    Ok(result)
}

/// Verify an invoice against one RPC endpoint at `finalized` commitment.
///
/// Prefer [`verify_payment_agreed`], which requires two independent endpoints
/// to produce the same verdict.
pub fn verify_payment(rpc: &dyn RpcTransport, expectation: &PaymentExpectation) -> PaymentVerdict {
    match verify_payment_inner(rpc, expectation) {
        Ok(verdict) => verdict,
        Err(reason) => PaymentVerdict::Unknown { reason },
    }
}

fn verify_payment_inner(
    rpc: &dyn RpcTransport,
    expectation: &PaymentExpectation,
) -> Result<PaymentVerdict, String> {
    let merchant_owner = parse_pubkey(&expectation.merchant_owner)?;
    let mint = parse_pubkey(&expectation.mint)?;
    parse_pubkey(&expectation.reference)?;
    let token_program = parse_pubkey(TOKEN_PROGRAM)?;

    // Proves the mint is classic SPL: a Token-2022 mint cannot get past here.
    let mint_decimals = fetch_classic_mint_decimals(rpc, &expectation.mint)?;
    let merchant_ata = ata_address(&merchant_owner, &token_program, &mint).to_string();

    let response = rpc.call(
        "getSignaturesForAddress",
        json!([expectation.reference, {"commitment": "finalized"}]),
    )?;
    if let Some(error) = rpc_error(&response) {
        return Err(format!("getSignaturesForAddress JSON-RPC error: {error}"));
    }
    let entries = response
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(|| "getSignaturesForAddress missing or malformed result".to_string())?;
    if entries.len() > MAX_SIGNATURES {
        return Ok(PaymentVerdict::Review {
            reason: format!(
                "{} finalized transactions reference this invoice; manual review required",
                entries.len()
            ),
            signatures: Vec::new(),
        });
    }

    let mut accepted: Vec<PaymentEvidence> = Vec::new();
    let mut reviews: Vec<(String, String)> = Vec::new();

    for entry in entries {
        if entry.get("err").is_some_and(|e| !e.is_null()) {
            continue;
        }
        let signature = entry
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| "signature entry missing signature".to_string())?
            .to_string();

        let tx_response = rpc.call(
            "getTransaction",
            json!([signature, {
                "commitment": "finalized",
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": 0
            }]),
        )?;
        if let Some(error) = rpc_error(&tx_response) {
            return Err(format!("getTransaction JSON-RPC error: {error}"));
        }
        let tx = tx_response
            .get("result")
            .ok_or_else(|| "getTransaction missing result".to_string())?;
        if tx.is_null() {
            // Listed as finalized but not retrievable: refuse to guess.
            return Err(format!(
                "getTransaction returned null for finalized signature {signature}"
            ));
        }

        match examine_transaction(tx, expectation, &merchant_ata, mint_decimals)? {
            Candidate::Irrelevant => {}
            Candidate::Review(reason) => reviews.push((signature, reason)),
            Candidate::Accepted {
                payer_owner,
                observed_amount_raw,
            } => {
                let slot = tx
                    .get("slot")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "getTransaction result missing slot".to_string())?;
                let block_time = tx.get("blockTime").and_then(Value::as_i64);
                // A non-positive expiry is not a deadline in 1970; it means the
                // caller supplied no expiry at all.
                let late = match (expectation.expiry_unix, block_time) {
                    (Some(expiry), Some(block_time)) if expiry > 0 => block_time > expiry,
                    _ => false,
                };
                accepted.push(PaymentEvidence {
                    signature,
                    payer_owner,
                    observed_amount_raw,
                    requested_amount_raw: expectation.requested_amount_raw,
                    block_time,
                    slot,
                    late,
                });
            }
        }
    }

    if accepted.len() > 1 {
        return Ok(PaymentVerdict::Review {
            reason: "duplicate payment: more than one finalized transfer satisfies this invoice"
                .to_string(),
            signatures: accepted.into_iter().map(|e| e.signature).collect(),
        });
    }
    if let Some(evidence) = accepted.pop() {
        // A structurally broken transfer alongside a good one still needs eyes.
        if !reviews.is_empty() {
            let mut signatures: Vec<String> = vec![evidence.signature];
            signatures.extend(reviews.iter().map(|(sig, _)| sig.clone()));
            return Ok(PaymentVerdict::Review {
                reason: format!(
                    "a valid payment and {} unexplained merchant transfer(s) reference this invoice",
                    reviews.len()
                ),
                signatures,
            });
        }
        // The amount is the more consequential fact, so a mismatch is never
        // masked by lateness — `evidence.late` carries the timing alongside it.
        return Ok(
            match evidence
                .observed_amount_raw
                .cmp(&expectation.requested_amount_raw)
            {
                std::cmp::Ordering::Less => PaymentVerdict::Underpaid(evidence),
                std::cmp::Ordering::Greater => PaymentVerdict::Overpaid(evidence),
                std::cmp::Ordering::Equal if evidence.late => PaymentVerdict::Late(evidence),
                std::cmp::Ordering::Equal => PaymentVerdict::Paid(evidence),
            },
        );
    }
    if !reviews.is_empty() {
        return Ok(PaymentVerdict::Review {
            reason: reviews
                .iter()
                .map(|(_, reason)| reason.clone())
                .collect::<Vec<_>>()
                .join("; "),
            signatures: reviews.into_iter().map(|(sig, _)| sig).collect(),
        });
    }
    Ok(PaymentVerdict::Unpaid)
}

/// Verify against two independent endpoints and require them to agree.
///
/// A single compromised, lagging, or lying RPC cannot mark an invoice paid.
/// Disagreement is `Unknown`, never a merge of the two answers.
pub fn verify_payment_agreed(
    primary: &dyn RpcTransport,
    fallback: &dyn RpcTransport,
    expectation: &PaymentExpectation,
) -> PaymentVerdict {
    let first = verify_payment(primary, expectation);
    // Short-circuit: a primary that cannot be trusted makes the second call
    // pointless, and calling anyway would only widen the window for a
    // time-of-check race between the two reads.
    if matches!(first, PaymentVerdict::Unknown { .. }) {
        return combine_agreed(first, None);
    }
    let second = verify_payment(fallback, expectation);
    combine_agreed(first, Some(second))
}

/// The rule-combining algorithm for two independent endpoints, named and
/// separated so it can be tested exhaustively rather than inferred from the
/// call site.
///
/// The shape is deliberate, and it is the asymmetric one from functional-safety
/// practice (IEC 61508's 1oo2/2oo2 distinction):
///
/// - **Unanimity is required to earn a permissive answer.** Both endpoints must
///   independently reach the same verdict before it is returned.
/// - **A single dissent is enough to force the safe state.** Any disagreement,
///   and any endpoint that could not be trusted at all, yields `Unknown`.
///
/// A symmetric "2-out-of-2 to trip" design would be the dangerous inverse:
/// it buys availability by letting one dead channel suppress a refusal. Here a
/// dead channel can only ever cost availability, never safety.
///
/// `fallback` is `None` when the primary already failed and the second call was
/// skipped.
pub fn combine_agreed(
    primary: PaymentVerdict,
    fallback: Option<PaymentVerdict>,
) -> PaymentVerdict {
    if let PaymentVerdict::Unknown { reason } = &primary {
        return PaymentVerdict::Unknown {
            reason: format!("primary RPC: {reason}"),
        };
    }
    let Some(fallback) = fallback else {
        // A trustworthy primary with no second opinion is still one endpoint,
        // and one endpoint is not evidence.
        return PaymentVerdict::Unknown {
            reason: "fallback RPC produced no verdict — one endpoint is not evidence".to_string(),
        };
    };
    if let PaymentVerdict::Unknown { reason } = &fallback {
        return PaymentVerdict::Unknown {
            reason: format!("fallback RPC: {reason}"),
        };
    }
    if primary != fallback {
        return PaymentVerdict::Unknown {
            reason: format!(
                "primary and fallback RPC disagree: {} vs {}",
                primary.tag(),
                fallback.tag()
            ),
        };
    }
    primary
}
