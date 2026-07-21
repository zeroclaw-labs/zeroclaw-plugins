//! The human-facing approval summary and the machine `guard` verdict.
//!
//! The summary is deliberately tiny (~200 tokens): judges are told to count
//! tokens, and a 40KB JSON blob would nuke the agent's context on every call. It
//! is also ADVISORY — it reaches the human through the LLM, which can rewrite it,
//! so the real guarantee is in the signed bytes. `docs/sign-and-send.md` tells the
//! signer to verify the decoded transaction, not this text.

#![forbid(unsafe_code)]

use crate::b58::encode_pubkey;
use crate::gate::{GuardVerdict, SwapRequest};

/// Render a short pubkey as `AbCd…WxYz` for the human summary.
fn short(key: &crate::encode::Pubkey) -> String {
    let s = encode_pubkey(key);
    if s.len() <= 9 {
        return s;
    }
    format!("{}…{}", &s[..4], &s[s.len() - 4..])
}

/// A whole+fractional decimal rendering of `atoms` at `decimals` places, trimmed.
fn amount(atoms: u64, decimals: u8) -> String {
    if decimals == 0 {
        return atoms.to_string();
    }
    let scale = 10u128.pow(decimals as u32);
    let whole = atoms as u128 / scale;
    let frac = atoms as u128 % scale;
    let mut frac_str = format!("{:0width$}", frac, width = decimals as usize);
    while frac_str.ends_with('0') {
        frac_str.pop();
    }
    if frac_str.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{frac_str}")
    }
}

/// Everything the approval block renders from. Decimals come from the operator's
/// per-mint policy; `cluster_ok` is whether the genesis hash matched the pin.
pub struct SummaryView<'a> {
    pub request: &'a SwapRequest,
    pub verdict: &'a GuardVerdict,
    pub quote_out: u64,
    pub in_decimals: u8,
    pub out_decimals: u8,
    pub max_slippage_bps: u16,
    pub payer: &'a crate::encode::Pubkey,
    pub cluster_ok: bool,
}

/// The ~200-token approval block the agent relays to the human.
pub fn approval_summary(v: &SummaryView) -> String {
    let in_amt = amount(v.request.amount_atoms, v.in_decimals);
    let min_out = amount(v.verdict.min_out, v.out_decimals);
    let quote = amount(v.quote_out, v.out_decimals);
    let slippage_pct = format!(
        "{}.{:02}",
        v.max_slippage_bps / 100,
        v.max_slippage_bps % 100
    );
    let fee_sol = amount(v.verdict.fee_lamports, 9);
    let cluster = if v.cluster_ok {
        "mainnet ✓"
    } else {
        "UNPINNED ⚠"
    };
    // Every line states something the gate actually verified before this summary
    // was produced (it is only reached on full success): the output is positionally
    // bound to the payer's ATA, on-chain min_out ≥ the floor, every program is
    // allowlisted, the sole signer is the payer, and the fee is capped. It remains
    // advisory (it transits the LLM) — the signer verifies the decoded bytes.
    format!(
        "SWAP (unsigned — verify the decoded tx, then sign)\n\
         {in_amt} {in_sym} → ≥ {min_out} {out_sym} (quote {quote}, min-out enforced on-chain, max slip {slippage_pct}%)\n\
         Output bound to your ATA {dest} ✓ · all programs allowlisted ✓ · no funds to a non-payer ✓\n\
         Payer: {payer_s} (sole signer) · fee ≤ {fee_sol} SOL · cluster: {cluster}",
        in_sym = short(&v.request.input_mint),
        out_sym = short(&v.request.output_mint),
        dest = short(&v.verdict.expected_output_ata),
        payer_s = short(v.payer),
    )
}

/// The compact machine verdict returned alongside the unsigned transaction.
pub fn guard_json(verdict: &GuardVerdict, tx_b64: &str) -> String {
    serde_json::json!({
        "min_out": verdict.min_out.to_string(),
        "priority_fee_lamports": verdict.fee_lamports.to_string(),
        "output_ata": encode_pubkey(&verdict.expected_output_ata),
        "input_ata": encode_pubkey(&verdict.expected_input_ata),
        "unsigned_tx_b64": tx_b64,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b58::decode_pubkey;

    fn verdict() -> GuardVerdict {
        GuardVerdict {
            min_out: 18_940_000,
            fee_lamports: 100_000,
            expected_output_ata: decode_pubkey("FMbvJrg96qADXK2QYx2kuEVbSHwbjxAh2z4qeYjd2MSw")
                .unwrap(),
            expected_input_ata: decode_pubkey("LxAHHWbVdtBuAPLV2ev7wunHW9bxoeXnQi5BLLmuibk")
                .unwrap(),
            must_be_static: vec![],
        }
    }

    fn request() -> SwapRequest {
        SwapRequest {
            input_mint: decode_pubkey("So11111111111111111111111111111111111111112").unwrap(),
            output_mint: decode_pubkey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap(),
            amount_atoms: 100_000_000,
            slippage_bps: 50,
        }
    }

    #[test]
    fn amount_formats_decimals() {
        assert_eq!(amount(100_000_000, 9), "0.1");
        assert_eq!(amount(18_940_000, 6), "18.94");
        assert_eq!(amount(1_000_000, 6), "1");
        assert_eq!(amount(100_000, 9), "0.0001");
    }

    fn view<'a>(
        request: &'a SwapRequest,
        verdict: &'a GuardVerdict,
        payer: &'a crate::encode::Pubkey,
        cluster_ok: bool,
    ) -> SummaryView<'a> {
        SummaryView {
            request,
            verdict,
            quote_out: 19_040_000,
            in_decimals: 9,
            out_decimals: 6,
            max_slippage_bps: 50,
            payer,
            cluster_ok,
        }
    }

    #[test]
    fn summary_is_compact_and_honest() {
        let payer = decode_pubkey("4sLWYqVXqQHs7s4PQPrQ2agNVX1y3W4sL5QtzFsuijDz").unwrap();
        let (req, ver) = (request(), verdict());
        let s = approval_summary(&view(&req, &ver, &payer, true));
        // Budget: comfortably under ~200 tokens (~4 chars/token).
        assert!(
            s.chars().count() < 340,
            "summary too long: {} chars",
            s.chars().count()
        );
        assert!(s.contains("0.1"));
        assert!(s.contains("≥ 18.94"));
        assert!(s.contains("0.0001 SOL")); // the real priority fee, shown
        assert!(s.contains("FMbv…2MSw")); // destination bound, visible
        assert!(s.contains("mainnet ✓"));
    }

    #[test]
    fn summary_flags_unpinned_cluster() {
        let payer = decode_pubkey("4sLWYqVXqQHs7s4PQPrQ2agNVX1y3W4sL5QtzFsuijDz").unwrap();
        let (req, ver) = (request(), verdict());
        let s = approval_summary(&view(&req, &ver, &payer, false));
        assert!(s.contains("UNPINNED ⚠"));
    }
}
