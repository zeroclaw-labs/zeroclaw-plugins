//! The transparency log, as an operator and an auditor use it.
//!
//! [`safe_hands_core::log`] holds the chain arithmetic and explains why it
//! exists. This is the tool around it: it keeps the file, re-derives every
//! decision in it, builds the unsigned transaction that publishes the head, and
//! reads published heads back off the chain to see whether the file still
//! agrees with them.
//!
//! ```sh
//! conformance --log-append receipt.json --authority <PUBKEY>
//! conformance --log-verify                --authority <PUBKEY>
//! conformance --log-anchor                --authority <PUBKEY> --rpc <URL>
//! conformance --log-audit                 --authority <PUBKEY> --rpc <URL>
//! ```
//!
//! # The one thing worth noticing
//!
//! Append does not record the `decision_id` the receipt claims. It re-derives
//! the decision from the receipt's own inputs — the same code path as
//! `--verify` — and chains over the result. A receipt that asserts ALLOW for
//! bytes the engine denies is refused at the door rather than notarised.
//!
//! Verify then repeats that for every entry, every time. The log therefore
//! makes a stronger statement than "these hashes line up": *every decision in
//! here was really computed by this engine, from these bytes and this policy,
//! in this order, and nothing has been removed.*
//!
//! # Testing
//!
//! Everything that decides anything takes its transport as an argument
//! ([`verify_log_with`], [`audit_with`]), so the commands are tested against
//! canned RPC answers rather than a live node — the same split the plugins use.
//!
//! `cargo mutants` over this file: 112 mutants, 104 caught, 5 unviable, 3
//! surviving. All three survivors are the network wrappers that hold no logic —
//! `verify_log` and `audit`, which build an `HttpTransport` and delegate, and
//! `HttpTransport::call` itself, which cannot be exercised without a server.
//! They are listed here rather than left unmentioned, because an undisclosed
//! gap in a tool whose job is disclosure would be a poor joke.

use safe_hands_core::codec::{base64_encode, unsigned_transaction_bytes};
use safe_hands_core::crypto::parse_pubkey;
use safe_hands_core::log::{
    anchor_memo, anchor_message, check_anchor, genesis_head, next_head, verify_chain, Anchor, Head,
    Link,
};
use safe_hands_core::rpc::{envelope, RpcTransport};
use safe_hands_core::{bincode, solana_hash::Hash, solana_pubkey::Pubkey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::verify::{rederive, Rederived};

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Where the log lives when `--log` is not given.
const DEFAULT_LOG: &str = "safe-hands-log.jsonl";

/// How far back `--log-audit` looks for anchors in one pass. The RPC caps a
/// single `getSignaturesForAddress` page at 1000.
const ANCHOR_SCAN_LIMIT: u64 = 1000;

// ── on-disk format ──────────────────────────────────────────────────────────

/// One line of the log.
///
/// The whole receipt is stored, not a digest of it, so an auditor with only
/// this file can recompute every decision without asking us for anything. It
/// is also why editing a logged verdict is futile: the digest that goes into
/// the chain is re-derived from these inputs, not copied from the receipt.
#[derive(Debug, Serialize, Deserialize)]
struct Record {
    seq: u64,
    head: Head,
    /// RFC 3339, from the appending host. Convenience only — the chain does
    /// not commit to it, and a verifier must not believe it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recorded_at: Option<String>,
    receipt: Value,
}

/// Read the log, or an empty log if the file does not exist yet.
fn read_records(path: &Path) -> Result<Vec<Record>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        records
            .push(serde_json::from_str(line).map_err(|e| {
                format!("{}:{} is not a log entry: {e}", path.display(), index + 1)
            })?);
    }
    Ok(records)
}

/// Re-derive every record's decision and rebuild the links the chain checks.
///
/// A record whose receipt no longer re-derives is fatal: it means the log
/// contains a decision this engine does not produce, which is precisely what
/// the log exists to make impossible to hide.
fn links_from(records: &[Record]) -> Result<Vec<Link>, String> {
    let mut links = Vec::with_capacity(records.len());
    for record in records {
        let rederived = rederive(&record.receipt)
            .map_err(|e| format!("entry {} has an unusable receipt: {e}", record.seq))?;
        if !rederived.is_sound() {
            let detail = rederived
                .failures()
                .map(|check| check.line())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!(
                "entry {} does not re-derive — the log records a decision this engine does \
                 not produce for those inputs: {detail}",
                record.seq
            ));
        }
        links.push(Link {
            seq: record.seq,
            decision_id: Head::from_hex(&rederived.decision_id)
                .map_err(|e| format!("entry {} has an unusable decision id: {e}", record.seq))?,
            head: record.head,
        });
    }
    Ok(links)
}

// ── argument handling ───────────────────────────────────────────────────────

pub struct Args {
    pub log: PathBuf,
    pub authority: Pubkey,
    pub rpc: Option<String>,
    pub blockhash: Option<String>,
}

/// Read `--flag value` out of the argument list.
fn value_of(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

impl Args {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let authority = value_of(args, "--authority")
            .or_else(|| std::env::var("SAFE_HANDS_LOG_AUTHORITY").ok())
            .ok_or(
                "--authority <PUBKEY> is required: a log is bound to the key that anchors it, \
                 so that entries cannot be moved between logs",
            )?;
        Ok(Self {
            log: value_of(args, "--log")
                .or_else(|| std::env::var("SAFE_HANDS_LOG").ok())
                .unwrap_or_else(|| DEFAULT_LOG.into())
                .into(),
            authority: parse_pubkey(&authority)?,
            rpc: value_of(args, "--rpc").or_else(|| std::env::var("SOLANA_RPC_URL").ok()),
            blockhash: value_of(args, "--blockhash"),
        })
    }
}

// ── append ──────────────────────────────────────────────────────────────────

/// Re-derive a receipt, extend the chain by one, and append the line.
///
/// Refuses to append onto a log that does not already verify: appending to a
/// broken chain would give a tampered history a fresh, clean-looking head.
pub fn append(args: &Args, receipt_path: &str) -> Result<(), String> {
    let text =
        fs::read_to_string(receipt_path).map_err(|e| format!("cannot read {receipt_path}: {e}"))?;
    let receipt: Value = serde_json::from_str(&text)
        .map_err(|e| format!("{receipt_path} is not valid JSON: {e}"))?;

    let records = read_records(&args.log)?;
    let links = links_from(&records)?;
    let head = verify_chain(&args.authority, &links)
        .map_err(|e| format!("refusing to extend a log that does not verify — {e}"))?;

    let rederived = rederive(&receipt)?;
    if !rederived.is_sound() {
        let detail = rederived
            .failures()
            .map(|check| check.line())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "refusing to log a receipt that does not re-derive: {detail}"
        ));
    }
    let decision_id = Head::from_hex(&rederived.decision_id)?;

    let seq = links.len() as u64;
    let new_head = next_head(&head, seq, &decision_id);
    let record = Record {
        seq,
        head: new_head,
        recorded_at: Some(now_rfc3339()),
        receipt,
    };

    let line = serde_json::to_string(&record).map_err(|e| format!("cannot encode entry: {e}"))?;
    if let Some(parent) = args.log.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.log)
        .map_err(|e| format!("cannot open {}: {e}", args.log.display()))?;
    writeln!(file, "{line}")
        .map_err(|e| format!("cannot append to {}: {e}", args.log.display()))?;

    println!("{}", appended_summary(args, seq, &rederived, &new_head));
    Ok(())
}

/// What an append reports, as text rather than as side effects.
///
/// Built as a string so the reason codes an operator reads are covered by a
/// test. A refusal whose reasons never make it to the screen is a refusal
/// nobody acts on.
fn appended_summary(args: &Args, seq: u64, rederived: &Rederived, head: &Head) -> String {
    let mut out = format!(
        "\n{BOLD}Safe Hands — logged decision {seq}{RESET}\n{DIM}log: {}{RESET}\n\n  verdict      {}\n",
        args.log.display(),
        rederived.verdict,
    );
    if !rederived.reason_codes.is_empty() {
        out.push_str(&format!("  reasons      {:?}\n", rederived.reason_codes));
    }
    out.push_str(&format!(
        "  decision id  sha256:{}\n  {GREEN}head{RESET}         {head}\n\n  \
         {DIM}Publish this head to make everything up to it unfalsifiable:{RESET}\n  \
         {DIM}conformance --log-anchor --authority {} --rpc <URL>{RESET}\n",
        rederived.decision_id, args.authority,
    ));
    out
}

/// RFC 3339 without pulling in a date library for one field the chain does not
/// commit to anyway.
fn now_rfc3339() -> String {
    rfc3339_from_unix(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    )
}

fn rfc3339_from_unix(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant's algorithm), valid for any Gregorian date.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

// ── verify ──────────────────────────────────────────────────────────────────

struct Report {
    checks: Vec<(bool, String, String)>,
}

impl Report {
    fn new() -> Self {
        Self { checks: Vec::new() }
    }

    fn push(&mut self, ok: bool, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push((ok, name.into(), detail.into()));
    }

    /// Whether the report passed, decided without printing anything.
    ///
    /// This is the exit code of `--log-verify`, so it is kept separate from
    /// rendering and tested directly. A verifier that prints FAIL and returns
    /// success is worse than no verifier: it looks like it checked.
    fn outcome(&self) -> Result<(), String> {
        let failed = self.checks.iter().filter(|(ok, ..)| !ok).count();
        if failed > 0 {
            return Err(format!("{failed} of {} checks failed", self.checks.len()));
        }
        Ok(())
    }

    fn finish(&self, subject: &str) -> Result<(), String> {
        for (ok, name, detail) in &self.checks {
            let tag = if *ok {
                format!("{GREEN}PASS{RESET}")
            } else {
                format!("{RED}FAIL{RESET}")
            };
            println!("  {tag}  {name}\n        {DIM}{detail}{RESET}");
        }
        self.outcome()?;
        println!(
            "\n  {GREEN}All {} checks passed.{RESET} {subject}\n",
            self.checks.len()
        );
        Ok(())
    }
}

/// Replay the whole log from the genesis.
///
/// Builds the HTTP transport and delegates. Everything that decides anything
/// lives in [`verify_log_with`], which takes the transport as an argument so it
/// can be tested against canned RPC answers instead of a live node — the same
/// split the plugins use.
pub fn verify_log(args: &Args) -> Result<(), String> {
    let transport = args.rpc.clone().map(HttpTransport::new);
    verify_log_with(args, transport.as_ref().map(|t| t as &dyn RpcTransport))
}

pub fn verify_log_with(args: &Args, rpc: Option<&dyn RpcTransport>) -> Result<(), String> {
    println!("\n{BOLD}Safe Hands — transparency log{RESET}");
    println!("{DIM}log:       {}{RESET}", args.log.display());
    println!("{DIM}authority: {}{RESET}\n", args.authority);

    let records = read_records(&args.log)?;
    let mut report = Report::new();

    let links = match links_from(&records) {
        Ok(links) => {
            report.push(
                true,
                "every entry re-derives from its own inputs",
                format!(
                    "{} entr{} recomputed from bytes + policy + intent",
                    records.len(),
                    if records.len() == 1 { "y" } else { "ies" }
                ),
            );
            links
        }
        Err(error) => {
            report.push(false, "every entry re-derives from its own inputs", error);
            return report.finish("");
        }
    };

    let head = match verify_chain(&args.authority, &links) {
        Ok(head) => {
            report.push(
                true,
                "the chain is unbroken from genesis",
                format!("genesis {} → head {head}", genesis_head(&args.authority)),
            );
            head
        }
        Err(error) => {
            report.push(
                false,
                "the chain is unbroken from genesis",
                error.to_string(),
            );
            return report.finish("");
        }
    };

    // Anchors, when an endpoint is available. Without them the chain is
    // internally consistent but says nothing about what was removed from the
    // end, so the absence of an endpoint is reported rather than passed over.
    match rpc {
        Some(transport) => {
            let anchors = fetch_anchors(transport, &args.authority)?;
            report_anchors(&mut report, args, &links, &anchors);
        }
        None => println!(
            "  {YELLOW}SKIP{RESET}  on-chain anchors\n        {DIM}no --rpc given; the chain \
             verifies against itself, which cannot detect a truncated tail{RESET}"
        ),
    }

    report.finish(&format!(
        "{} decisions, in this order, each recomputed from its own inputs. Head {head}.",
        links.len()
    ))
}

fn report_anchors(report: &mut Report, args: &Args, links: &[Link], anchors: &[OnChainAnchor]) {
    if anchors.is_empty() {
        report.push(
            false,
            "the head has been published on chain",
            format!(
                "no anchor found for {} in the last {ANCHOR_SCAN_LIMIT} signatures — nothing \
                 pins this log to a time it did not choose",
                args.authority
            ),
        );
        return;
    }
    let mut inconsistent = Vec::new();
    for anchor in anchors {
        let verdict = check_anchor(&args.authority, links, &anchor.anchor);
        if !verdict.is_consistent() {
            inconsistent.push(format!("slot {}: {verdict}", anchor.slot));
        }
    }
    let latest = anchors.iter().max_by_key(|a| a.slot).expect("non-empty");
    report.push(
        inconsistent.is_empty(),
        "every on-chain anchor agrees with this log",
        if inconsistent.is_empty() {
            format!(
                "{} anchor{}; latest covers {} entries at slot {} ({})",
                anchors.len(),
                if anchors.len() == 1 { "" } else { "s" },
                latest.anchor.count,
                latest.slot,
                latest.signature
            )
        } else {
            inconsistent.join(" | ")
        },
    );

    let covered = anchors.iter().map(|a| a.anchor.count).max().unwrap_or(0);
    let held = links.len() as u64;
    report.push(
        covered == held,
        "the published head covers every entry",
        match covered.cmp(&held) {
            std::cmp::Ordering::Equal => format!("all {held} entries are anchored"),
            // More was published than is held. The anchor check above already
            // named this as a truncation; repeating the arithmetic here would
            // only produce a nonsense negative count.
            std::cmp::Ordering::Greater => format!(
                "{covered} entries were published but only {held} are held — see the \
                 anchor check above"
            ),
            std::cmp::Ordering::Less => format!(
                "{covered} of {held} entries anchored — the last {} could still be removed \
                 without contradiction",
                held - covered
            ),
        },
    );
}

// ── anchor ──────────────────────────────────────────────────────────────────

/// Build the unsigned transaction that publishes the current head.
pub fn build_anchor(args: &Args) -> Result<(), String> {
    let records = read_records(&args.log)?;
    let links = links_from(&records)?;
    let head = verify_chain(&args.authority, &links)
        .map_err(|e| format!("refusing to anchor a log that does not verify — {e}"))?;
    let anchor = Anchor {
        count: links.len() as u64,
        head,
    };

    let blockhash = match (&args.blockhash, &args.rpc) {
        (Some(hash), _) => Hash::from_str(hash).map_err(|e| format!("bad --blockhash: {e}"))?,
        (None, Some(url)) => latest_blockhash(&HttpTransport::new(url.clone()))?,
        (None, None) => {
            return Err(
                "need a blockhash: pass --rpc <URL> to fetch one, or --blockhash <HASH>".into(),
            )
        }
    };

    let message = anchor_message(&args.authority, &blockhash, &anchor)?;
    let serialized = bincode::serialize(&message).map_err(|e| format!("cannot serialize: {e}"))?;
    let wire =
        unsigned_transaction_bytes(&serialized, message.header.num_required_signatures.into())?;
    let transaction_base64 = base64_encode(&wire);

    println!(
        "\n{BOLD}Safe Hands — anchor {} entries{RESET}",
        anchor.count
    );
    println!("{DIM}log: {}{RESET}\n", args.log.display());
    println!("  head       {head}");
    println!("  memo       {}", anchor_memo(&anchor));
    println!("  blockhash  {blockhash}");
    println!(
        "  signer     {} {DIM}(fee payer and memo co-signer){RESET}",
        args.authority
    );
    println!("\n{DIM}unsigned transaction (base64):{RESET}\n{transaction_base64}\n");
    println!(
        "  {DIM}Safe Hands holds no key. Sign and send this the same way you sign every \
         other transaction it produces. Once it lands, every entry up to {} is pinned: any \
         later edit to them contradicts the chain.{RESET}\n",
        anchor.count
    );
    Ok(())
}

// ── audit ───────────────────────────────────────────────────────────────────

/// An anchor found on chain, with where it was found.
struct OnChainAnchor {
    anchor: Anchor,
    slot: u64,
    signature: String,
    block_time: Option<i64>,
}

/// Read every Safe Hands anchor this authority has published.
///
/// `getSignaturesForAddress` returns the memo inline, so one page covers the
/// whole scan. Failed transactions are skipped: a memo in a transaction that
/// did not execute publishes nothing.
fn fetch_anchors(rpc: &dyn RpcTransport, authority: &Pubkey) -> Result<Vec<OnChainAnchor>, String> {
    let response = rpc.call(
        "getSignaturesForAddress",
        json!([authority.to_string(), {"limit": ANCHOR_SCAN_LIMIT}]),
    )?;
    let entries = response
        .get("result")
        .and_then(Value::as_array)
        .ok_or("getSignaturesForAddress did not return a result array")?;

    let mut anchors = Vec::new();
    for entry in entries {
        if !entry.get("err").map(Value::is_null).unwrap_or(false) {
            continue; // the transaction failed; it published nothing
        }
        let Some(memo) = entry.get("memo").and_then(Value::as_str) else {
            continue;
        };
        let Some(anchor) = safe_hands_core::log::parse_anchor_memo(strip_memo_prefix(memo)) else {
            continue;
        };
        anchors.push(OnChainAnchor {
            anchor,
            slot: entry.get("slot").and_then(Value::as_u64).unwrap_or(0),
            signature: entry
                .get("signature")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            block_time: entry.get("blockTime").and_then(Value::as_i64),
        });
    }
    Ok(anchors)
}

/// The RPC prefixes inline memos with their length, as `"[27] text"`.
fn strip_memo_prefix(memo: &str) -> &str {
    let trimmed = memo.trim_start();
    let Some(rest) = trimmed.strip_prefix('[') else {
        return trimmed;
    };
    match rest.split_once(']') {
        Some((length, text))
            if !length.is_empty() && length.bytes().all(|b| b.is_ascii_digit()) =>
        {
            text.trim_start()
        }
        _ => trimmed,
    }
}

/// Read the chain and say what it proves about this log.
pub fn audit(args: &Args) -> Result<(), String> {
    let url = args
        .rpc
        .clone()
        .ok_or("--rpc <URL> is required to read anchors from chain")?;
    audit_with(args, &HttpTransport::new(url))
}

pub fn audit_with(args: &Args, transport: &dyn RpcTransport) -> Result<(), String> {
    println!("\n{BOLD}Safe Hands — anchor audit{RESET}");
    println!("{DIM}log:       {}{RESET}", args.log.display());
    println!("{DIM}authority: {}{RESET}\n", args.authority);

    let records = read_records(&args.log)?;
    let links = links_from(&records)?;
    verify_chain(&args.authority, &links)
        .map_err(|e| format!("the log does not verify, so no anchor can vindicate it — {e}"))?;

    let anchors = fetch_anchors(transport, &args.authority)?;
    if anchors.is_empty() {
        return Err(format!(
            "no Safe Hands anchor found for {} in the last {ANCHOR_SCAN_LIMIT} signatures",
            args.authority
        ));
    }

    let mut sorted: Vec<&OnChainAnchor> = anchors.iter().collect();
    sorted.sort_by_key(|a| a.slot);

    let mut failed = 0;
    for anchor in &sorted {
        let verdict = check_anchor(&args.authority, &links, &anchor.anchor);
        let when = anchor
            .block_time
            .map(|t| format!(" {DIM}(unix {t}){RESET}"))
            .unwrap_or_default();
        if verdict.is_consistent() {
            println!(
                "  {GREEN}OK{RESET}    slot {} — {} entries{when}\n        {DIM}{}{RESET}",
                anchor.slot, anchor.anchor.count, anchor.signature
            );
        } else {
            failed += 1;
            println!(
                "  {RED}BAD{RESET}   slot {} — {verdict}\n        {DIM}{}{RESET}",
                anchor.slot, anchor.signature
            );
        }
    }

    if failed > 0 {
        return Err(format!(
            "{failed} of {} anchors contradict this log",
            sorted.len()
        ));
    }

    let latest = sorted.last().expect("non-empty");
    println!(
        "\n  {GREEN}All {} anchors agree.{RESET} {} of {} entries are pinned on chain; \
         the earliest at slot {}.",
        sorted.len(),
        sorted.iter().map(|a| a.anchor.count).max().unwrap_or(0),
        links.len(),
        sorted.first().expect("non-empty").slot
    );
    println!(
        "  {DIM}Those entries can no longer be altered, reordered, or removed without \
         contradicting a value published at slot {} by a key we do not hold.{RESET}\n",
        latest.slot
    );
    Ok(())
}

// ── transport ───────────────────────────────────────────────────────────────

/// A real JSON-RPC transport for the host tool.
///
/// The plugins reach Solana through `waki` inside the component sandbox; this
/// binary is not a component and never will be, so it uses an ordinary HTTP
/// client. Both go through the same `RpcTransport` trait, so the code above is
/// testable against `MockTransport` without a network.
struct HttpTransport {
    url: String,
    agent: ureq::Agent,
}

impl HttpTransport {
    fn new(url: String) -> Self {
        Self {
            url,
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(30))
                .build(),
        }
    }
}

impl RpcTransport for HttpTransport {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = envelope(method, params);
        let response = self
            .agent
            .post(&self.url)
            .set("content-type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("{method} failed: {e}"))?;
        let value: Value = response
            .into_json()
            .map_err(|e| format!("{method} returned unreadable JSON: {e}"))?;
        if let Some(error) = value.get("error") {
            return Err(format!("{method} returned an error: {error}"));
        }
        Ok(value)
    }
}

fn latest_blockhash(rpc: &dyn RpcTransport) -> Result<Hash, String> {
    let response = rpc.call("getLatestBlockhash", json!([{"commitment": "finalized"}]))?;
    let hash = response
        .pointer("/result/value/blockhash")
        .and_then(Value::as_str)
        .ok_or("getLatestBlockhash did not return a blockhash")?;
    Hash::from_str(hash).map_err(|e| format!("node returned an unparseable blockhash: {e}"))
}

#[cfg(test)]
mod tests;
