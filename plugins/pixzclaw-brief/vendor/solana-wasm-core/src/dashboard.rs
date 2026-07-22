//! PixZClaw treasury / receivables brief — pure formatting (T0).
//!
//! No network here: callers pass a [`DashboardSnapshot`] from RPC (or fixtures).

use crate::rpc::SignatureInfo;
use crate::shape::short_label;
use crate::solana_pay::USDC_MINT;

/// Pre-fetched dashboard inputs.
#[derive(Debug, Clone)]
pub struct DashboardSnapshot {
    pub merchant_solana: String,
    /// Lamports (1 SOL = 1e9).
    pub sol_lamports: u64,
    /// USDC UI amount string (e.g. `"142.5"`); `"0"` if none.
    pub usdc_ui: String,
    /// Recent signatures for the merchant (or watch address).
    pub signatures: Vec<SignatureInfo>,
    /// Unix time used for relative labels / 7d buckets (tests inject fixed).
    pub now_unix: i64,
    /// How many recent lines to show.
    pub recent_limit: usize,
}

impl Default for DashboardSnapshot {
    fn default() -> Self {
        Self {
            merchant_solana: String::new(),
            sol_lamports: 0,
            usdc_ui: "0".into(),
            signatures: Vec::new(),
            now_unix: 1_700_000_000,
            recent_limit: 5,
        }
    }
}

/// Janela "Hoje" = últimas 24h (por simplicidade; rotulado no card).
const DAY_SECS: i64 = 86_400;

/// Format the Telegram-friendly PixZClaw cash card (~200 tokens).
///
/// Layout: caixa unicode (largura útil 35 ≤ 38, mobile-friendly) só para os
/// saldos; seções "Hoje" / "7 dias" / movimentações em linhas simples (sem
/// moldura à direita) para não quebrar alinhamento com valores longos.
pub fn format_dashboard(snap: &DashboardSnapshot) -> String {
    let merchant_short = short_label(&snap.merchant_solana, 22);
    let sol = lamports_to_sol_display(snap.sol_lamports);
    let usdc = if snap.usdc_ui.trim().is_empty() {
        "0"
    } else {
        snap.usdc_ui.trim()
    };

    let ok_sigs: Vec<&SignatureInfo> = snap.signatures.iter().filter(|s| s.is_success()).collect();

    let pix_memos: Vec<&&SignatureInfo> = ok_sigs.iter().filter(|s| is_pix_memo(s)).collect();

    let spark = sparkline_7d(&ok_sigs, snap.now_unix);
    let activity_7d = count_in_window(&ok_sigs, snap.now_unix, 7 * DAY_SECS);

    // --- Fechamento do dia (últimas 24h) ---
    let today_txs = count_in_window(&ok_sigs, snap.now_unix, DAY_SECS);
    let today_pix = count_pix_in_window(&ok_sigs, snap.now_unix, DAY_SECS);
    let today_ids = pix_invoice_ids_in_window(&ok_sigs, snap.now_unix, DAY_SECS, 4);

    let mut lines: Vec<String> = Vec::new();
    lines.push("╭─ PixZClaw · Caixa ─────────────────╮".into());
    lines.push(format!("│ Wallet     {merchant_short:<22} │"));
    lines.push(format!("│ USDC       {usdc:<22} │"));
    lines.push(format!("│ SOL (gas)  {sol:<22} │"));
    lines.push("╰───────────────────────────────────╯".into());

    // --- Hoje ---
    lines.push(String::new());
    lines.push("Hoje (últimas 24h)".into());
    lines.push(format!("• txs ok:      {today_txs}"));
    lines.push(format!("• faturas PIX: {today_pix}"));
    if today_ids.is_empty() {
        lines.push("• pagas: —".into());
    } else {
        lines.push(format!("• pagas: {}", today_ids.join(", ")));
    }

    // --- 7 dias ---
    lines.push(String::new());
    lines.push("7 dias".into());
    lines.push(format!("• txs ok: {activity_7d}"));
    lines.push(format!("• 7d {spark}  (velho→novo)"));

    // --- Movimentações ---
    lines.push(String::new());
    lines.push("Últimas movimentações (on-chain)".into());

    let limit = snap.recent_limit.max(1);
    let mut shown = 0usize;
    for s in &ok_sigs {
        if shown >= limit {
            break;
        }
        let when = relative_time(s.block_time, snap.now_unix);
        // PIX-memo → mostra invoice_id + tag PIX; senão memo curto / sig.
        let (label, tag) = if is_pix_memo(s) {
            let inv = extract_invoice_id(s.memo.as_deref()).unwrap_or_else(|| "invoice".into());
            (inv, "PIX".to_string())
        } else {
            let memo = s
                .memo
                .as_deref()
                .filter(|m| !m.trim().is_empty())
                .map(|m| short_label(m, 14))
                .unwrap_or_else(|| "tx".into());
            (memo, short_label(&s.signature, 8))
        };
        lines.push(format!("• {label:<14} {when:<7} {tag}"));
        shown += 1;
    }
    if shown == 0 {
        lines.push("• (nenhuma assinatura recente nesta wallet)".into());
    }

    let pix_hits = pix_memos.len();
    lines.push(String::new());
    lines.push(format!("Memos PixZClaw (PIX|BRL|…) nas sigs: {pix_hits}"));
    lines.push("PIX banco: não visível on-chain — só USDC/SOL aqui.".into());
    lines.push("T0 read-only · sem chave · PixZClaw".into());

    lines.join("\n")
}

/// True when the memo carries a PixZClaw `PIX|BRL|` marker.
fn is_pix_memo(s: &SignatureInfo) -> bool {
    s.memo
        .as_deref()
        .map(|m| m.contains("PIX|BRL|"))
        .unwrap_or(false)
}

/// Count PIX-memo successful txs inside `window_secs` before `now`.
fn count_pix_in_window(sigs: &[&SignatureInfo], now: i64, window_secs: i64) -> usize {
    let start = now.saturating_sub(window_secs);
    sigs.iter()
        .filter(|s| is_pix_memo(s))
        .filter(|s| {
            s.block_time
                .map(|t| t >= start && t <= now)
                .unwrap_or(false)
        })
        .count()
}

/// Deduped list of invoice ids paid (PIX-memo) inside the window, capped at `max`.
fn pix_invoice_ids_in_window(
    sigs: &[&SignatureInfo],
    now: i64,
    window_secs: i64,
    max: usize,
) -> Vec<String> {
    let start = now.saturating_sub(window_secs);
    let mut out: Vec<String> = Vec::new();
    for s in sigs {
        if out.len() >= max {
            break;
        }
        let in_window = s
            .block_time
            .map(|t| t >= start && t <= now)
            .unwrap_or(false);
        if !in_window {
            continue;
        }
        if let Some(id) = extract_invoice_id(s.memo.as_deref()) {
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

fn lamports_to_sol_display(lamports: u64) -> String {
    let sol = lamports as f64 / 1_000_000_000.0;
    let s = format!("{sol:.4}");
    s.trim_end_matches('0').trim_end_matches('.').to_string() + " SOL"
}

fn extract_invoice_id(memo: Option<&str>) -> Option<String> {
    let m = memo?;
    // PIX|BRL|<id>|...
    let mut parts = m.split('|');
    if parts.next()? != "PIX" {
        return None;
    }
    if parts.next()? != "BRL" {
        return None;
    }
    let id = parts.next()?.trim();
    if id.is_empty() {
        None
    } else {
        Some(short_label(id, 12))
    }
}

fn count_in_window(sigs: &[&SignatureInfo], now: i64, window_secs: i64) -> usize {
    let start = now.saturating_sub(window_secs);
    sigs.iter()
        .filter(|s| {
            s.block_time
                .map(|t| t >= start && t <= now)
                .unwrap_or(false)
        })
        .count()
}

/// 7-day sparkline (oldest → newest) from successful tx counts per day.
pub fn sparkline_7d(sigs: &[&SignatureInfo], now: i64) -> String {
    let day = 86_400i64;
    let mut buckets = [0u32; 7];
    for s in sigs {
        let Some(t) = s.block_time else { continue };
        let age = now.saturating_sub(t);
        if age < 0 || age >= 7 * day {
            continue;
        }
        let idx = (6 - (age / day).min(6)) as usize;
        buckets[idx] = buckets[idx].saturating_add(1);
    }
    let bars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = *buckets.iter().max().unwrap_or(&0);
    buckets
        .iter()
        .map(|&c| {
            if max == 0 {
                '▁'
            } else {
                let level = ((c as usize) * (bars.len() - 1)) / (max as usize);
                bars[level.min(bars.len() - 1)]
            }
        })
        .collect()
}

fn relative_time(block_time: Option<i64>, now: i64) -> String {
    let Some(t) = block_time else {
        return "??".into();
    };
    let d = now.saturating_sub(t);
    if d < 60 {
        return "agora".into();
    }
    if d < 3600 {
        return format!("há {}m", d / 60);
    }
    if d < 86_400 {
        return format!("há {}h", d / 3600);
    }
    format!("há {}d", d / 86_400)
}

/// Default USDC mint used when config omits it.
pub fn default_usdc_mint() -> &'static str {
    USDC_MINT
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sig(sig: &str, memo: Option<&str>, t: i64) -> SignatureInfo {
        SignatureInfo {
            signature: sig.into(),
            slot: 1,
            err: None,
            memo: memo.map(|m| m.into()),
            block_time: Some(t),
            confirmation_status: Some("finalized".into()),
        }
    }

    #[test]
    fn card_contains_sections() {
        let now = 1_700_000_000i64;
        let snap = DashboardSnapshot {
            merchant_solana: "11111111111111111111111111111112".into(),
            sol_lamports: 410_000_000,
            usdc_ui: "142.5".into(),
            signatures: vec![
                sig(
                    "VeryLongSigAAAAAAAA",
                    Some("PIX|BRL|demo-1|cafe"),
                    now - 120,
                ),
                sig(
                    "VeryLongSigBBBBBBBB",
                    Some("PIX|BRL|inv-412|x"),
                    now - 90_000,
                ),
            ],
            now_unix: now,
            recent_limit: 5,
        };
        let s = format_dashboard(&snap);
        assert!(s.contains("PixZClaw · Caixa"));
        assert!(s.contains("142.5"));
        assert!(s.contains("USDC"));
        assert!(s.contains("demo-1") || s.contains("PIX|BRL"));
        assert!(s.contains("T0 read-only"));
        assert!(s.contains("▁") || s.chars().any(|c| "▂▃▄▅▆▇█".contains(c)));
    }

    #[test]
    fn empty_sigs_ok() {
        let snap = DashboardSnapshot {
            merchant_solana: "11111111111111111111111111111112".into(),
            sol_lamports: 0,
            usdc_ui: "0".into(),
            signatures: vec![],
            now_unix: 1_700_000_000,
            recent_limit: 5,
        };
        let s = format_dashboard(&snap);
        assert!(s.contains("nenhuma assinatura") || s.contains("0"));
    }

    #[test]
    fn sparkline_len_7() {
        let now = 1_700_000_000i64;
        let a = sig("a", None, now - 100);
        let b = sig("b", None, now - 86_400 - 10);
        let refs: Vec<&SignatureInfo> = vec![&a, &b];
        let sp = sparkline_7d(&refs, now);
        assert_eq!(sp.chars().count(), 7);
    }

    #[test]
    fn extract_id() {
        assert_eq!(
            extract_invoice_id(Some("PIX|BRL|demo-1|cafe")).as_deref(),
            Some("demo-1")
        );
        assert!(extract_invoice_id(Some("nope")).is_none());
        let _ = json!({});
    }

    #[test]
    fn today_window_counts_24h_only() {
        let now = 1_700_000_000i64;
        let sigs = [
            sig("A", Some("PIX|BRL|hoje-1|x"), now - 3_600), // 1h atrás → dentro
            sig("B", Some("PIX|BRL|hoje-2|x"), now - 80_000), // ~22h → dentro
            sig("C", Some("PIX|BRL|velha|x"), now - 90_000), // 25h → fora
            sig("D", None, now - 100),                       // tx não-PIX, dentro
        ];
        let refs: Vec<&SignatureInfo> = sigs.iter().collect();
        assert_eq!(count_in_window(&refs, now, DAY_SECS), 3); // A,B,D
        assert_eq!(count_pix_in_window(&refs, now, DAY_SECS), 2); // A,B
        let ids = pix_invoice_ids_in_window(&refs, now, DAY_SECS, 4);
        assert_eq!(ids, vec!["hoje-1".to_string(), "hoje-2".to_string()]);
    }

    #[test]
    fn today_ids_dedup_and_capped() {
        let now = 1_700_000_000i64;
        let sigs = [
            sig("A", Some("PIX|BRL|dup|x"), now - 10),
            sig("B", Some("PIX|BRL|dup|y"), now - 20),
            sig("C", Some("PIX|BRL|two|z"), now - 30),
        ];
        let refs: Vec<&SignatureInfo> = sigs.iter().collect();
        let ids = pix_invoice_ids_in_window(&refs, now, DAY_SECS, 4);
        assert_eq!(ids, vec!["dup".to_string(), "two".to_string()]);
        let capped = pix_invoice_ids_in_window(&refs, now, DAY_SECS, 1);
        assert_eq!(capped.len(), 1);
    }

    #[test]
    fn card_has_today_and_legend_sections() {
        let now = 1_700_000_000i64;
        let snap = DashboardSnapshot {
            merchant_solana: "11111111111111111111111111111112".into(),
            sol_lamports: 410_000_000,
            usdc_ui: "142.5".into(),
            signatures: vec![
                sig(
                    "VeryLongSigAAAAAAAA",
                    Some("PIX|BRL|demo-1|cafe"),
                    now - 120,
                ),
                sig(
                    "VeryLongSigBBBBBBBB",
                    Some("PIX|BRL|inv-412|x"),
                    now - 3_600,
                ),
            ],
            now_unix: now,
            recent_limit: 5,
        };
        let s = format_dashboard(&snap);
        assert!(s.contains("Hoje (últimas 24h)"));
        assert!(s.contains("faturas PIX:"));
        assert!(s.contains("pagas: demo-1"));
        assert!(s.contains("(velho→novo)"));
        assert!(s.contains("há 1h")); // relative time prefix
        assert!(s.contains("PIX")); // movement tag
    }
}
