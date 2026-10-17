//! Pure portfolio-brief logic: aggregate, value, sort, and shape a wallet's
//! holdings into a compact human summary. No wasm, no HTTP, no host deps — the
//! shim in `lib.rs` fetches balances (RPC) and prices (HTTP) and hands the
//! decoded holdings here, so the shaping is fully covered by host `cargo test`.
//!
//! This module is the concrete answer to trap #3: it turns what could be dozens
//! of raw token-account blobs into the ~200 tokens the model actually needs.

use solana_core::shape::format_f64;

/// One holding, already valued by the shim (raw amount + decimals -> `ui_amount`,
/// price -> `usd_value`).
#[derive(Debug, Clone, PartialEq)]
pub struct Holding {
    /// Display label: a known symbol (e.g. "SOL", "USDC") or an abbreviated mint.
    pub label: String,
    /// UI amount (already scaled by the mint's decimals).
    pub ui_amount: f64,
    /// USD value, or `None` when no price was available.
    pub usd_value: Option<f64>,
    /// 24h price change in percent, when the price source provided it.
    pub change_24h_pct: Option<f64>,
}

/// A shaped brief: the holdings worth showing plus a compact tail summary.
#[derive(Debug, Clone, PartialEq)]
pub struct Brief {
    /// Priced holdings to display, sorted by USD value descending.
    pub shown: Vec<Holding>,
    /// Total USD across all priced holdings.
    pub total_usd: f64,
    /// Number of priced holdings not shown (below the display cap).
    pub hidden_priced_count: usize,
    /// Combined USD of the hidden priced holdings.
    pub hidden_priced_usd: f64,
    /// Number of holdings with no available price.
    pub unpriced_count: usize,
}

/// Build a brief: sum priced value, sort by USD descending, keep the top
/// `max_lines`, and summarize the rest. Dust with no price is counted, not
/// listed, so the output stays small.
pub fn build(holdings: Vec<Holding>, max_lines: usize) -> Brief {
    let total_usd: f64 = holdings.iter().filter_map(|h| h.usd_value).sum();

    let (mut priced, unpriced): (Vec<Holding>, Vec<Holding>) =
        holdings.into_iter().partition(|h| h.usd_value.is_some());

    // Descending by USD value (all priced holdings have Some).
    priced.sort_by(|a, b| {
        b.usd_value
            .unwrap_or(0.0)
            .total_cmp(&a.usd_value.unwrap_or(0.0))
    });

    let shown: Vec<Holding> = priced.iter().take(max_lines).cloned().collect();
    let hidden_priced_count = priced.len().saturating_sub(shown.len());
    let hidden_priced_usd: f64 = priced
        .iter()
        .skip(shown.len())
        .filter_map(|h| h.usd_value)
        .sum();

    Brief {
        shown,
        total_usd,
        hidden_priced_count,
        hidden_priced_usd,
        unpriced_count: unpriced.len(),
    }
}

/// Render a brief as a compact, model-friendly block.
pub fn render(owner: &str, brief: &Brief) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Portfolio for {} — total ~{}\n",
        owner,
        usd(brief.total_usd)
    ));

    if brief.shown.is_empty() {
        s.push_str("- no priced holdings found\n");
    }
    for h in &brief.shown {
        let value = h.usd_value.map(usd).unwrap_or_else(|| "—".to_string());
        let delta = h
            .change_24h_pct
            .map(|p| format!(" [{p:+.1}% 24h]"))
            .unwrap_or_default();
        s.push_str(&format!(
            "- {}: {} · {}{}\n",
            h.label,
            format_f64(h.ui_amount, 4),
            value,
            delta
        ));
    }

    let mut tail = Vec::new();
    if brief.hidden_priced_count > 0 {
        tail.push(format!(
            "{} smaller priced holding{} worth {}",
            brief.hidden_priced_count,
            plural(brief.hidden_priced_count),
            usd(brief.hidden_priced_usd)
        ));
    }
    if brief.unpriced_count > 0 {
        tail.push(format!(
            "{} unpriced token{}",
            brief.unpriced_count,
            plural(brief.unpriced_count)
        ));
    }
    if !tail.is_empty() {
        s.push_str(&format!("(+ {})\n", tail.join("; ")));
    }

    s.trim_end().to_string()
}

fn usd(v: f64) -> String {
    format!("${}", format_f64(v, 2))
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(label: &str, amount: f64, usd: Option<f64>, chg: Option<f64>) -> Holding {
        Holding {
            label: label.to_string(),
            ui_amount: amount,
            usd_value: usd,
            change_24h_pct: chg,
        }
    }

    #[test]
    fn sorts_by_usd_descending_and_totals() {
        let brief = build(
            vec![
                h("BONK", 1_200_000.0, Some(7.43), Some(5.1)),
                h("SOL", 12.5, Some(977.13), Some(2.3)),
                h("USDC", 250.0, Some(250.0), Some(-0.01)),
            ],
            10,
        );
        assert_eq!(brief.shown[0].label, "SOL");
        assert_eq!(brief.shown[1].label, "USDC");
        assert_eq!(brief.shown[2].label, "BONK");
        assert!((brief.total_usd - 1_234.56).abs() < 1e-6);
    }

    #[test]
    fn caps_lines_and_summarizes_the_tail() {
        let holdings = vec![
            h("A", 1.0, Some(100.0), None),
            h("B", 1.0, Some(50.0), None),
            h("C", 1.0, Some(10.0), None),
            h("D", 1.0, Some(5.0), None),
            h("dust1", 1.0, None, None),
            h("dust2", 1.0, None, None),
        ];
        let brief = build(holdings, 2);
        assert_eq!(brief.shown.len(), 2);
        assert_eq!(brief.shown[0].label, "A");
        assert_eq!(brief.hidden_priced_count, 2);
        assert!((brief.hidden_priced_usd - 15.0).abs() < 1e-9);
        assert_eq!(brief.unpriced_count, 2);
    }

    #[test]
    fn render_is_compact_and_readable() {
        let brief = build(
            vec![
                h("SOL", 12.5, Some(977.13), Some(2.3)),
                h("USDC", 250.0, Some(250.0), Some(-0.0)),
            ],
            10,
        );
        let text = render("7xKXAbc1111", &brief);
        assert!(text.starts_with("Portfolio for 7xKXAbc1111 — total ~$1,227.13"));
        assert!(text.contains("- SOL: 12.5 · $977.13 [+2.3% 24h]"));
        assert!(text.len() < 400);
    }

    #[test]
    fn render_handles_empty_and_unpriced_only() {
        let brief = build(vec![h("x", 1.0, None, None)], 10);
        let text = render("owner", &brief);
        assert!(text.contains("no priced holdings"));
        assert!(text.contains("1 unpriced token"));
    }
}
