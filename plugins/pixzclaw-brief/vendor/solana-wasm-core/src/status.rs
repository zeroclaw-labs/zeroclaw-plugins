//! Invoice status shaping from Solana signature lists (+ optional PIX flag).

use std::cmp::Ordering;

use crate::amount::{compare_units_to_decimal, format_minor_units};
use crate::rpc::SignatureInfo;
use crate::shape::short_label;

/// Build a short LLM-oriented status string from signature query results.
///
/// Honesty rules:
/// - USDC leg is inferred only from successful signatures on `reference`.
/// - PIX bank settlement is **not** visible on-chain; only confirmed when
///   `pix_marked_paid` is true (operator / PSP signal).
pub fn status_from_signatures(
    invoice_id: &str,
    reference: &str,
    sigs: &[SignatureInfo],
    expected_usdc: Option<&str>,
    pix_marked_paid: bool,
) -> String {
    let id = if invoice_id.trim().is_empty() {
        "(unknown)"
    } else {
        invoice_id.trim()
    };
    let ref_short = short_label(reference, 12);

    let successful: Vec<&SignatureInfo> = sigs.iter().filter(|s| s.is_success()).collect();
    let failed = sigs.len().saturating_sub(successful.len());
    let usdc_paid = !successful.is_empty();

    let usdc_status = if !usdc_paid {
        if sigs.is_empty() {
            "USDC: PENDING (nenhuma assinatura no reference)".to_string()
        } else {
            format!("USDC: PENDING ({failed} sig(s) com erro; nenhuma sucesso)")
        }
    } else {
        let latest = successful[0];
        let sig = &latest.signature;
        let sig_short = short_label(sig, 12);
        let conf = latest.confirmation_status.as_deref().unwrap_or("unknown");
        let explorer = format!("https://solscan.io/tx/{sig}");
        let amt_note = expected_usdc
            .map(|a| format!(" esperado={a} USDC"))
            .unwrap_or_default();
        format!(
            "USDC: PAID ({n} sig ok) latest={sig_short} conf={conf}{amt_note}\nEXPLORER: {explorer}",
            n = successful.len(),
        )
    };

    let pix_status = if pix_marked_paid {
        "PIX: PAID (marcado pelo operador — SPI/banco NÃO verificado por esta tool)".to_string()
    } else {
        "PIX: PENDING (tool não vê SPI do banco; use pix_marked_paid=true se confirmou)".to_string()
    };

    let overall = match (pix_marked_paid, usdc_paid) {
        (true, true) => "OVERALL: ambos trilhos com indício de pagamento",
        (true, false) => "OVERALL: PIX marcado; USDC PENDING",
        (false, true) => "OVERALL: USDC PAID; PIX não confirmado",
        (false, false) => "OVERALL: PENDING nos dois trilhos",
    };

    format!("INVOICE: {id}\nREF: {ref_short}\n{usdc_status}\n{pix_status}\n{overall}")
}

/// Verified USDC settlement detail extracted from `getTransaction`.
///
/// `received_units` is the net amount of the invoice mint **received by the
/// merchant** (`post − pre` token balances), in **minor units** at `decimals`.
/// It is an exact integer on purpose: this is the number the merchant is told
/// they were paid, so no part of its path may go through floating point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsdcReceipt {
    /// Net amount received by the merchant for the invoice mint, minor units.
    pub received_units: u128,
    /// Decimals of the invoice mint, as reported by the RPC.
    pub decimals: u32,
    /// Block time (unix seconds) of the paying transaction, if known.
    pub block_time: Option<i64>,
}

/// Value-aware invoice status.
///
/// Unlike [`status_from_signatures`] (which marks USDC PAID on the mere
/// existence of a successful signature), this checks the **amount actually
/// received by the merchant**:
///
/// - `USDC: PAID ✅` when received **equals** expected, to the minor unit.
/// - `USDC: UNDERPAID ⚠️` when `0 < received < expected` — including by one
///   minor unit. There is no tolerance band: a shortfall is a shortfall.
/// - `USDC: OVERPAID` when received > expected (still counts as paid).
/// - `USDC: RECEBIDO X` when **no** expected amount was provided but funds
///   arrived.
/// - `USDC: PENDING` when nothing arrived.
/// - `USDC: SIG OK (valor não verificado …)` when a successful signature exists
///   but `getTransaction` could not confirm the amount (`verified == None`),
///   **or** when an `expected_usdc` was supplied that cannot be used (a
///   wrong-locale `"27,27"`, a stray currency symbol, a zero). An unusable
///   expectation is not the same as no expectation: answering it with
///   `RECEBIDO` would hand a receipt to anyone who sent one dust unit.
///   This **never** claims PAID without a confirmed value.
///
/// The comparison is exact integer arithmetic on minor units — the same
/// discipline the issuing side ([`crate::amount`]) already used.
///
/// When paid with a confirmed value a shareable PT-BR receipt block is appended
/// for the merchant to forward to the customer.
pub fn status_from_signatures_verified(
    invoice_id: &str,
    reference: &str,
    sigs: &[SignatureInfo],
    verified: Option<UsdcReceipt>,
    expected_usdc: Option<&str>,
    pix_marked_paid: bool,
) -> String {
    let id = if invoice_id.trim().is_empty() {
        "(unknown)"
    } else {
        invoice_id.trim()
    };
    let ref_short = short_label(reference, 12);

    let successful: Vec<&SignatureInfo> = sigs.iter().filter(|s| s.is_success()).collect();
    let failed = sigs.len().saturating_sub(successful.len());

    // (usdc status text, confirmed-paid flag, optional receipt block)
    let (usdc_status, usdc_confirmed, receipt) = if successful.is_empty() {
        let text = if sigs.is_empty() {
            "USDC: PENDING (nenhuma assinatura no reference)".to_string()
        } else {
            format!("USDC: PENDING ({failed} sig(s) com erro; nenhuma sucesso)")
        };
        (text, false, None)
    } else {
        let latest = successful[0];
        let sig = latest.signature.as_str();
        let sig_short = short_label(sig, 12);
        let explorer = format!("https://solscan.io/tx/{sig}");
        let block_time = verified
            .as_ref()
            .and_then(|v| v.block_time)
            .or(latest.block_time);

        match &verified {
            // getTransaction unavailable / no meta → honest degrade.
            None => {
                let text = format!(
                    "USDC: SIG OK (valor não verificado — RPC não retornou a transação) \
                     latest={sig_short}\nEXPLORER: {explorer}"
                );
                (text, false, None)
            }
            Some(v) => {
                let recv_str = format_minor_units(v.received_units, v.decimals);
                // Three distinct states, and collapsing the last two is how a
                // dust payment used to buy a receipt: *no* expectation given
                // (report what arrived), an expectation that parses exactly and
                // is positive (compare), or an expectation that was given and
                // cannot be used — a wrong-locale `"27,27"`, a stray `R$`, a
                // zero. That last case must not be answered with a verdict.
                let expected_raw = expected_usdc.map(str::trim).filter(|s| !s.is_empty());
                let expected = expected_raw.and_then(|s| {
                    compare_units_to_decimal(v.received_units, v.decimals, s)
                        .ok()
                        .filter(|c| c.expected_units > 0)
                });
                let expected_unusable = expected_raw.is_some() && expected.is_none();

                if v.received_units == 0 {
                    // Successful signature but no USDC reached the merchant.
                    let text = format!(
                        "USDC: PENDING (assinatura sem transferência de USDC ao lojista) \
                         latest={sig_short}\nEXPLORER: {explorer}"
                    );
                    (text, false, None)
                } else if expected_unusable {
                    // An expectation was stated and could not be used. There is
                    // nothing to compare against, so there is no verdict — and
                    // emphatically no receipt for whatever did arrive.
                    let bad = short_label(&echo_safe(expected_raw.unwrap_or("")), 16);
                    let text = format!(
                        "USDC: SIG OK (recebido {recv_str}, mas expected_usdc inválido: \
                         {bad} — valor não comparado) latest={sig_short}\nEXPLORER: {explorer}"
                    );
                    (text, false, None)
                } else if let Some(cmp) = expected {
                    let exp_str = &cmp.expected_fmt;
                    match cmp.ordering {
                        Ordering::Less => {
                            let missing = &cmp.diff;
                            let text = format!(
                                "USDC: UNDERPAID ⚠️ (recebido {recv_str} de {exp_str} USDC — faltam {missing}) \
                                 latest={sig_short}\nEXPLORER: {explorer}"
                            );
                            (text, false, None)
                        }
                        Ordering::Greater => {
                            let excess = &cmp.diff;
                            let text = format!(
                                "USDC: OVERPAID (recebido {recv_str}, esperado {exp_str}; excedente {excess}) ✅ \
                                 latest={sig_short}\nEXPLORER: {explorer}"
                            );
                            let rc = build_receipt(id, &recv_str, block_time, sig, &sig_short);
                            (text, true, Some(rc))
                        }
                        Ordering::Equal => {
                            let text = format!(
                                "USDC: PAID ✅ (recebido {recv_str} de {exp_str} USDC) \
                                 latest={sig_short}\nEXPLORER: {explorer}"
                            );
                            let rc = build_receipt(id, &recv_str, block_time, sig, &sig_short);
                            (text, true, Some(rc))
                        }
                    }
                } else {
                    // Funds arrived but no expected amount to compare against.
                    let text = format!(
                        "USDC: RECEBIDO {recv_str} (sem valor esperado para comparar) \
                         latest={sig_short}\nEXPLORER: {explorer}"
                    );
                    let rc = build_receipt(id, &recv_str, block_time, sig, &sig_short);
                    (text, true, Some(rc))
                }
            }
        }
    };

    let pix_status = if pix_marked_paid {
        "PIX: PAID (marcado pelo operador — SPI/banco NÃO verificado por esta tool)".to_string()
    } else {
        "PIX: PENDING (tool não vê SPI do banco; use pix_marked_paid=true se confirmou)".to_string()
    };

    let overall = match (pix_marked_paid, usdc_confirmed) {
        (true, true) => "OVERALL: ambos trilhos com indício de pagamento",
        (true, false) => "OVERALL: PIX marcado; USDC não confirmado",
        (false, true) => "OVERALL: USDC PAID (valor conferido); PIX não confirmado",
        (false, false) => "OVERALL: PENDING (USDC não confirmado por valor)",
    };

    let mut out =
        format!("INVOICE: {id}\nREF: {ref_short}\n{usdc_status}\n{pix_status}\n{overall}");
    if let Some(rc) = receipt {
        out.push('\n');
        out.push_str(&rc);
    }
    // Settled with a confirmed amount → tell the agent to stop any watcher.
    // Never emitted on PENDING / UNDERPAID / SIG OK: the reminder must keep
    // running until the value is actually confirmed.
    if usdc_confirmed {
        out.push('\n');
        out.push_str(SETTLED_CRON_HINT);
    }
    out
}

/// Agent-facing instruction appended after the shareable receipt when the
/// invoice is settled with a confirmed amount. Always the last line, outside
/// the receipt block.
pub const SETTLED_CRON_HINT: &str = "[sistema] Fatura liquidada: se existir um lembrete cron desta fatura, remova-o (cron_remove) e não agende novos.";

/// Narrow a caller-supplied string down to characters that are safe to echo
/// back into the output.
///
/// The status block is a fixed shape of lines that a model reads; an
/// `expected_usdc` arriving from a tool call must not be able to introduce
/// newlines or markup into it just because it was rejected.
fn echo_safe(s: &str) -> String {
    s.chars()
        .filter(|&c| c.is_ascii_alphanumeric() || matches!(c, '.' | ',' | '-' | '+'))
        .collect()
}

/// Build the shareable PT-BR receipt block for a confirmed USDC payment.
fn build_receipt(
    invoice_id: &str,
    received_str: &str,
    block_time: Option<i64>,
    sig: &str,
    sig_short: &str,
) -> String {
    let date = match block_time {
        Some(ts) => format_unix_utc(ts),
        None => "data indisponível".to_string(),
    };
    format!(
        "──────────────────────\n\
         🧾 RECIBO — INVOICE #{invoice_id}\n\
         ✅ Pago em USDC (Solana)\n\
         Valor: {received_str} USDC (R$ equivalente na fatura)\n\
         Data: {date}\n\
         Tx: {sig_short}\n\
         🔗 https://solscan.io/tx/{sig}\n\
         ──────────────────────\n\
         👉 Encaminhe esta mensagem ao cliente como comprovante."
    )
}

/// Convert a unix timestamp (seconds, UTC) to `YYYY-MM-DD HH:MM UTC`.
///
/// Pure integer civil-date conversion (Howard Hinnant's algorithm) — no
/// external crate, no system clock. Valid for the full proleptic Gregorian
/// range and negative timestamps.
fn format_unix_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let hour = secs / 3_600;
    let minute = (secs % 3_600) / 60;

    // civil_from_days: days since 1970-01-01 → (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sig(signature: &str, ok: bool, memo: Option<&str>) -> SignatureInfo {
        SignatureInfo {
            signature: signature.into(),
            slot: 1,
            err: if ok {
                None
            } else {
                Some(json!({"InstructionError": [0, "Custom"]}))
            },
            memo: memo.map(|s| s.into()),
            block_time: Some(1),
            confirmation_status: Some("finalized".into()),
        }
    }

    #[test]
    fn unpaid_when_empty() {
        let s = status_from_signatures("inv-1", "RefABC123456", &[], Some("10"), false);
        assert!(s.contains("USDC: PENDING"));
        assert!(s.contains("PIX: PENDING"));
        assert!(s.contains("OVERALL: PENDING"));
    }

    #[test]
    fn usdc_paid_pix_open() {
        let sigs = vec![sig(
            "VeryLongSignature111ABCDEF",
            true,
            Some("PIX|BRL|inv-1|x"),
        )];
        let s = status_from_signatures("inv-1", "RefABC123456", &sigs, Some("10"), false);
        assert!(s.contains("USDC: PAID"));
        assert!(s.contains("solscan.io/tx/"));
        assert!(s.contains("PIX: PENDING") || s.contains("PIX não confirmado"));
    }

    #[test]
    fn both_rails() {
        let sigs = vec![sig("SigOK", true, None)];
        let s = status_from_signatures("inv-2", "RefXYZ", &sigs, None, true);
        assert!(s.contains("ambos trilhos") || s.contains("USDC: PAID"));
        assert!(s.contains("PIX: PAID"));
    }

    /// Receipt from a decimal string, parsed exactly at USDC's 6 decimals.
    fn recv(amount: &str) -> Option<UsdcReceipt> {
        Some(UsdcReceipt {
            received_units: crate::amount::parse_decimal(amount, 6).unwrap().value,
            decimals: 6,
            block_time: Some(1_700_000_000),
        })
    }

    #[test]
    fn verified_paid_exact_with_receipt() {
        let sigs = vec![sig("VeryLongSignaturePaid1", true, None)];
        let s = status_from_signatures_verified(
            "inv-001",
            "RefABC123456",
            &sigs,
            recv("27.27"),
            Some("27.27"),
            false,
        );
        assert!(s.contains("USDC: PAID ✅"), "{s}");
        assert!(s.contains("🧾 RECIBO — INVOICE #inv-001"), "{s}");
        assert!(s.contains("Valor: 27.27 USDC"), "{s}");
        assert!(s.contains("2023-11-14"), "date from block_time: {s}");
        assert!(s.contains("Encaminhe esta mensagem"), "{s}");
        assert!(s.contains("USDC PAID (valor conferido)"), "{s}");
    }

    /// FURO C: there is no tolerance band. 99.5% of an invoice is an
    /// underpayment, and so is a shortfall of a single minor unit.
    #[test]
    fn verified_no_tolerance_band() {
        let sigs = [sig("Sig", true, None)];

        // The old rule called this PAID and issued a receipt: 0.5% of a
        // R$ 1.000 invoice walked away free.
        let s = status_from_signatures_verified(
            "inv-1",
            "Ref",
            &sigs,
            recv("99.6"),
            Some("100"),
            false,
        );
        assert!(s.contains("USDC: UNDERPAID ⚠️"), "{s}");
        assert!(s.contains("recebido 99.6 de 100 USDC — faltam 0.4"), "{s}");
        assert!(!s.contains("RECIBO"), "no receipt on a shortfall: {s}");
        assert!(!s.contains("cron_remove"), "watcher must keep running: {s}");

        // One millionth of a USDC short is still short.
        let s = status_from_signatures_verified(
            "inv-1",
            "Ref",
            &sigs,
            recv("99.999999"),
            Some("100"),
            false,
        );
        assert!(s.contains("USDC: UNDERPAID ⚠️"), "{s}");
        assert!(s.contains("faltam 0.000001"), "{s}");

        // Exactly the invoiced amount is PAID.
        let s =
            status_from_signatures_verified("inv-1", "Ref", &sigs, recv("100"), Some("100"), false);
        assert!(s.contains("USDC: PAID ✅"), "{s}");
    }

    /// A decimal expected value that survived the f64 round-trip badly before.
    #[test]
    fn verified_exact_decimal_expected_is_paid() {
        let sigs = [sig("Sig", true, None)];
        for amount in ["0.1", "0.3", "1.1", "27.272727", "0.000001"] {
            let s = status_from_signatures_verified(
                "inv-1",
                "Ref",
                &sigs,
                recv(amount),
                Some(amount),
                false,
            );
            assert!(s.contains("USDC: PAID ✅"), "{amount}: {s}");
        }
    }

    #[test]
    fn verified_underpaid_no_receipt() {
        let sigs = [sig("Sig", true, None)];
        let s =
            status_from_signatures_verified("inv-1", "Ref", &sigs, recv("0.01"), Some("90"), false);
        assert!(s.contains("USDC: UNDERPAID ⚠️"), "{s}");
        assert!(s.contains("faltam"), "{s}");
        assert!(!s.contains("RECIBO"), "no receipt when underpaid: {s}");
        assert!(s.contains("PENDING (USDC não confirmado por valor)"), "{s}");
    }

    /// The exact line the demo video freezes on.
    #[test]
    fn verified_underpaid_matches_video_script_wording() {
        let sigs = [sig("Sig", true, None)];
        let s = status_from_signatures_verified(
            "INV-DEMO-A",
            "Ref",
            &sigs,
            recv("1"),
            Some("10"),
            false,
        );
        assert!(
            s.contains("USDC: UNDERPAID ⚠️ (recebido 1 de 10 USDC — faltam 9)"),
            "{s}"
        );
    }

    #[test]
    fn verified_overpaid_counts_as_paid() {
        let sigs = [sig("Sig", true, None)];
        let s =
            status_from_signatures_verified("inv-1", "Ref", &sigs, recv("120"), Some("100"), false);
        assert!(s.contains("USDC: OVERPAID"), "{s}");
        assert!(s.contains("excedente 20"), "{s}");
        assert!(s.contains("RECIBO"), "receipt on overpaid: {s}");
    }

    #[test]
    fn verified_no_expected_reports_received() {
        let sigs = [sig("Sig", true, None)];
        let s = status_from_signatures_verified("inv-1", "Ref", &sigs, recv("42.5"), None, false);
        assert!(s.contains("USDC: RECEBIDO 42.5"), "{s}");
        assert!(s.contains("sem valor esperado"), "{s}");
        assert!(s.contains("RECIBO"), "{s}");
    }

    /// An `expected_usdc` that was supplied but cannot be used must NOT be
    /// answered as if none had been supplied.
    ///
    /// `RECEBIDO` is a settled verdict: receipt, `usdc_confirmed`, cron
    /// teardown. Reaching it by typing `"27,27"` (the way a Brazilian merchant
    /// writes it) would mean one dust unit on the reference buys a receipt.
    #[test]
    fn verified_unusable_expected_degrades_instead_of_settling() {
        let sigs = [sig("Sig", true, None)];
        for bad in ["abc", "-5", "0", "R$ 27,27", "27,27"] {
            let s = status_from_signatures_verified(
                "inv-1",
                "Ref",
                &sigs,
                recv("0.000001"),
                Some(bad),
                false,
            );
            assert!(s.contains("USDC: SIG OK"), "{bad}: {s}");
            assert!(s.contains("expected_usdc inválido"), "{bad}: {s}");
            assert!(!s.contains("USDC: RECEBIDO"), "{bad}: {s}");
            assert!(!s.contains("PAID ✅"), "{bad}: {s}");
            assert!(!s.contains("RECIBO"), "no receipt: {bad}: {s}");
            assert!(
                !s.contains("cron_remove"),
                "watcher keeps running: {bad}: {s}"
            );
            assert!(
                s.contains("PENDING (USDC não confirmado por valor)"),
                "{bad}: {s}"
            );
        }
    }

    /// A blank / absent expectation is a different thing and keeps reporting
    /// what arrived, as documented.
    #[test]
    fn verified_absent_expected_still_reports_received() {
        let sigs = [sig("Sig", true, None)];
        for none_ish in [None, Some("  "), Some("")] {
            let s = status_from_signatures_verified(
                "inv-1",
                "Ref",
                &sigs,
                recv("42.5"),
                none_ish,
                false,
            );
            assert!(s.contains("USDC: RECEBIDO 42.5"), "{none_ish:?}: {s}");
        }
    }

    /// A mint with different decimals is rendered at its own precision.
    #[test]
    fn verified_respects_mint_decimals() {
        let sigs = [sig("Sig", true, None)];
        let nine = Some(UsdcReceipt {
            received_units: 1_500_000_000,
            decimals: 9,
            block_time: Some(1_700_000_000),
        });
        let s = status_from_signatures_verified("inv-1", "Ref", &sigs, nine, Some("1.5"), false);
        assert!(
            s.contains("USDC: PAID ✅ (recebido 1.5 de 1.5 USDC)"),
            "{s}"
        );
    }

    #[test]
    fn verified_degrades_when_tx_unavailable() {
        let sigs = [sig("Sig", true, None)];
        let s = status_from_signatures_verified("inv-1", "Ref", &sigs, None, Some("90"), false);
        assert!(s.contains("USDC: SIG OK"), "{s}");
        assert!(s.contains("valor não verificado"), "{s}");
        assert!(!s.contains("USDC: PAID"), "never PAID without value: {s}");
        assert!(!s.contains("RECIBO"), "{s}");
    }

    #[test]
    fn verified_zero_received_is_pending() {
        let sigs = [sig("Sig", true, None)];
        let s =
            status_from_signatures_verified("inv-1", "Ref", &sigs, recv("0"), Some("90"), false);
        assert!(s.contains("USDC: PENDING"), "{s}");
        assert!(s.contains("sem transferência de USDC"), "{s}");
    }

    #[test]
    fn verified_empty_sigs_pending() {
        let s = status_from_signatures_verified("inv-1", "Ref", &[], None, Some("90"), false);
        assert!(s.contains("USDC: PENDING (nenhuma assinatura"), "{s}");
    }

    /// Paid-with-confirmed-value cases must end with the cron-teardown line,
    /// after (and outside) the shareable receipt.
    #[test]
    fn settled_cron_hint_on_paid_overpaid_and_recebido() {
        let sigs = vec![sig("SigPaid", true, None)];
        let cases = [
            ("PAID", recv("27.27"), Some("27.27")),
            ("OVERPAID", recv("120"), Some("100")),
            ("RECEBIDO", recv("42.5"), None),
        ];
        for (name, verified, expected) in cases {
            let s =
                status_from_signatures_verified("inv-1", "Ref", &sigs, verified, expected, false);
            let last = s.lines().last().unwrap();
            assert_eq!(last, SETTLED_CRON_HINT, "{name}: {s}");
            assert!(last.starts_with("[sistema]"), "{name}");
            assert!(last.contains("cron_remove"), "{name}");
            assert_eq!(s.matches("[sistema]").count(), 1, "{name}: {s}");
            // Receipt still intact and *before* the system line.
            let rc = s.find("🧾 RECIBO").unwrap_or_else(|| panic!("{name}: {s}"));
            assert!(rc < s.find(SETTLED_CRON_HINT).unwrap(), "{name}: {s}");
            assert!(s.contains("Encaminhe esta mensagem ao cliente"), "{name}");
        }
    }

    /// Not settled (or value unconfirmed) → the watcher must keep running.
    #[test]
    fn no_settled_cron_hint_when_not_confirmed() {
        let sigs = [sig("Sig", true, None)];
        let cases = [
            // (label, sigs, verified, expected)
            ("PENDING empty", &[][..], None, Some("90")),
            ("PENDING zero", &sigs[..], recv("0"), Some("90")),
            ("UNDERPAID", &sigs[..], recv("0.01"), Some("90")),
            ("SIG OK", &sigs[..], None, Some("90")),
        ];
        for (name, s_in, verified, expected) in cases {
            let s =
                status_from_signatures_verified("inv-1", "Ref", s_in, verified, expected, false);
            assert!(!s.contains("cron_remove"), "{name}: {s}");
            assert!(!s.contains("[sistema]"), "{name}: {s}");
            assert!(!s.contains("Fatura liquidada"), "{name}: {s}");
        }
    }

    /// PIX marked + USDC confirmed still ends with the teardown line.
    #[test]
    fn settled_cron_hint_with_pix_marked() {
        let sigs = [sig("Sig", true, None)];
        let s =
            status_from_signatures_verified("inv-9", "Ref", &sigs, recv("10"), Some("10"), true);
        assert_eq!(s.lines().last().unwrap(), SETTLED_CRON_HINT, "{s}");
    }

    /// The non-verified legacy shaper never emits the teardown line.
    #[test]
    fn legacy_shaper_has_no_cron_hint() {
        let sigs = [sig("Sig", true, None)];
        let s = status_from_signatures("inv-1", "Ref", &sigs, Some("10"), false);
        assert!(!s.contains("cron_remove"), "{s}");
    }

    #[test]
    fn unix_utc_formatting() {
        assert_eq!(format_unix_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_unix_utc(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(format_unix_utc(1_609_459_200), "2021-01-01 00:00 UTC");
    }
}
