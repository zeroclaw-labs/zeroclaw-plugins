//! Invoice status shaping from Solana signature lists (+ optional PIX flag).

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
        let conf = latest
            .confirmation_status
            .as_deref()
            .unwrap_or("unknown");
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
/// `received_ui` is the net amount of the invoice mint **received by the
/// merchant** in the paying transaction (`post − pre` token balances).
#[derive(Debug, Clone)]
pub struct UsdcReceipt {
    /// Net UI amount received by the merchant for the invoice mint.
    pub received_ui: f64,
    /// Block time (unix seconds) of the paying transaction, if known.
    pub block_time: Option<i64>,
}

/// Value-aware invoice status.
///
/// Unlike [`status_from_signatures`] (which marks USDC PAID on the mere
/// existence of a successful signature), this checks the **amount actually
/// received by the merchant**:
///
/// - `USDC: PAID ✅` when received ≥ expected (tolerance ≥ 99.5%).
/// - `USDC: UNDERPAID ⚠️` when `0 < received < expected`.
/// - `USDC: OVERPAID` when received > expected (still counts as paid).
/// - `USDC: RECEBIDO X` when no expected amount was provided but funds arrived.
/// - `USDC: PENDING` when nothing arrived.
/// - `USDC: SIG OK (valor não verificado …)` when a successful signature exists
///   but `getTransaction` could not confirm the amount (`verified == None`).
///   This **never** claims PAID without a confirmed value.
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
                let received = v.received_ui;
                let recv_str = fmt_amount(received);
                let expected = expected_usdc
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .and_then(|s| s.parse::<f64>().ok().filter(|x| *x > 0.0));

                if received <= 0.0 {
                    // Successful signature but no USDC reached the merchant.
                    let text = format!(
                        "USDC: PENDING (assinatura sem transferência de USDC ao lojista) \
                         latest={sig_short}\nEXPLORER: {explorer}"
                    );
                    (text, false, None)
                } else if let Some(exp) = expected {
                    let exp_str = fmt_amount(exp);
                    let tol = exp * 0.995;
                    if received + 1e-9 < tol {
                        let missing = fmt_amount(exp - received);
                        let text = format!(
                            "USDC: UNDERPAID ⚠️ (recebido {recv_str} de {exp_str} USDC — faltam {missing}) \
                             latest={sig_short}\nEXPLORER: {explorer}"
                        );
                        (text, false, None)
                    } else if received > exp + 1e-6 {
                        let excess = fmt_amount(received - exp);
                        let text = format!(
                            "USDC: OVERPAID (recebido {recv_str}, esperado {exp_str}; excedente {excess}) ✅ \
                             latest={sig_short}\nEXPLORER: {explorer}"
                        );
                        let rc = build_receipt(id, &recv_str, block_time, sig, &sig_short);
                        (text, true, Some(rc))
                    } else {
                        let text = format!(
                            "USDC: PAID ✅ (recebido {recv_str} de {exp_str} USDC) \
                             latest={sig_short}\nEXPLORER: {explorer}"
                        );
                        let rc = build_receipt(id, &recv_str, block_time, sig, &sig_short);
                        (text, true, Some(rc))
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

/// Format an `f64` amount with up to 6 decimals, trimming trailing zeros.
fn fmt_amount(x: f64) -> String {
    let s = format!("{x:.6}");
    if !s.contains('.') {
        return s;
    }
    let t = s.trim_end_matches('0').trim_end_matches('.');
    if t.is_empty() {
        "0".to_string()
    } else {
        t.to_string()
    }
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
        let sigs = vec![sig("VeryLongSignature111ABCDEF", true, Some("PIX|BRL|inv-1|x"))];
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

    fn recv(ui: f64) -> Option<UsdcReceipt> {
        Some(UsdcReceipt {
            received_ui: ui,
            block_time: Some(1_700_000_000),
        })
    }

    #[test]
    fn verified_paid_exact_with_receipt() {
        let sigs = vec![sig("VeryLongSignaturePaid1", true, None)];
        let s = status_from_signatures_verified(
            "inv-001", "RefABC123456", &sigs, recv(27.27), Some("27.27"), false,
        );
        assert!(s.contains("USDC: PAID ✅"), "{s}");
        assert!(s.contains("🧾 RECIBO — INVOICE #inv-001"), "{s}");
        assert!(s.contains("Valor: 27.27 USDC"), "{s}");
        assert!(s.contains("2023-11-14"), "date from block_time: {s}");
        assert!(s.contains("Encaminhe esta mensagem"), "{s}");
        assert!(s.contains("USDC PAID (valor conferido)"), "{s}");
    }

    #[test]
    fn verified_tolerance_counts_as_paid() {
        // 99.6% of expected → within tolerance → PAID (no underpaid).
        let sigs = [sig("Sig", true, None)];
        let s = status_from_signatures_verified(
            "inv-1", "Ref", &sigs, recv(99.6), Some("100"), false,
        );
        assert!(s.contains("USDC: PAID ✅"), "{s}");
        assert!(!s.contains("UNDERPAID"), "{s}");
    }

    #[test]
    fn verified_underpaid_no_receipt() {
        let sigs = [sig("Sig", true, None)];
        let s = status_from_signatures_verified(
            "inv-1", "Ref", &sigs, recv(0.01), Some("90"), false,
        );
        assert!(s.contains("USDC: UNDERPAID ⚠️"), "{s}");
        assert!(s.contains("faltam"), "{s}");
        assert!(!s.contains("RECIBO"), "no receipt when underpaid: {s}");
        assert!(s.contains("PENDING (USDC não confirmado por valor)"), "{s}");
    }

    #[test]
    fn verified_overpaid_counts_as_paid() {
        let sigs = [sig("Sig", true, None)];
        let s = status_from_signatures_verified(
            "inv-1", "Ref", &sigs, recv(120.0), Some("100"), false,
        );
        assert!(s.contains("USDC: OVERPAID"), "{s}");
        assert!(s.contains("excedente 20"), "{s}");
        assert!(s.contains("RECIBO"), "receipt on overpaid: {s}");
    }

    #[test]
    fn verified_no_expected_reports_received() {
        let sigs = [sig("Sig", true, None)];
        let s = status_from_signatures_verified(
            "inv-1", "Ref", &sigs, recv(42.5), None, false,
        );
        assert!(s.contains("USDC: RECEBIDO 42.5"), "{s}");
        assert!(s.contains("sem valor esperado"), "{s}");
        assert!(s.contains("RECIBO"), "{s}");
    }

    #[test]
    fn verified_degrades_when_tx_unavailable() {
        let sigs = [sig("Sig", true, None)];
        let s = status_from_signatures_verified(
            "inv-1", "Ref", &sigs, None, Some("90"), false,
        );
        assert!(s.contains("USDC: SIG OK"), "{s}");
        assert!(s.contains("valor não verificado"), "{s}");
        assert!(!s.contains("USDC: PAID"), "never PAID without value: {s}");
        assert!(!s.contains("RECIBO"), "{s}");
    }

    #[test]
    fn verified_zero_received_is_pending() {
        let sigs = [sig("Sig", true, None)];
        let s = status_from_signatures_verified(
            "inv-1", "Ref", &sigs, recv(0.0), Some("90"), false,
        );
        assert!(s.contains("USDC: PENDING"), "{s}");
        assert!(s.contains("sem transferência de USDC"), "{s}");
    }

    #[test]
    fn verified_empty_sigs_pending() {
        let s = status_from_signatures_verified(
            "inv-1", "Ref", &[], None, Some("90"), false,
        );
        assert!(s.contains("USDC: PENDING (nenhuma assinatura"), "{s}");
    }

    /// Paid-with-confirmed-value cases must end with the cron-teardown line,
    /// after (and outside) the shareable receipt.
    #[test]
    fn settled_cron_hint_on_paid_overpaid_and_recebido() {
        let sigs = vec![sig("SigPaid", true, None)];
        let cases = [
            ("PAID", recv(27.27), Some("27.27")),
            ("OVERPAID", recv(120.0), Some("100")),
            ("RECEBIDO", recv(42.5), None),
        ];
        for (name, verified, expected) in cases {
            let s = status_from_signatures_verified(
                "inv-1", "Ref", &sigs, verified, expected, false,
            );
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
            ("PENDING zero", &sigs[..], recv(0.0), Some("90")),
            ("UNDERPAID", &sigs[..], recv(0.01), Some("90")),
            ("SIG OK", &sigs[..], None, Some("90")),
        ];
        for (name, s_in, verified, expected) in cases {
            let s = status_from_signatures_verified(
                "inv-1", "Ref", s_in, verified, expected, false,
            );
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
            status_from_signatures_verified("inv-9", "Ref", &sigs, recv(10.0), Some("10"), true);
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
