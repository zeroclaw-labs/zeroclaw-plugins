//! Presentation helpers: QR-image URLs and clickable block-explorer links.
//!
//! Two side benefits beyond nicer output:
//! - A QR-image URL lets a chat channel render/preview a scannable code for a
//!   `solana:` payment request or an address, with no image bytes crossing the
//!   WIT boundary (the tool result stays a short string).
//! - Emitting an address *inside a link* shields it from a host's
//!   high-entropy leak-detection heuristic (a link destination is a protected
//!   span), so real base58 values reach the user unredacted while genuine
//!   secrets (deterministic patterns) are still caught.

/// RFC 3986 percent-encoding for URL query values.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// A QR-image URL that renders `data` as a scannable PNG (goqr.me, keyless).
/// For a Solana Pay request, pass the `solana:` URL; a Solana Pay wallet that
/// scans the resulting QR gets the transfer request.
pub fn qr_image_url(data: &str) -> String {
    format!(
        "https://api.qrserver.com/v1/create-qr-code/?size=320x320&margin=12&data={}",
        percent_encode(data)
    )
}

/// Solscan account page for an address — clickable, and shields the address
/// from high-entropy redaction.
pub fn explorer_account_url(address: &str) -> String {
    format!("https://solscan.io/account/{address}")
}

/// Solscan token page for a mint.
pub fn explorer_token_url(mint: &str) -> String {
    format!("https://solscan.io/token/{mint}")
}

/// Solana Explorer transaction inspector, pre-loaded with a transaction's
/// **message** for read-only review before signing. Pass base64 of the message
/// bytes (`CompiledMessage::message_bytes()`) — NOT the full unsigned tx, whose
/// leading signature-count byte would make the inspector misparse it. The value
/// is percent-encoded so base58/base64's `+ / =` survive as a query value.
/// This is a review link only: a transaction cannot be *signed* from a QR/URL
/// (that needs a hosted Solana Pay transaction-request endpoint); the human
/// still signs in their own wallet / Squads / CLI.
pub fn explorer_inspector_url(message_base64: &str) -> String {
    format!(
        "https://explorer.solana.com/tx/inspector?message={}",
        percent_encode(message_base64)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_url_encodes_solana_uri() {
        let q = qr_image_url("solana:ABC?amount=25&spl-token=XYZ");
        assert!(q.starts_with("https://api.qrserver.com/"));
        assert!(q.contains("solana%3AABC%3Famount%3D25")); // metacharacters encoded
        assert!(!q.contains(' '));
    }

    #[test]
    fn explorer_links() {
        assert_eq!(
            explorer_account_url("Fw1E"),
            "https://solscan.io/account/Fw1E"
        );
        assert_eq!(explorer_token_url("EPjF"), "https://solscan.io/token/EPjF");
    }

    #[test]
    fn inspector_url_percent_encodes_base64() {
        // base64's `+ / =` must be percent-encoded so the message survives as a
        // query value (Explorer decodeURIComponent's it exactly once).
        let u = explorer_inspector_url("AQAB+/xy==");
        assert!(u.starts_with("https://explorer.solana.com/tx/inspector?message="));
        assert!(u.contains("%2B") && u.contains("%2F") && u.contains("%3D"));
        assert!(!u.ends_with('+') && !u.contains("xy=="));
    }
}
