//! Vendored Solana primitives this plugin builds on.
//!
//! # Provenance
//! Copied from the `solana-core` crate in
//! <https://github.com/belumume/zeroclaw-solana>, revision
//! `b90dac0170ce24031f2e2726764caa7ac68288c2`, at
//! `crates/solana-core/src/{sanitize.rs,pubkey.rs,lib.rs}`.
//!
//! It is vendored rather than depended on because a registry plugin is built
//! from its own directory alone: CI copies `plugins/<name>/` and `wit/` into an
//! otherwise empty tree, so a path dependency pointing outside that directory
//! cannot resolve and a crate that is not published cannot be named as a
//! version dependency. Vendoring is also what the registry asks for in its own
//! words, "self-contained WIT components".
//!
//! `sanitize.rs` is verbatim. `pubkey.rs` is reduced to the base58 codec; the
//! omissions and the reason for them are documented in that file.

pub mod pubkey;
pub mod sanitize;

pub use pubkey::{Pubkey, PubkeyError};
pub use sanitize::{
    label_untrusted, sanitize_onchain, sanitize_onchain_bounded, truncate_to_byte_budget,
    Sanitized, DEFAULT_LABEL_MAX,
};

/// Shorten a base58 identifier for display: `AAAAAAAA…ZZZZZZZZ`. Operates on
/// CHARS, not bytes, so an untrusted non-ASCII input can never panic on a
/// non-char-boundary byte slice.
///
/// Eight characters a side rather than four. Eight base58 characters is roughly
/// 47 bits, so a GPU can grind a vanity address matching both ends of a 4+4
/// rendering and show a human a recipient that looks like the one they expect.
/// Sixteen characters is roughly 94 bits, which is not grindable, and the string
/// is still short enough to read in a chat line.
///
/// This is a defence for DISPLAY paths. A field that actually decides where
/// money goes should not be truncated at all, which is why the recipient in this
/// plugin's summary line is rendered in full.
pub fn short_pubkey(pk: &str) -> String {
    let n = pk.chars().count();
    if n <= 17 {
        pk.to_string()
    } else {
        let head: String = pk.chars().take(8).collect();
        let tail: String = pk.chars().skip(n - 8).collect();
        format!("{head}\u{2026}{tail}")
    }
}

#[cfg(test)]
mod short_pubkey_tests {
    use super::short_pubkey;

    #[test]
    fn shortens_a_long_base58() {
        assert_eq!(
            short_pubkey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            "EPjFWdd5\u{2026}ZwyTDt1v"
        );
    }

    #[test]
    fn leaves_a_short_identifier_alone() {
        // At or below the 17-char threshold the shortened form would be no
        // shorter than the input, so the input is returned unchanged.
        assert_eq!(short_pubkey("ABC"), "ABC");
        assert_eq!(short_pubkey("12345678901234567"), "12345678901234567");
    }

    #[test]
    fn counts_chars_rather_than_bytes() {
        // A multi-byte input must not panic on a non-char-boundary slice. This
        // is the case that makes the char-based implementation load-bearing
        // rather than a stylistic choice.
        let multibyte = "\u{00e9}".repeat(40);
        let shortened = short_pubkey(&multibyte);
        assert_eq!(shortened.chars().count(), 17);
    }
}
