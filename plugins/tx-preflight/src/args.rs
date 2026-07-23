//! Argument handling for `tx-preflight`.
//!
//! Pure: no wasm, no network. The interesting decision here is about **where
//! each input comes from**, which is a security question rather than an
//! ergonomic one.
//!
//! The transaction arrives in `args`, supplied by the model. That is fine —
//! the whole point is to inspect something untrusted.
//!
//! The wallet being protected, the RPC endpoint, and every spending limit
//! arrive in `__config`, which the host injects and which it strips from
//! caller-supplied args first. If the model could name the owner, a poisoned
//! agent would simply verify a transaction against *someone else's* empty
//! wallet, collect a clean PASS, and hand the human a green light on a drain.
//! Same for the RPC: an attacker-controlled endpoint can return any "before"
//! state it likes.
//!
//! So: untrusted input in `args`, trusted parameters in `__config`, and never
//! the other way around.

use std::collections::HashMap;

use cupel_core::message::Pubkey;

/// What the model asked us to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Base64 transaction, signed or not.
    pub transaction: String,
}

/// Trusted parameters, injected by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub rpc_url: String,
    pub owner: Pubkey,
}

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// Split an `execute` payload into the model's request and the host's config.
pub fn parse_args(args: &str) -> Result<(Request, HashMap<String, String>), String> {
    let value: serde_json::Value =
        serde_json::from_str(args).map_err(|e| format!("arguments are not valid JSON: {e}"))?;

    let transaction = value
        .get("transaction")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "missing required argument: transaction (base64)".to_string())?
        .to_string();

    let config = value
        .get("__config")
        .and_then(serde_json::Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    Ok((Request { transaction }, config))
}

/// Give an `https://` URL an explicit `:443` when it has no port.
///
/// Outbound requests from a plugin travel `waki` -> `wasi:http` -> the host's
/// `default-send-request` handler, which builds a TCP authority from the
/// request. A scheme's *default* port does not survive that trip: an
/// authority with no port dials **80**, so an `https://` endpoint is refused
/// before TLS is ever attempted. The failure surfaces as
/// `ErrorCode::ConnectionRefused`, which is the handler's catch-all and says
/// nothing about the cause — it looks exactly like an endpoint being down.
///
/// Naming the port removes the ambiguity, and an operator should not have to
/// know any of this to configure a URL.
pub fn normalise_https_port(url: &str) -> String {
    let Some(rest) = url.strip_prefix("https://") else {
        return url.to_string();
    };

    // Split the authority from whatever follows it.
    let split = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(split);

    if authority.is_empty() {
        return url.to_string();
    }

    // A bracketed IPv6 literal carries its own colons; only a colon *after*
    // the closing bracket is a port.
    let has_port = match authority.strip_prefix('[') {
        Some(_) => authority
            .rfind(']')
            .is_some_and(|close| authority[close + 1..].starts_with(':')),
        None => authority.contains(':'),
    };

    if has_port {
        url.to_string()
    } else {
        format!("https://{authority}:443{tail}")
    }
}

/// Read the trusted parameters.
///
/// `owner_pubkey` is mandatory and has no default: guessing whose wallet to
/// protect is not a thing this tool is willing to do.
pub fn settings_from_config(config: &HashMap<String, String>) -> Result<Settings, String> {
    let owner = config
        .get("owner_pubkey")
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "owner_pubkey is not configured: tx-preflight cannot tell whose funds to protect"
                .to_string()
        })
        .and_then(|s| Pubkey::from_base58(s).map_err(|e| format!("owner_pubkey {e}")))?;

    let raw_url = config
        .get("rpc_url")
        .map(String::as_str)
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .unwrap_or(DEFAULT_RPC_URL);

    if !raw_url.starts_with("https://") {
        return Err(format!(
            "rpc_url must be https, got '{raw_url}': a plaintext endpoint can be rewritten in flight"
        ));
    }

    Ok(Settings {
        rpc_url: normalise_https_port(raw_url),
        owner,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    const OWNER: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

    #[test]
    fn reads_the_transaction_and_the_config() {
        let (request, cfg) = parse_args(
            r#"{"transaction":"AQAB","__config":{"rpc_url":"https://rpc.example","owner_pubkey":"abc"}}"#,
        )
        .expect("well-formed args parse");

        assert_eq!(request.transaction, "AQAB");
        assert_eq!(cfg.get("rpc_url").unwrap(), "https://rpc.example");
    }

    #[test]
    fn a_missing_transaction_is_an_error() {
        assert!(parse_args(r#"{"__config":{}}"#).is_err());
        assert!(parse_args(r#"{"transaction":""}"#).is_err());
        assert!(parse_args(r#"{"transaction":"   "}"#).is_err());
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(parse_args("not json").is_err());
    }

    #[test]
    fn absent_config_parses_but_yields_no_settings() {
        let (_, cfg) = parse_args(r#"{"transaction":"AQAB"}"#).unwrap();
        assert!(cfg.is_empty());
        assert!(settings_from_config(&cfg).is_err());
    }

    #[test]
    fn the_owner_must_be_configured_and_is_never_defaulted() {
        let err = settings_from_config(&config(&[("rpc_url", "https://rpc.example")]))
            .expect_err("an unconfigured owner must not be guessed");
        assert!(err.contains("owner_pubkey"));
    }

    #[test]
    fn a_malformed_owner_is_rejected() {
        assert!(settings_from_config(&config(&[("owner_pubkey", "0OIl")])).is_err());
        assert!(settings_from_config(&config(&[("owner_pubkey", "   ")])).is_err());
    }

    #[test]
    fn the_owner_comes_only_from_config_never_from_arguments() {
        // A poisoned agent naming its own wallet would otherwise get a clean
        // PASS on a transaction draining the operator's.
        let (_, cfg) = parse_args(
            r#"{"transaction":"AQAB","owner_pubkey":"AttackerControlledKey","__config":{"owner_pubkey":"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"}}"#,
        )
        .unwrap();

        let settings = settings_from_config(&cfg).unwrap();
        assert_eq!(settings.owner.to_base58(), OWNER);
    }

    #[test]
    fn plaintext_endpoints_are_refused() {
        let err = settings_from_config(&config(&[
            ("owner_pubkey", OWNER),
            ("rpc_url", "http://rpc.example"),
        ]))
        .expect_err("http must not be accepted");
        assert!(err.contains("must be https"));
    }

    #[test]
    fn an_absent_rpc_url_falls_back_to_a_public_endpoint() {
        let settings = settings_from_config(&config(&[("owner_pubkey", OWNER)])).unwrap();
        assert_eq!(settings.rpc_url, "https://api.mainnet-beta.solana.com:443");
    }

    #[test]
    fn a_portless_https_url_gains_443() {
        // Without this the request dials port 80 and is refused before TLS.
        assert_eq!(
            normalise_https_port("https://api.devnet.solana.com"),
            "https://api.devnet.solana.com:443"
        );
    }

    #[test]
    fn an_explicit_port_is_left_alone() {
        assert_eq!(
            normalise_https_port("https://api.devnet.solana.com:443"),
            "https://api.devnet.solana.com:443"
        );
        assert_eq!(
            normalise_https_port("https://rpc.example:8899"),
            "https://rpc.example:8899"
        );
    }

    #[test]
    fn a_path_survives_normalisation() {
        assert_eq!(
            normalise_https_port("https://rpc.example/v1/key"),
            "https://rpc.example:443/v1/key"
        );
        assert_eq!(
            normalise_https_port("https://rpc.example:8899/v1/key"),
            "https://rpc.example:8899/v1/key"
        );
    }

    #[test]
    fn a_query_string_survives_normalisation() {
        assert_eq!(
            normalise_https_port("https://rpc.example?api-key=abc"),
            "https://rpc.example:443?api-key=abc"
        );
    }

    #[test]
    fn ipv6_literals_are_not_mistaken_for_ports() {
        assert_eq!(
            normalise_https_port("https://[2001:db8::1]"),
            "https://[2001:db8::1]:443"
        );
        assert_eq!(
            normalise_https_port("https://[2001:db8::1]:8899"),
            "https://[2001:db8::1]:8899"
        );
    }

    #[test]
    fn non_https_urls_are_untouched() {
        assert_eq!(normalise_https_port("http://rpc.example"), "http://rpc.example");
        assert_eq!(normalise_https_port(""), "");
    }

    #[test]
    fn a_configured_url_reaches_settings_with_its_port() {
        let settings = settings_from_config(&config(&[
            ("owner_pubkey", OWNER),
            ("rpc_url", "https://api.devnet.solana.com"),
        ]))
        .unwrap();
        assert_eq!(settings.rpc_url, "https://api.devnet.solana.com:443");
    }
}
