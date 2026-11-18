//! Public Nostr feed configuration, signed-event validation and channel-message mapping.

use k256::schnorr::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Default relays, mirroring the native `default_nostr_relays()` so an operator
/// who omits `relays` still connects to a working set.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
];

/// Default subscription id used in the `REQ` frame.
pub const DEFAULT_SUBSCRIPTION_ID: &str = "sub1";

/// Default number of stored events to request on subscribe.
pub const DEFAULT_LIMIT: u64 = 20;

/// Kind of a plaintext short text note (NIP-01). The only kind we surface.
pub const KIND_TEXT_NOTE: u64 = 1;

/// Kind of a NIP-04 encrypted direct message. Never surfaced (we can't decrypt).
pub const KIND_ENCRYPTED_DM: u64 = 4;

/// The plugin's resolved config, mirroring the native `[channels.nostr.<alias>]`
/// section plus a couple of plugin-only conveniences (`relay_url`, `pubkey`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrConfig {
    /// Relay URLs (`wss://`). We connect to the first one (single-relay in
    /// v0.1.0; relay fan-out is a follow-up). Empty → the default relay set.
    pub relays: Vec<String>,
    /// Our own public key in 64-char hex, when known. When set we narrow the
    /// subscription to notes that `#p`-tag us (i.e. mentions/replies); when
    /// absent we subscribe to recent public notes.
    pub pubkey: Option<String>,
    /// Event kinds to subscribe to. Defaults to `[1]` (plaintext notes).
    pub kinds: Vec<u64>,
    /// Subscription id used in the `REQ` frame.
    pub subscription_id: String,
    /// Number of stored events to request on subscribe.
    pub limit: u64,
    /// Sender allow-list (hex pubkeys or `"*"`). Empty = allow everyone
    /// (mirrors the sibling Telegram plugin's `allowed_users` semantics).
    pub allowed_pubkeys: Vec<String>,
    /// Host-configured TLS profile for the relay (a private CA or a client
    /// certificate). `None` uses the roots the host already trusts.
    pub tls_profile: Option<String>,
}

impl Default for NostrConfig {
    fn default() -> Self {
        Self {
            relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
            pubkey: None,
            kinds: vec![KIND_TEXT_NOTE],
            subscription_id: DEFAULT_SUBSCRIPTION_ID.to_string(),
            limit: DEFAULT_LIMIT,
            allowed_pubkeys: Vec::new(),
            tls_profile: None,
        }
    }
}

/// Raw wire shape as the host serializes the config section. Field names are the
/// snake_case keys the native `NostrConfig` uses, plus a few accepted aliases.
#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(default)]
    relays: Vec<String>,
    /// Convenience for a single relay.
    #[serde(default)]
    relay_url: Option<String>,
    #[serde(default)]
    relay: Option<String>,
    #[serde(default)]
    pubkey: Option<String>,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    kinds: Option<Vec<u64>>,
    #[serde(default)]
    subscription_id: Option<String>,
    #[serde(default)]
    limit: Option<u64>,
    #[serde(default)]
    allowed_pubkeys: Option<Vec<String>>,
    #[serde(default)]
    tls_profile: Option<String>,
}

impl NostrConfig {
    /// Parse the JSON config the host hands to `configure`. A malformed or empty
    /// string yields defaults (so a mis-permissioned `"{}"` is inert rather than
    /// a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        let raw: RawConfig = serde_json::from_str(config_json).unwrap_or_default();

        let mut relays: Vec<String> = raw.relays;
        if let Some(u) = raw.relay_url {
            relays.push(u);
        }
        if let Some(u) = raw.relay {
            relays.push(u);
        }
        let mut relays = dedup_nonempty(relays);
        if relays.is_empty() {
            relays = DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect();
        }

        let pubkey = raw
            .pubkey
            .or(raw.public_key)
            .and_then(|p| normalize_pubkey(&p));

        let kinds = match raw.kinds {
            Some(k) if !k.is_empty() => k,
            _ => vec![KIND_TEXT_NOTE],
        };

        let subscription_id = raw
            .subscription_id
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_SUBSCRIPTION_ID.to_string());

        let limit = raw.limit.unwrap_or(DEFAULT_LIMIT);

        // Keep `*` and normalize hex; unrecognizable entries (e.g. `npub…`,
        // which we can't decode without bech32) are retained verbatim so a
        // non-empty allow-list never silently degrades to allow-all — they
        // simply never match a hex sender. Mirrors the native's behavior.
        let allowed_pubkeys = raw
            .allowed_pubkeys
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .map(|p| {
                if p == "*" {
                    p
                } else {
                    normalize_pubkey(&p).unwrap_or(p)
                }
            })
            .collect();

        NostrConfig {
            relays,
            pubkey,
            kinds,
            subscription_id,
            limit,
            allowed_pubkeys,
            tls_profile: raw.tls_profile.filter(|p| !p.trim().is_empty()),
        }
    }

    /// The relay we connect to (the first configured one).
    pub fn first_relay(&self) -> Option<&str> {
        self.relays.first().map(String::as_str)
    }

    /// Build the `["REQ", <sub_id>, <filter>]` subscription frame as a JSON
    /// string. When `pubkey` is set, the filter narrows to notes that `#p`-tag
    /// us (mentions/replies); otherwise it samples recent notes of the
    /// configured `kinds`.
    pub fn build_req_frame(&self) -> String {
        self.build_req_frame_since(None)
    }

    /// The `REQ` frame, asking only for notes created at or after `since`
    /// (unix seconds) when a delivery cursor is known.
    pub fn build_req_frame_since(&self, since: Option<u64>) -> String {
        let mut filter = serde_json::Map::new();
        filter.insert("kinds".to_string(), json!(self.kinds));
        if self.limit > 0 {
            filter.insert("limit".to_string(), json!(self.limit));
        }
        if let Some(since) = since {
            filter.insert("since".to_string(), json!(since));
        }
        if let Some(pk) = &self.pubkey {
            filter.insert("#p".to_string(), json!([pk]));
        }
        json!(["REQ", self.subscription_id, Value::Object(filter)]).to_string()
    }

    /// Whether `pubkey_hex` (a received event's author) is permitted by the
    /// configured allow-list.
    pub fn is_pubkey_allowed(&self, pubkey_hex: &str) -> bool {
        is_pubkey_allowed(&self.allowed_pubkeys, pubkey_hex)
    }
}

/// Durable-state key for the delivery cursor: the `created_at` of the newest
/// note this instance has delivered.
pub const CURSOR_KEY: &str = "subscription-cursor";

/// Encode a delivery cursor for durable state.
pub fn encode_cursor(created_at: u64) -> Vec<u8> {
    created_at.to_string().into_bytes()
}

/// Decode a stored delivery cursor; `None` for anything malformed, which the
/// caller treats as "no cursor" rather than as an error.
pub fn decode_cursor(bytes: &[u8]) -> Option<u64> {
    std::str::from_utf8(bytes).ok()?.trim().parse().ok()
}

/// Trim, drop empties, and de-duplicate while preserving first-seen order.
fn dedup_nonempty(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for it in items {
        let t = it.trim().to_string();
        if !t.is_empty() && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// Normalize a public key to 64-char lowercase hex, or `None` if it is not a
/// plain hex pubkey. A leading `0x` is tolerated. `npub…` bech32 is intentionally
/// **not** decoded here (that needs bech32 and is a documented follow-up).
pub fn normalize_pubkey(raw: &str) -> Option<String> {
    let t = raw.trim();
    let t = t.strip_prefix("0x").unwrap_or(t);
    if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(t.to_ascii_lowercase())
    } else {
        None
    }
}

/// Whether `pubkey_hex` is permitted by `allowed`. An empty list allows everyone;
/// a `"*"` entry allows everyone; otherwise an entry matches by lowercased hex.
pub fn is_pubkey_allowed(allowed: &[String], pubkey_hex: &str) -> bool {
    if allowed.is_empty() {
        return true;
    }
    if allowed.iter().any(|a| a == "*") {
        return true;
    }
    let target = pubkey_hex.trim().to_ascii_lowercase();
    allowed.iter().any(|a| a.eq_ignore_ascii_case(&target))
}

/// NIP-01 signed event. Verify both the event ID and its author's signature.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub content: String,
    pub tags: Vec<Vec<String>>,
    pub sig: String,
}

impl NostrEvent {
    fn verify(&self) -> Option<()> {
        if self.id.len() != 64 || self.pubkey.len() != 64 || self.sig.len() != 128 {
            return None;
        }
        let serialized = serde_json::to_vec(&(
            0,
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        ))
        .ok()?;
        let id = Sha256::digest(serialized);
        if hex::encode(id) != self.id {
            return None;
        }
        let key = VerifyingKey::from_bytes(&hex::decode(&self.pubkey).ok()?).ok()?;
        let signature = Signature::try_from(hex::decode(&self.sig).ok()?.as_slice()).ok()?;
        key.verify_prehash(&id, &signature).ok()
    }
}

/// A decoded relay → client message (NIP-01 / NIP-42 wire frames).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMessage {
    /// A matched event delivered on a subscription.
    Event {
        subscription_id: String,
        event: NostrEvent,
    },
    /// End of stored events for a subscription; live events follow.
    EndOfStoredEvents { subscription_id: String },
    /// Human-readable relay notice.
    Notice { message: String },
    /// Acknowledgement of a published event.
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    /// The relay closed a subscription.
    Closed {
        subscription_id: String,
        message: String,
    },
    /// NIP-42 auth challenge (unhandled in receive-only mode).
    Auth { challenge: String },
    /// A frame we don't handle or couldn't parse.
    Unknown,
}

/// Decode one relay text frame (a JSON array) into a [`RelayMessage`].
pub fn decode_relay_message(text: &str) -> RelayMessage {
    let arr: Vec<Value> = match serde_json::from_str(text) {
        Ok(a) => a,
        Err(_) => return RelayMessage::Unknown,
    };
    let tag = arr.first().and_then(Value::as_str).unwrap_or("");
    let str_at = |i: usize| arr.get(i).and_then(Value::as_str).unwrap_or("").to_string();
    match tag {
        "EVENT" => match arr.get(2).cloned() {
            Some(v) => match serde_json::from_value::<NostrEvent>(v) {
                Ok(event) if event.verify().is_some() => RelayMessage::Event {
                    subscription_id: str_at(1),
                    event,
                },
                _ => RelayMessage::Unknown,
            },
            None => RelayMessage::Unknown,
        },
        "EOSE" => RelayMessage::EndOfStoredEvents {
            subscription_id: str_at(1),
        },
        "NOTICE" => RelayMessage::Notice { message: str_at(1) },
        "OK" => RelayMessage::Ok {
            event_id: str_at(1),
            accepted: arr.get(2).and_then(Value::as_bool).unwrap_or(false),
            message: str_at(3),
        },
        "CLOSED" => RelayMessage::Closed {
            subscription_id: str_at(1),
            message: str_at(2),
        },
        "AUTH" => RelayMessage::Auth {
            challenge: str_at(1),
        },
        _ => RelayMessage::Unknown,
    }
}

/// A Nostr note mapped onto the host inbound-message fields (`channel` is stamped
/// `"nostr"` by the shim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub channel_alias: Option<String>,
    /// Unix timestamp in **milliseconds** (the WIT contract).
    pub timestamp: u64,
}

/// Map a note event to an [`Inbound`]. `sender` and `reply_target` are the
/// author's hex pubkey (so a reply is addressed back to them); `timestamp` is
/// converted from the event's seconds to milliseconds.
pub fn event_to_inbound(event: &NostrEvent, alias: Option<&str>) -> Inbound {
    Inbound {
        id: event.id.clone(),
        sender: event.pubkey.clone(),
        reply_target: event.pubkey.clone(),
        content: event.content.clone(),
        channel_alias: alias.map(str::to_string),
        timestamp: event.created_at.saturating_mul(1000),
    }
}

/// Whether a decoded event should be surfaced as an inbound message: it must be
/// a configured, non-encrypted kind with non-empty content, a non-empty id, and
/// an allow-listed author.
pub fn should_emit(cfg: &NostrConfig, event: &NostrEvent) -> bool {
    if event.id.trim().is_empty() || event.pubkey.trim().is_empty() {
        return false;
    }
    if matches!(event.kind, KIND_ENCRYPTED_DM | 13 | 1059) {
        return false; // Private/sealed events belong to the encrypted-message path.
    }
    if !cfg.kinds.contains(&event.kind) {
        return false;
    }
    if event.content.trim().is_empty() {
        return false;
    }
    cfg.is_pubkey_allowed(&event.pubkey)
        && cfg.pubkey.as_ref().is_none_or(|own| {
            event
                .tags
                .iter()
                .any(|tag| tag.first().is_some_and(|kind| kind == "p") && tag.get(1) == Some(own))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const HEX_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn note(id: &str, pubkey: &str, kind: u64, content: &str) -> NostrEvent {
        NostrEvent {
            tags: vec![],
            sig: String::new(),
            id: id.to_string(),
            pubkey: pubkey.to_string(),
            created_at: 1_700_000_000,
            kind,
            content: content.to_string(),
        }
    }

    // ── config parsing ────────────────────────────────────────────────────

    #[test]
    fn empty_config_yields_defaults() {
        let cfg = NostrConfig::from_json("");
        assert_eq!(cfg.relays, DEFAULT_RELAYS);
        assert_eq!(cfg.kinds, vec![KIND_TEXT_NOTE]);
        assert_eq!(cfg.subscription_id, DEFAULT_SUBSCRIPTION_ID);
        assert_eq!(cfg.limit, DEFAULT_LIMIT);
        assert!(cfg.pubkey.is_none());
        assert!(cfg.allowed_pubkeys.is_empty());
    }

    #[test]
    fn malformed_config_is_defaults_not_panic() {
        let cfg = NostrConfig::from_json("{not json");
        assert_eq!(cfg.relays, DEFAULT_RELAYS);
    }

    #[test]
    fn relays_array_is_read_and_deduped() {
        let cfg = NostrConfig::from_json(
            r#"{"relays":["wss://a.example ","wss://a.example","wss://b.example"]}"#,
        );
        assert_eq!(cfg.relays, vec!["wss://a.example", "wss://b.example"]);
    }

    #[test]
    fn relay_url_and_relay_aliases_are_merged() {
        let cfg = NostrConfig::from_json(
            r#"{"relays":["wss://a.example"],"relay_url":"wss://b.example","relay":"wss://c.example"}"#,
        );
        assert_eq!(
            cfg.relays,
            vec!["wss://a.example", "wss://b.example", "wss://c.example"]
        );
    }

    #[test]
    fn empty_relays_fall_back_to_defaults() {
        let cfg = NostrConfig::from_json(r#"{"relays":[]}"#);
        assert_eq!(cfg.relays, DEFAULT_RELAYS);
    }

    #[test]
    fn pubkey_hex_is_normalized_lowercase() {
        let upper = HEX_A.to_ascii_uppercase();
        let cfg = NostrConfig::from_json(&format!(r#"{{"pubkey":"{upper}"}}"#));
        assert_eq!(cfg.pubkey.as_deref(), Some(HEX_A));
    }

    #[test]
    fn public_key_alias_is_accepted() {
        let cfg = NostrConfig::from_json(&format!(r#"{{"public_key":"{HEX_A}"}}"#));
        assert_eq!(cfg.pubkey.as_deref(), Some(HEX_A));
    }

    #[test]
    fn npub_pubkey_is_dropped_not_used() {
        // We can't decode bech32 in the pure core; a non-hex pubkey is ignored
        // (→ no `#p` filter) rather than producing a broken subscription.
        let cfg = NostrConfig::from_json(r#"{"pubkey":"npub1abcdef"}"#);
        assert!(cfg.pubkey.is_none());
    }

    #[test]
    fn kinds_and_limit_and_sub_id_overrides() {
        let cfg = NostrConfig::from_json(r#"{"kinds":[1,7],"limit":5,"subscription_id":"mysub"}"#);
        assert_eq!(cfg.kinds, vec![1, 7]);
        assert_eq!(cfg.limit, 5);
        assert_eq!(cfg.subscription_id, "mysub");
    }

    #[test]
    fn empty_kinds_falls_back_to_note() {
        let cfg = NostrConfig::from_json(r#"{"kinds":[]}"#);
        assert_eq!(cfg.kinds, vec![KIND_TEXT_NOTE]);
    }

    #[test]
    fn allowed_pubkeys_hex_normalized_wildcard_kept_npub_verbatim() {
        let upper = HEX_A.to_ascii_uppercase();
        let cfg = NostrConfig::from_json(&format!(
            r#"{{"allowed_pubkeys":["{upper}","*","npub1keep"," "]}}"#
        ));
        assert_eq!(
            cfg.allowed_pubkeys,
            vec![HEX_A.to_string(), "*".to_string(), "npub1keep".to_string()]
        );
    }

    // ── REQ frame ─────────────────────────────────────────────────────────

    #[test]
    fn req_frame_without_pubkey_has_no_p_filter() {
        let cfg = NostrConfig::from_json(r#"{"limit":3}"#);
        let frame: Vec<Value> = serde_json::from_str(&cfg.build_req_frame()).unwrap();
        assert_eq!(frame[0], json!("REQ"));
        assert_eq!(frame[1], json!("sub1"));
        let filter = &frame[2];
        assert_eq!(filter["kinds"], json!([1]));
        assert_eq!(filter["limit"], json!(3));
        assert!(filter.get("#p").is_none());
    }

    #[test]
    fn req_frame_with_pubkey_adds_mention_filter() {
        let cfg = NostrConfig::from_json(&format!(r#"{{"pubkey":"{HEX_A}"}}"#));
        let frame: Vec<Value> = serde_json::from_str(&cfg.build_req_frame()).unwrap();
        assert_eq!(frame[2]["#p"], json!([HEX_A]));
    }

    #[test]
    fn req_frame_omits_limit_when_zero() {
        let cfg = NostrConfig::from_json(r#"{"limit":0}"#);
        let frame: Vec<Value> = serde_json::from_str(&cfg.build_req_frame()).unwrap();
        assert!(frame[2].get("limit").is_none());
    }

    // ── relay message decode ──────────────────────────────────────────────

    #[test]
    fn reject_event_with_invalid_signature_or_content() {
        let raw = include_str!("../tests/signed-note.json");
        let mut frame: Value = serde_json::from_str(raw).unwrap();
        frame[2]["sig"] = json!("00".repeat(64));
        assert_eq!(
            decode_relay_message(&frame.to_string()),
            RelayMessage::Unknown
        );
        assert_eq!(
            decode_relay_message(&raw.replace("gm nostr", "different note")),
            RelayMessage::Unknown
        );
    }

    #[test]
    fn decode_eose_notice_ok_closed_auth() {
        assert_eq!(
            decode_relay_message(r#"["EOSE","sub1"]"#),
            RelayMessage::EndOfStoredEvents {
                subscription_id: "sub1".to_string()
            }
        );
        assert_eq!(
            decode_relay_message(r#"["NOTICE","rate limited"]"#),
            RelayMessage::Notice {
                message: "rate limited".to_string()
            }
        );
        assert_eq!(
            decode_relay_message(r#"["OK","evtid",true,""]"#),
            RelayMessage::Ok {
                event_id: "evtid".to_string(),
                accepted: true,
                message: String::new(),
            }
        );
        assert_eq!(
            decode_relay_message(r#"["CLOSED","sub1","auth-required"]"#),
            RelayMessage::Closed {
                subscription_id: "sub1".to_string(),
                message: "auth-required".to_string(),
            }
        );
        assert_eq!(
            decode_relay_message(r#"["AUTH","challenge-str"]"#),
            RelayMessage::Auth {
                challenge: "challenge-str".to_string()
            }
        );
    }

    #[test]
    fn decode_garbage_and_malformed_event_are_unknown() {
        assert_eq!(decode_relay_message("not json"), RelayMessage::Unknown);
        assert_eq!(decode_relay_message("{}"), RelayMessage::Unknown);
        assert_eq!(decode_relay_message(r#"["WAT"]"#), RelayMessage::Unknown);
        // EVENT with a non-object payload → Unknown, not a panic.
        assert_eq!(
            decode_relay_message(r#"["EVENT","sub1","oops"]"#),
            RelayMessage::Unknown
        );
    }

    // ── event → inbound mapping ───────────────────────────────────────────

    #[test]
    fn event_maps_to_inbound_with_ms_timestamp() {
        let ev = note("id1", HEX_A, 1, "gm");
        let inb = event_to_inbound(&ev, Some("main"));
        assert_eq!(inb.id, "id1");
        assert_eq!(inb.sender, HEX_A);
        assert_eq!(inb.reply_target, HEX_A);
        assert_eq!(inb.content, "gm");
        assert_eq!(inb.channel_alias.as_deref(), Some("main"));
        assert_eq!(inb.timestamp, 1_700_000_000_000);
    }

    // ── should_emit gating ────────────────────────────────────────────────

    #[test]
    fn emits_plaintext_note() {
        let cfg = NostrConfig::default();
        assert!(should_emit(&cfg, &note("i", HEX_A, 1, "hi")));
    }

    #[test]
    fn drops_encrypted_dm_even_if_kind_configured() {
        let cfg = NostrConfig {
            kinds: vec![1, KIND_ENCRYPTED_DM, 13, 1059],
            ..NostrConfig::default()
        };
        for kind in [KIND_ENCRYPTED_DM, 13, 1059] {
            assert!(!should_emit(&cfg, &note("i", HEX_A, kind, "ciphertext")));
        }
    }

    #[test]
    fn drops_unconfigured_kind_and_empty_content_and_empty_ids() {
        let cfg = NostrConfig::default(); // kinds = [1]
        assert!(!should_emit(&cfg, &note("i", HEX_A, 7, "reaction")));
        assert!(!should_emit(&cfg, &note("i", HEX_A, 1, "   ")));
        assert!(!should_emit(&cfg, &note("", HEX_A, 1, "hi")));
        assert!(!should_emit(&cfg, &note("i", "", 1, "hi")));
    }

    #[test]
    fn allowlist_gates_by_author() {
        let gated = NostrConfig {
            allowed_pubkeys: vec![HEX_A.to_string()],
            ..NostrConfig::default()
        };
        assert!(should_emit(&gated, &note("i", HEX_A, 1, "hi")));
        assert!(!should_emit(&gated, &note("i", HEX_B, 1, "hi")));

        let wildcard = NostrConfig {
            allowed_pubkeys: vec!["*".to_string()],
            ..NostrConfig::default()
        };
        assert!(should_emit(&wildcard, &note("i", HEX_B, 1, "hi")));
    }

    // ── helpers ───────────────────────────────────────────────────────────

    #[test]
    fn is_pubkey_allowed_semantics() {
        assert!(is_pubkey_allowed(&[], HEX_A)); // empty = allow all
        assert!(is_pubkey_allowed(&["*".to_string()], HEX_A));
        assert!(is_pubkey_allowed(&[HEX_A.to_string()], HEX_A));
        assert!(is_pubkey_allowed(
            &[HEX_A.to_string()],
            &HEX_A.to_ascii_uppercase()
        ));
        assert!(!is_pubkey_allowed(&[HEX_A.to_string()], HEX_B));
        // A retained npub entry never matches a hex sender (safe deny).
        assert!(!is_pubkey_allowed(&["npub1abc".to_string()], HEX_A));
    }

    #[test]
    fn normalize_pubkey_accepts_hex_rejects_others() {
        assert_eq!(normalize_pubkey(HEX_A), Some(HEX_A.to_string()));
        assert_eq!(
            normalize_pubkey(&format!("0x{HEX_A}")),
            Some(HEX_A.to_string())
        );
        assert_eq!(normalize_pubkey("npub1abc"), None);
        assert_eq!(normalize_pubkey("tooshort"), None);
        assert_eq!(normalize_pubkey(&"z".repeat(64)), None);
    }

    #[test]
    fn first_relay_is_first_configured() {
        let cfg = NostrConfig::from_json(r#"{"relays":["wss://one.example","wss://two.example"]}"#);
        assert_eq!(cfg.first_relay(), Some("wss://one.example"));
    }
}
