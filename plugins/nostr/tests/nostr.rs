//! Host integration test: exercise the pure core end-to-end (config → REQ frame
//! → decode a relay EVENT → inbound), the exact path the wasm shim drives over
//! the host WebSocket. No wasm, no sockets.

use nostr::nostr::{
    decode_relay_message, event_to_inbound, should_emit, NostrConfig, RelayMessage,
};

const HEX: &str = "abababababababababababababababababababababababababababababababab";

#[test]
fn subscribe_then_receive_a_note() {
    // 1) Operator configures a single relay and their pubkey (mentions mode).
    let cfg = NostrConfig::from_json(&format!(
        r#"{{"relays":["wss://relay.example"],"pubkey":"{HEX}"}}"#
    ));
    assert_eq!(cfg.first_relay(), Some("wss://relay.example"));

    // 2) The shim would send this REQ frame on connect.
    let req: Vec<serde_json::Value> = serde_json::from_str(&cfg.build_req_frame()).unwrap();
    assert_eq!(req[0], serde_json::json!("REQ"));
    assert_eq!(req[2]["#p"], serde_json::json!([HEX]));

    // 3) The relay streams back a matching plaintext note.
    let frame = format!(
        r#"["EVENT","sub1",{{"id":"evt1","pubkey":"{HEX}","created_at":1700000000,"kind":1,"tags":[],"content":"gm nostr"}}]"#
    );
    let event = match decode_relay_message(&frame) {
        RelayMessage::Event { event, .. } => event,
        other => panic!("expected an EVENT, got {other:?}"),
    };

    // 4) It passes the emit gate and maps onto an inbound message.
    assert!(should_emit(&cfg, &event));
    let inbound = event_to_inbound(&event, None);
    assert_eq!(inbound.sender, HEX);
    assert_eq!(inbound.reply_target, HEX);
    assert_eq!(inbound.content, "gm nostr");
    assert_eq!(inbound.timestamp, 1_700_000_000_000);
}

#[test]
fn control_frames_do_not_produce_inbound() {
    // EOSE / NOTICE / OK / CLOSED / AUTH are not events, so nothing is emitted.
    for frame in [
        r#"["EOSE","sub1"]"#,
        r#"["NOTICE","hi"]"#,
        r#"["OK","x",true,""]"#,
        r#"["CLOSED","sub1","bye"]"#,
        r#"["AUTH","c"]"#,
    ] {
        assert!(!matches!(
            decode_relay_message(frame),
            RelayMessage::Event { .. }
        ));
    }
}

#[test]
fn delivery_cursor_round_trips_and_narrows_the_subscription() {
    use nostr::nostr::{decode_cursor, encode_cursor, since_after, NostrConfig};

    assert_eq!(
        decode_cursor(&encode_cursor(1_700_000_000)),
        Some(1_700_000_000)
    );
    assert_eq!(decode_cursor(b"not-a-number"), None);
    assert_eq!(since_after(None), None);
    assert_eq!(since_after(Some(1_700_000_000)), Some(1_700_000_001));
    assert_eq!(since_after(Some(u64::MAX)), Some(u64::MAX));

    let config = NostrConfig::default();
    let fresh: serde_json::Value = serde_json::from_str(&config.build_req_frame()).unwrap();
    assert!(fresh[2].get("since").is_none());
    let resumed: serde_json::Value =
        serde_json::from_str(&config.build_req_frame_since(Some(1_700_000_001))).unwrap();
    assert_eq!(resumed[2]["since"], 1_700_000_001);
}
