//! Host integration test: exercise the pure core end-to-end (config → REQ frame
//! → decode a relay EVENT → inbound), the exact path the wasm shim drives over
//! the host WebSocket. No wasm, no sockets.

use nostr::nostr::{
    decode_relay_message, event_to_inbound, should_emit, NostrConfig, RelayMessage,
};

#[test]
fn subscribe_then_receive_a_note() {
    let cfg = NostrConfig::from_json(r#"{"relays":["wss://relay.example"]}"#);
    assert_eq!(cfg.first_relay(), Some("wss://relay.example"));

    // 2) The shim would send this REQ frame on connect.
    let req: Vec<serde_json::Value> = serde_json::from_str(&cfg.build_req_frame()).unwrap();
    assert_eq!(req[0], serde_json::json!("REQ"));
    assert_eq!(req[2]["kinds"], serde_json::json!([1]));

    // 3) The relay streams back a matching plaintext note.
    let frame = include_str!("signed-note.json");
    let event = match decode_relay_message(frame) {
        RelayMessage::Event { event, .. } => event,
        other => panic!("expected an EVENT, got {other:?}"),
    };

    // 4) It passes the emit gate and maps onto an inbound message.
    assert!(should_emit(&cfg, &event));
    let inbound = event_to_inbound(&event, None);
    assert_eq!(
        inbound.sender,
        "5be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c"
    );
    assert_eq!(inbound.reply_target, inbound.sender);
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
    use nostr::nostr::{decode_cursor, encode_cursor, NostrConfig};

    assert_eq!(
        decode_cursor(&encode_cursor(1_700_000_000)),
        Some(1_700_000_000)
    );
    assert_eq!(decode_cursor(b"not-a-number"), None);

    let config = NostrConfig::default();
    let fresh: serde_json::Value = serde_json::from_str(&config.build_req_frame()).unwrap();
    assert!(fresh[2].get("since").is_none());
    let resumed: serde_json::Value =
        serde_json::from_str(&config.build_req_frame_since(Some(1_700_000_000))).unwrap();
    assert_eq!(resumed[2]["since"], 1_700_000_000);
}
