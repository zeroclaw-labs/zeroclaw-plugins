//! Host integration tests for the private-message path driven by the WASM shim.

use nostr::nostr::{
    build_direct_message, build_event_frame, decode_direct_message, decode_relay_message,
    DmProtocol, NostrConfig, NostrEvent, NostrKeys, RelayMessage, SUBSCRIPTION_ID,
};

const ALICE_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const BOB_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000002";

fn config(secret: &str) -> NostrConfig {
    NostrConfig::from_json(&format!(
        r#"{{"private_key":"{secret}","relays":["wss://relay.example"]}}"#
    ))
    .unwrap()
}

#[test]
fn nip17_conversation_round_trips_through_relay_frames() {
    let alice = config(ALICE_SECRET);
    let bob = config(BOB_SECRET);

    let outbound = build_direct_message(
        &alice.keys,
        &bob.keys.public_key(),
        "hello bob",
        DmProtocol::Nip17,
        1_700_000_000,
    )
    .unwrap();
    let event_frame = build_event_frame(&outbound).unwrap();
    assert!(event_frame.starts_with("[\"EVENT\","));

    let relay_frame =
        serde_json::to_string(&serde_json::json!(["EVENT", SUBSCRIPTION_ID, outbound])).unwrap();
    let event = match decode_relay_message(&relay_frame).unwrap() {
        RelayMessage::Event { event, .. } => event,
        other => panic!("expected relay event, got {other:?}"),
    };
    let inbound = decode_direct_message(&bob.keys, &event, 1_699_999_999)
        .unwrap()
        .unwrap();
    assert_eq!(inbound.sender, alice.keys.public_key());
    assert_eq!(inbound.content, "hello bob");
    assert_eq!(inbound.protocol, DmProtocol::Nip17);

    let reply = build_direct_message(
        &bob.keys,
        &inbound.sender,
        "hello alice",
        inbound.protocol,
        1_700_000_001,
    )
    .unwrap();
    let received = decode_direct_message(&alice.keys, &reply, 1_699_999_999)
        .unwrap()
        .unwrap();
    assert_eq!(received.sender, bob.keys.public_key());
    assert_eq!(received.content, "hello alice");
}

#[test]
fn nip04_sender_gets_a_nip04_reply() {
    let alice = NostrKeys::from_private_key(ALICE_SECRET).unwrap();
    let bob = NostrKeys::from_private_key(BOB_SECRET).unwrap();
    let incoming =
        build_direct_message(&alice, &bob.public_key(), "legacy", DmProtocol::Nip04, 50).unwrap();
    let decoded = decode_direct_message(&bob, &incoming, 49).unwrap().unwrap();
    let reply =
        build_direct_message(&bob, &decoded.sender, "legacy reply", decoded.protocol, 51).unwrap();
    let decoded_reply = decode_direct_message(&alice, &reply, 49).unwrap().unwrap();
    assert_eq!(decoded_reply.content, "legacy reply");
    assert_eq!(decoded_reply.protocol, DmProtocol::Nip04);
}

#[test]
fn control_frames_never_decode_as_events() {
    for frame in [
        r#"["EOSE","zeroclaw-dms"]"#,
        r#"["NOTICE","hello"]"#,
        r#"["OK","id",true,""]"#,
        r#"["CLOSED","zeroclaw-dms","bye"]"#,
        r#"["AUTH","challenge"]"#,
    ] {
        assert!(!matches!(
            decode_relay_message(frame).unwrap(),
            RelayMessage::Event { .. }
        ));
    }
}

#[test]
fn unsigned_or_invalid_events_cannot_cross_the_boundary() {
    let bob = NostrKeys::from_private_key(BOB_SECRET).unwrap();
    let forged = NostrEvent {
        id: None,
        pubkey: bob.public_key(),
        created_at: 1,
        kind: 4,
        tags: vec![vec!["p".to_string(), bob.public_key()]],
        content: "not ciphertext".to_string(),
        sig: None,
    };
    assert!(decode_direct_message(&bob, &forged, 0).is_err());
}
