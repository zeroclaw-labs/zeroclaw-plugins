//! One scripted gateway lifetime through the pure state machine: discover,
//! dial, Hello, IDENTIFY, READY, a message, heartbeats, a server-requested
//! reconnect, RESUME, RESUMED, a fatal close, park, and the probe that ends
//! it.

use discord::discord::{
    parse_gateway_bot, Beat, Disconnect, DiscordConfig, FrameAction, Gateway, Handshake, Health,
    ParkReason, Phase, Step, BACKOFF_FLOOR_MS, DEFAULT_INTENTS, PARK_FIRST_PROBE_MS,
};

const BOT: &str = "123456789012345678";
const TOKEN: &str = "MTIzNDU2Nzg5MDEyMzQ1Njc4.mock.mock";

fn dispatch(t: &str, seq: i64, d: &str) -> String {
    format!(r#"{{"op":0,"t":"{t}","s":{seq},"d":{d}}}"#)
}

#[test]
fn a_session_lives_resumes_and_parks() {
    let cfg = DiscordConfig::default();
    let mut gw = Gateway::new(0, BOT, 42);

    // Discovery, then the dial on a later call.
    assert_eq!(gw.next_step(0, &cfg), Step::Discover);
    let discovered = parse_gateway_bot(
        200,
        br#"{"url":"wss://gateway.discord.gg","shards":1,"session_start_limit":{"total":1000,"remaining":999,"reset_after":0,"max_concurrency":1}}"#,
        false,
    );
    gw.on_discovery(10, discovered);
    let Step::Connect { url, resume } = gw.next_step(20, &cfg) else {
        panic!("dial after discovery");
    };
    assert_eq!((url.as_str(), resume), ("wss://gateway.discord.gg", false));
    gw.on_connected(20, &url, resume);
    assert_eq!(gw.next_step(20, &cfg), Step::Pump);

    // Hello owes an IDENTIFY, built with the token read at that moment.
    let FrameAction::Handshake(identify) =
        gw.on_frame(30, r#"{"op":10,"d":{"heartbeat_interval":41250}}"#, &cfg)
    else {
        panic!("Hello asks for a handshake");
    };
    assert_eq!(
        identify,
        Handshake::Identify {
            intents: DEFAULT_INTENTS
        }
    );
    assert!(identify.payload(TOKEN).contains(TOKEN));
    gw.on_handshake_sent(30);

    // READY establishes the session.
    let ready = dispatch(
        "READY",
        1,
        &format!(
            r#"{{"session_id":"s1","resume_gateway_url":"wss://gateway-us-east1-b.discord.gg","user":{{"id":"{BOT}","username":"zc"}}}}"#
        ),
    );
    assert_eq!(
        gw.on_frame(40, &ready, &cfg),
        FrameAction::Identified { resumed: false }
    );
    assert_eq!(gw.health(true), Health::Healthy);

    // A message from a person is emitted; the bot's own is not.
    let FrameAction::Emit(inbound) = gw.on_frame(
        50,
        &dispatch(
            "MESSAGE_CREATE",
            2,
            r#"{"id":"1300000000000000000","type":0,"channel_id":"555","guild_id":"9","author":{"id":"42"},"content":"hello"}"#,
        ),
        &cfg,
    ) else {
        panic!("a person's message is emitted");
    };
    assert_eq!(
        (
            inbound.sender.as_str(),
            inbound.reply_target.as_str(),
            inbound.content.as_str()
        ),
        ("42", "555", "hello")
    );
    let own = dispatch(
        "MESSAGE_CREATE",
        3,
        &format!(
            r#"{{"id":"1300000000000000001","type":0,"channel_id":"555","author":{{"id":"{BOT}"}},"content":"echo"}}"#
        ),
    );
    assert_eq!(gw.on_frame(60, &own, &cfg), FrameAction::None);

    // The heartbeat carries the last sequence and is acknowledged.
    let Beat::Send(beat) = gw.heartbeat_step(41_300, true) else {
        panic!("a heartbeat is due within one interval of Hello");
    };
    assert!(beat.contains(r#""d":3"#));
    gw.on_heartbeat_sent(41_300);
    gw.on_frame(41_350, r#"{"op":11}"#, &cfg);
    assert_eq!(gw.heartbeat_step(50_000, true), Beat::Idle);

    // op 7: reconnect at once to the resume URL and RESUME.
    assert_eq!(
        gw.on_frame(60_000, r#"{"op":7,"d":null}"#, &cfg),
        FrameAction::Reconnect { keep_session: true }
    );
    gw.on_disconnect(60_000, Disconnect::ServerReconnect { keep_session: true });
    assert_eq!(
        gw.next_step(60_000, &cfg),
        Step::Connect {
            url: "wss://gateway-us-east1-b.discord.gg".into(),
            resume: true
        }
    );
    gw.on_connected(60_010, "wss://gateway-us-east1-b.discord.gg", true);
    assert_eq!(
        gw.on_frame(
            60_020,
            r#"{"op":10,"d":{"heartbeat_interval":41250}}"#,
            &cfg
        ),
        FrameAction::Handshake(Handshake::Resume {
            session_id: "s1".into(),
            seq: 3
        })
    );
    gw.on_handshake_sent(60_020);
    assert_eq!(
        gw.on_frame(60_030, &dispatch("RESUMED", 4, "{}"), &cfg),
        FrameAction::Identified { resumed: true }
    );

    // 4014: a privileged intent is off in the portal. Park; probe later.
    gw.on_disconnect(70_000, Disconnect::Closed(Some(4014)));
    assert_eq!(
        gw.phase(),
        &Phase::Parked {
            reason: ParkReason::DisallowedIntents,
            probe_at_ms: 70_000 + PARK_FIRST_PROBE_MS
        }
    );
    assert_eq!(gw.health(true), Health::Unhealthy);
    assert!(!gw.can_resume(), "a fatal close ends the session");
    assert!(ParkReason::DisallowedIntents
        .hint(cfg.intents())
        .contains("Message Content"));
    assert_eq!(
        gw.next_step(70_000 + PARK_FIRST_PROBE_MS - 1, &cfg),
        Step::Wait
    );

    // The probe finds the token valid and dials again with a new IDENTIFY.
    let probe_at = 70_000 + PARK_FIRST_PROBE_MS;
    assert_eq!(gw.next_step(probe_at, &cfg), Step::Discover);
    gw.on_discovery(
        probe_at,
        parse_gateway_bot(200, br#"{"url":"wss://gateway.discord.gg"}"#, false),
    );
    assert!(matches!(
        gw.next_step(probe_at, &cfg),
        Step::Connect { resume: false, .. }
    ));
}

#[test]
fn a_dropped_socket_backs_off_and_resumes() {
    let cfg = DiscordConfig {
        gateway_url: Some("ws://127.0.0.1:8765/gateway".into()),
        ..DiscordConfig::default()
    };
    let mut gw = Gateway::new(0, BOT, 1);
    // A configured gateway is dialed without discovery.
    assert_eq!(
        gw.next_step(0, &cfg),
        Step::Connect {
            url: "ws://127.0.0.1:8765/gateway".into(),
            resume: false
        }
    );
    gw.on_connected(0, "ws://127.0.0.1:8765/gateway", false);
    gw.on_frame(0, r#"{"op":10,"d":{"heartbeat_interval":1000}}"#, &cfg);
    gw.on_handshake_sent(0);
    gw.on_frame(
        0,
        &dispatch(
            "READY",
            1,
            &format!(r#"{{"session_id":"s","user":{{"id":"{BOT}"}}}}"#),
        ),
        &cfg,
    );

    // The TCP connection drops without a close frame.
    gw.on_disconnect(5, Disconnect::Closed(None));
    assert_eq!(gw.next_step(5, &cfg), Step::Wait);
    // No resume URL from READY: resume through the configured gateway.
    assert_eq!(
        gw.next_step(5 + BACKOFF_FLOOR_MS, &cfg),
        Step::Connect {
            url: "ws://127.0.0.1:8765/gateway".into(),
            resume: true
        }
    );
}
