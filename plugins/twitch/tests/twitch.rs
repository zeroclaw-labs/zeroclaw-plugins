use twitch::twitch::{
    encode_privmsg, normalize_oauth_token, normalize_twitch_channel, oauth_pass,
    registration_frame, IrcLineBuffer, IrcMessage, ProtocolAction, ProtocolSession, TwitchConfig,
};

fn config(mention_only: bool) -> TwitchConfig {
    TwitchConfig {
        bot_username: "ZeroClaw_Bot".to_string(),
        channels: vec!["MyChannel".to_string(), "#Other_Channel".to_string()],
        mention_only,
    }
}

fn ready_session(config: &TwitchConfig) -> ProtocolSession {
    let mut session = ProtocolSession::default();
    let actions = session.receive(
        b":tmi.twitch.tv CAP * ACK :twitch.tv/tags twitch.tv/commands\r\n\
          :tmi.twitch.tv 001 zeroclaw_bot :Welcome, GLHF!\r\n",
        config,
    );
    assert_eq!(
        actions,
        vec![
            ProtocolAction::Send(b"JOIN #mychannel\r\nJOIN #other_channel\r\n".to_vec()),
            ProtocolAction::Ready,
        ]
    );
    assert!(session.is_ready());
    session
}

#[test]
fn public_config_and_secret_token_drive_registration_in_required_order() {
    let parsed = TwitchConfig::from_public_json(
        r##"{
            "bot_username": "  TwitchBot  ",
            "channels": ["SomeChannel", "#SECOND"],
            "mention_only": true
        }"##,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(registration_frame(&parsed, " token-value ").unwrap()).unwrap(),
        "CAP REQ :twitch.tv/tags twitch.tv/commands\r\n\
         PASS oauth:token-value\r\nNICK twitchbot\r\n"
    );
    assert_eq!(
        parsed.normalized_channels().unwrap(),
        vec!["#somechannel", "#second"]
    );
    assert!(parsed.mention_only);
}

#[test]
fn native_normalization_and_command_injection_validation_are_preserved() {
    assert_eq!(normalize_oauth_token(" oauth:abc "), "oauth:abc");
    assert_eq!(normalize_oauth_token("abc"), "oauth:abc");
    assert_eq!(
        normalize_twitch_channel("  #MixedCase  ").as_deref(),
        Some("#mixedcase")
    );
    assert!(normalize_twitch_channel("#").is_none());

    let mut invalid = config(false);
    invalid.bot_username = "bot\r\nJOIN".to_string();
    assert!(invalid.validate().is_err());
    assert!(oauth_pass("token\nNICK attacker").is_err());
    assert!(oauth_pass("  ").is_err());
    assert!(oauth_pass("oauth:").is_err());
    assert!(registration_frame(&config(false), "token\nNICK attacker").is_err());
    assert!(TwitchConfig::from_public_json(r#"{"channels":["a"]}"#).is_err());
    assert!(
        TwitchConfig::from_public_json(r#"{"bot_username":"ok","channels":["bad name"]}"#).is_err()
    );
}

#[test]
fn non_channel_privmsg_is_not_misrouted_to_the_bots_own_channel() {
    let config = config(false);
    let mut session = ready_session(&config);
    assert!(session
        .receive(
            b"@id=w1 :alice!alice@host PRIVMSG zeroclaw_bot :psst\r\n",
            &config
        )
        .is_empty());
}

#[test]
fn tcp_chunks_are_reassembled_without_assuming_frame_boundaries() {
    let mut lines = IrcLineBuffer::default();
    assert!(lines.push(b"PING :tmi.twi").unwrap().is_empty());
    assert_eq!(
        lines
            .push(b"tch.tv\r\n:tmi.twitch.tv 001 bot :Welcome\r\n")
            .unwrap(),
        vec!["PING :tmi.twitch.tv", ":tmi.twitch.tv 001 bot :Welcome"]
    );
}

#[test]
fn registration_waits_for_welcome_and_required_capabilities_before_join() {
    let config = config(false);
    let mut session = ProtocolSession::default();
    assert!(session
        .receive(
            b":tmi.twitch.tv 001 zeroclaw_bot :Welcome, GLHF!\r\n",
            &config
        )
        .is_empty());
    assert!(!session.is_ready());
    assert!(session
        .receive(b":tmi.twitch.tv CAP * ACK :twitch.tv/tags\r\n", &config)
        .is_empty());
    assert!(!session.is_ready());
    assert_eq!(
        session.receive(b":tmi.twitch.tv CAP * ACK :twitch.tv/commands\r\n", &config),
        vec![
            ProtocolAction::Send(b"JOIN #mychannel\r\nJOIN #other_channel\r\n".to_vec()),
            ProtocolAction::Ready,
        ]
    );
}

#[test]
fn ping_is_answered_immediately_before_registration_finishes() {
    let mut session = ProtocolSession::default();
    assert_eq!(
        session.receive(b"PING :tmi.twitch.tv\r\n", &config(false)),
        vec![ProtocolAction::Send(b"PONG :tmi.twitch.tv\r\n".to_vec())]
    );
}

#[test]
fn tagged_privmsg_maps_login_channel_timestamp_and_reply_thread() {
    let config = config(false);
    let mut session = ready_session(&config);
    let actions = session.receive(
        b"@badge-info=;display-name=Alice\\sA;id=message-123;reply-parent-msg-id=parent-1;\
          reply-thread-parent-msg-id=root-1;tmi-sent-ts=1720000123456;user-id=42 \
          :Alice!alice@alice.tmi.twitch.tv PRIVMSG #MyChannel :Hello chat\r\n",
        &config,
    );
    let ProtocolAction::Inbound(inbound) = &actions[0] else {
        panic!("expected inbound PRIVMSG");
    };
    assert_eq!(inbound.id, "message-123");
    assert_eq!(inbound.sender, "alice");
    assert_eq!(inbound.reply_target, "#mychannel");
    assert_eq!(inbound.timestamp_ms, Some(1_720_000_123_456));
    assert_eq!(inbound.thread_id.as_deref(), Some("root-1"));
    assert!(inbound.content.ends_with("<Alice A> Hello chat"));
}

#[test]
fn mention_filter_is_case_insensitive_and_requires_login_boundaries() {
    let config = config(true);
    let mut session = ready_session(&config);
    assert!(session
        .receive(
            b"@id=m1 :alice!alice@host PRIVMSG #mychannel :zeroclaw_botanyone?\r\n",
            &config
        )
        .is_empty());
    assert!(matches!(
        session
            .receive(
                b"@id=m2 :alice!alice@host PRIVMSG #mychannel :Hey @ZEROCLAW_BOT, help\r\n",
                &config
            )
            .as_slice(),
        [ProtocolAction::Inbound(_)]
    ));
}

#[test]
fn outbound_privmsg_encodes_reply_tag_and_contains_every_logical_line() {
    let frames = encode_privmsg(
        "MyChannel",
        "first line\r\nsecond line\nthird line",
        Some("parent-message-1"),
    )
    .unwrap();
    assert_eq!(frames.len(), 3);
    let lines = frames
        .into_iter()
        .map(|frame| String::from_utf8(frame).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        lines,
        vec![
            "@reply-parent-msg-id=parent-message-1 PRIVMSG #mychannel :first line\r\n",
            "@reply-parent-msg-id=parent-message-1 PRIVMSG #mychannel :second line\r\n",
            "@reply-parent-msg-id=parent-message-1 PRIVMSG #mychannel :third line\r\n",
        ]
    );
}

#[test]
fn outbound_privmsg_splits_long_unicode_without_exceeding_irc_wire_limit() {
    let frames = encode_privmsg("mychannel", &"🙂".repeat(300), None).unwrap();
    assert!(frames.len() > 1);
    for frame in frames {
        assert!(frame.len() <= 512);
        assert!(String::from_utf8(frame).is_ok());
    }
}

#[test]
fn parser_unescapes_supported_ircv3_tag_values() {
    let message =
        IrcMessage::parse(r"@display-name=A\sB\:C\\D;id=1 :alice!a@host PRIVMSG #room :hello")
            .unwrap();
    assert_eq!(message.tag("display-name"), Some("A B;C\\D"));
    assert_eq!(message.nick(), Some("alice"));
}

#[test]
fn auth_failure_and_capability_rejection_are_terminal() {
    let config = config(false);
    let mut session = ProtocolSession::default();
    assert!(matches!(
        session
            .receive(
                b":tmi.twitch.tv NOTICE * :Login authentication failed\r\n",
                &config
            )
            .as_slice(),
        [ProtocolAction::Rejected(_)]
    ));

    let mut session = ProtocolSession::default();
    assert!(matches!(
        session
            .receive(
                b":tmi.twitch.tv CAP * NAK :twitch.tv/tags twitch.tv/commands\r\n",
                &config
            )
            .as_slice(),
        [ProtocolAction::Rejected(_)]
    ));

    let mut session = ready_session(&config);
    assert!(matches!(
        session
            .receive(b":tmi.twitch.tv RECONNECT\r\n", &config)
            .as_slice(),
        [ProtocolAction::Disconnect(_)]
    ));
}
