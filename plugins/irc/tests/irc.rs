//! Host-run tests over the pure IRC core. The parsing, SASL, splitting, and
//! mention cases carry over from the built-in ZeroClaw IRC channel's suite so
//! the plugin keeps its behavior; the rest cover what the plugin adds.

use std::collections::HashMap;

use irc::irc::{
    base64, encode_lines, format_privmsg, is_mentioned, join_lines, split_message,
    strip_formatting, Action, Backoff, Disconnect, Inbound, IrcConfig, IrcMessage, LineBuffer,
    Outbox, Retry, Secrets, SenderIdentity, Session, IDLE_BEFORE_PING_MS, IRC_STYLE_PREFIX,
    MAX_OUTBOUND_LINES, PACE_BURST, PACE_INTERVAL_MS, PING_TIMEOUT_MS, REGISTRATION_TIMEOUT_MS,
};

#[derive(Default)]
struct FakeSecrets {
    values: HashMap<&'static str, &'static str>,
    unavailable: bool,
}

impl FakeSecrets {
    fn with(pairs: &[(&'static str, &'static str)]) -> Self {
        Self {
            values: pairs.iter().copied().collect(),
            unavailable: false,
        }
    }
}

impl Secrets for FakeSecrets {
    fn get(&mut self, name: &str) -> Result<Option<String>, String> {
        if self.unavailable {
            return Err("unavailable".into());
        }
        Ok(self.values.get(name).map(|value| (*value).to_string()))
    }
}

fn config(json: &str) -> IrcConfig {
    IrcConfig::from_public_json(json).unwrap()
}

fn basic() -> IrcConfig {
    config(r##"{"server":"irc.example.net","nickname":"bot","channels":["#room","#dev"]}"##)
}

fn sends(actions: &[Action]) -> Vec<&str> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send(line) => Some(line.as_str()),
            _ => None,
        })
        .collect()
}

fn inbound(actions: &[Action]) -> Option<&Inbound> {
    actions.iter().find_map(|action| match action {
        Action::Inbound(message) => Some(message),
        _ => None,
    })
}

fn disconnect(actions: &[Action]) -> Option<&Disconnect> {
    actions.iter().find_map(|action| match action {
        Action::Disconnect(disconnect) => Some(disconnect),
        _ => None,
    })
}

/// A session that has completed registration without SASL.
fn registered(config: &IrcConfig) -> Session {
    let mut secrets = FakeSecrets::default();
    let mut session = Session::new(config, 0);
    session.handle_line(config, &mut secrets, ":s CAP * LS :multi-prefix", 0);
    session.handle_line(config, &mut secrets, ":s 001 bot :Welcome", 0);
    assert!(session.is_registered());
    session
}

fn line(session: &mut Session, config: &IrcConfig, text: &str) -> Vec<Action> {
    session.handle_line(config, &mut FakeSecrets::default(), text, 1)
}

// ── configuration ──────────────────────────────────────────────────────────

#[test]
fn minimal_config_defaults_port_and_username() {
    let config = config(r#"{"server":"irc.example.net","nickname":"bot"}"#);
    assert_eq!(config.port, 6697);
    assert_eq!(config.username(), "bot");
    assert_eq!(config.sasl_account(), "bot");
    assert!(config.channels.is_empty());
    assert!(!config.mention_only);
    assert_eq!(config.sender_identity, SenderIdentity::Nick);
}

#[test]
fn explicit_username_and_sasl_account_are_used() {
    let config = config(
        r#"{"server":"irc.example.net","nickname":"bot","username":"ident","sasl_username":"acct"}"#,
    );
    assert_eq!(config.username(), "ident");
    assert_eq!(config.sasl_account(), "acct");
}

#[test]
fn invalid_config_is_rejected() {
    for json in [
        r#"{"server":"irc example","nickname":"bot"}"#,
        r#"{"server":"irc.example.net","nickname":"bot","port":0}"#,
        r##"{"server":"irc.example.net","nickname":"#bot"}"##,
        r#"{"server":"irc.example.net","nickname":"b ot"}"#,
        r#"{"server":"irc.example.net","nickname":"bot","channels":["room"]}"#,
        r##"{"server":"irc.example.net","nickname":"bot","channels":["#a,#b"]}"##,
        r#"{"server":"irc.example.net","nickname":"bot","sasl_mechanism":"external"}"#,
        r#"{"server":"irc.example.net","nickname":"bot","sasl_mechanism":"scram"}"#,
    ] {
        assert!(IrcConfig::from_public_json(json).is_err(), "{json}");
    }
}

// ── parsing (from the built-in suite) ──────────────────────────────────────

#[test]
fn parse_privmsg_with_prefix() {
    let msg = IrcMessage::parse(":nick!user@host PRIVMSG #channel :Hello world").unwrap();
    assert_eq!(msg.prefix.as_deref(), Some("nick!user@host"));
    assert_eq!(msg.command, "PRIVMSG");
    assert_eq!(msg.params, ["#channel", "Hello world"]);
    assert_eq!(msg.nick(), Some("nick"));
}

#[test]
fn parse_ping_numeric_and_cap() {
    let ping = IrcMessage::parse("PING :server.example.com").unwrap();
    assert!(ping.prefix.is_none());
    assert_eq!(ping.params, ["server.example.com"]);
    let numeric = IrcMessage::parse(":server 433 * botname").unwrap();
    assert_eq!(numeric.command, "433");
    assert_eq!(numeric.params, ["*", "botname"]);
    let cap = IrcMessage::parse(":server CAP * ACK :sasl").unwrap();
    assert_eq!(cap.params, ["*", "ACK", "sasl"]);
}

#[test]
fn parse_edge_cases() {
    assert!(IrcMessage::parse("").is_none());
    assert!(IrcMessage::parse("\r\n").is_none());
    assert_eq!(IrcMessage::parse("ping :test\r\n").unwrap().command, "PING");
    assert_eq!(IrcMessage::parse("AUTHENTICATE +").unwrap().params, ["+"]);
    assert_eq!(
        IrcMessage::parse(":server 001 bot :Welcome")
            .unwrap()
            .nick(),
        Some("server")
    );
}

#[test]
fn parse_ircv3_tags() {
    let msg = IrcMessage::parse("@account=alice;msgid=a\\sb :alice!a@h PRIVMSG #room :hi").unwrap();
    assert_eq!(msg.tag("account"), Some("alice"));
    assert_eq!(msg.tag("msgid"), Some("a b"));
    assert_eq!(msg.params, ["#room", "hi"]);
}

#[test]
fn line_buffer_reassembles_fragments_and_bounds_memory() {
    let mut buffer = LineBuffer::default();
    assert!(buffer
        .push(b":a!u@h PRIVMSG #room :hel")
        .unwrap()
        .is_empty());
    assert_eq!(
        buffer.push(b"lo\r\nPING :x\n\r\n").unwrap(),
        [":a!u@h PRIVMSG #room :hello", "PING :x"]
    );
    assert!(buffer.push(&vec![b'a'; 17 * 1024]).is_err());
}

// ── registration ───────────────────────────────────────────────────────────

#[test]
fn registration_discovers_capabilities_then_registers() {
    let config = basic();
    let session = Session::new(&config, 0);
    let lines = session
        .registration(
            &config,
            &mut FakeSecrets::with(&[("server_password", "znc pass")]),
        )
        .unwrap();
    assert_eq!(
        lines,
        [
            "CAP LS 302",
            "PASS :znc pass",
            "NICK bot",
            "USER bot 0 * :ZeroClaw"
        ]
    );
}

#[test]
fn no_sasl_ends_capability_negotiation_and_joins_on_welcome() {
    let config = basic();
    let mut secrets = FakeSecrets::with(&[("nickserv_password", "ns")]);
    let mut session = Session::new(&config, 0);
    let actions = session.handle_line(&config, &mut secrets, ":s CAP * LS :sasl multi-prefix", 0);
    assert_eq!(sends(&actions), ["CAP END"]);
    let actions = session.handle_line(&config, &mut secrets, ":s 001 bot :Welcome", 0);
    assert_eq!(actions[0], Action::Registered);
    assert_eq!(
        sends(&actions),
        ["PRIVMSG NickServ :IDENTIFY ns", "JOIN #room,#dev"]
    );
}

#[test]
fn sasl_plain_authenticates_as_the_configured_account() {
    let config =
        config(r#"{"server":"irc.example.net","nickname":"jilles","sasl_mechanism":"plain"}"#);
    let mut secrets = FakeSecrets::with(&[("sasl_password", "sesame")]);
    let mut session = Session::new(&config, 0);
    // A nick collision before SASL must not change the account.
    session.handle_line(&config, &mut secrets, ":s 433 * jilles :in use", 0);
    assert_eq!(session.nick(), "jilles_");
    let actions = session.handle_line(&config, &mut secrets, ":s CAP * LS * :multi-prefix", 0);
    assert!(actions.is_empty(), "multiline LS waits for the last line");
    let actions = session.handle_line(&config, &mut secrets, ":s CAP * LS :sasl=PLAIN", 0);
    assert_eq!(sends(&actions), ["CAP REQ :sasl"]);
    let actions = session.handle_line(&config, &mut secrets, ":s CAP * ACK :sasl", 0);
    assert_eq!(sends(&actions), ["AUTHENTICATE PLAIN"]);
    let actions = session.handle_line(&config, &mut secrets, "AUTHENTICATE +", 0);
    assert_eq!(sends(&actions), ["AUTHENTICATE AGppbGxlcwBzZXNhbWU="]);
    let actions = session.handle_line(&config, &mut secrets, ":s 903 jilles_ :SASL ok", 0);
    assert_eq!(sends(&actions), ["CAP END"]);
    let actions = session.handle_line(&config, &mut secrets, ":s 001 jilles_ :Welcome", 0);
    assert_eq!(actions[0], Action::Registered);
}

#[test]
fn sasl_external_sends_an_empty_response() {
    let config = config(
        r#"{"server":"irc.example.net","nickname":"bot","sasl_mechanism":"external","tls_profile":"certfp"}"#,
    );
    let mut session = Session::new(&config, 0);
    line(&mut session, &config, ":s CAP * LS :sasl");
    assert_eq!(
        sends(&line(&mut session, &config, ":s CAP * ACK :sasl")),
        ["AUTHENTICATE EXTERNAL"]
    );
    assert_eq!(
        sends(&line(&mut session, &config, "AUTHENTICATE +")),
        ["AUTHENTICATE +"]
    );
}

#[test]
fn sasl_failures_are_fatal_not_silently_skipped() {
    let config =
        config(r#"{"server":"irc.example.net","nickname":"bot","sasl_mechanism":"plain"}"#);
    for lines in [
        vec![":s CAP * LS :multi-prefix"],
        vec![":s CAP * LS :sasl", ":s CAP * NAK :sasl"],
        vec![
            ":s CAP * LS :sasl",
            ":s CAP * ACK :sasl",
            ":s 904 bot :failed",
        ],
        vec![":s 001 bot :Welcome"],
    ] {
        let mut session = Session::new(&config, 0);
        let mut secrets = FakeSecrets::with(&[("sasl_password", "pw")]);
        let actions: Vec<Action> = lines
            .iter()
            .flat_map(|text| session.handle_line(&config, &mut secrets, text, 0))
            .collect();
        assert_eq!(
            disconnect(&actions).map(|d| d.retry),
            Some(Retry::Park),
            "{lines:?}"
        );
        assert!(!session.is_registered());
    }
}

#[test]
fn sasl_plain_without_a_password_is_fatal() {
    let config =
        config(r#"{"server":"irc.example.net","nickname":"bot","sasl_mechanism":"plain"}"#);
    let mut session = Session::new(&config, 0);
    line(&mut session, &config, ":s CAP * LS :sasl");
    line(&mut session, &config, ":s CAP * ACK :sasl");
    let actions = line(&mut session, &config, "AUTHENTICATE +");
    assert_eq!(disconnect(&actions).map(|d| d.retry), Some(Retry::Park));
}

#[test]
fn unavailable_secrets_retry_instead_of_parking() {
    let config = basic();
    let session = Session::new(&config, 0);
    let mut secrets = FakeSecrets {
        unavailable: true,
        ..FakeSecrets::default()
    };
    assert_eq!(
        session
            .registration(&config, &mut secrets)
            .unwrap_err()
            .retry,
        Retry::Backoff
    );
}

#[test]
fn credentials_with_line_breaks_are_refused() {
    let config = basic();
    let session = Session::new(&config, 0);
    let error = session
        .registration(
            &config,
            &mut FakeSecrets::with(&[("server_password", "a\r\nQUIT")]),
        )
        .unwrap_err();
    assert_eq!(error.retry, Retry::Park);
}

#[test]
fn nick_collisions_are_bounded() {
    let config = basic();
    let mut session = Session::new(&config, 0);
    for expected in ["NICK bot_", "NICK bot__", "NICK bot___"] {
        assert_eq!(
            sends(&line(&mut session, &config, ":s 433 * x :in use")),
            [expected]
        );
    }
    let actions = line(&mut session, &config, ":s 433 * x :in use");
    assert_eq!(disconnect(&actions).map(|d| d.retry), Some(Retry::Backoff));
}

#[test]
fn server_rejections_park_the_connection() {
    let config = basic();
    for text in [
        ":s 464 * :Password incorrect",
        ":s 465 * :banned",
        ":s 432 * bot :bad",
    ] {
        let mut session = Session::new(&config, 0);
        let actions = line(&mut session, &config, text);
        assert_eq!(
            disconnect(&actions).map(|d| d.retry),
            Some(Retry::Park),
            "{text}"
        );
    }
    let mut session = Session::new(&config, 0);
    let actions = line(&mut session, &config, "ERROR :Closing link");
    assert_eq!(disconnect(&actions).map(|d| d.retry), Some(Retry::Backoff));
}

#[test]
fn account_identity_requires_the_account_tag_capability() {
    let config =
        config(r#"{"server":"irc.example.net","nickname":"bot","sender_identity":"account"}"#);
    let mut session = Session::new(&config, 0);
    let actions = line(&mut session, &config, ":s CAP * LS :sasl");
    assert_eq!(disconnect(&actions).map(|d| d.retry), Some(Retry::Park));

    let mut session = Session::new(&config, 0);
    assert_eq!(
        sends(&line(
            &mut session,
            &config,
            ":s CAP * LS :account-tag sasl"
        )),
        ["CAP REQ :account-tag"]
    );
    assert_eq!(
        sends(&line(&mut session, &config, ":s CAP * ACK :account-tag")),
        ["CAP END"]
    );
    line(&mut session, &config, ":s 001 bot :Welcome");
    assert!(session.is_registered());
    let tagged = line(
        &mut session,
        &config,
        "@account=Alice :al!u@h PRIVMSG #room :hi",
    );
    assert_eq!(inbound(&tagged).unwrap().sender, "alice");
    assert!(inbound(&line(&mut session, &config, ":eve!u@h PRIVMSG #room :hi")).is_none());
    assert!(inbound(&line(
        &mut session,
        &config,
        "@account=* :eve!u@h PRIVMSG #room :hi"
    ))
    .is_none());
}

// ── liveness ───────────────────────────────────────────────────────────────

#[test]
fn ping_is_answered_with_its_token() {
    let config = basic();
    let mut session = registered(&config);
    assert_eq!(
        sends(&line(&mut session, &config, "PING :token")),
        ["PONG :token"]
    );
}

#[test]
fn idle_link_is_probed_then_dropped() {
    let config = basic();
    let mut session = registered(&config);
    assert_eq!(session.tick(IDLE_BEFORE_PING_MS), None);
    let probe = IDLE_BEFORE_PING_MS + 1;
    assert_eq!(
        session.tick(probe),
        Some(Action::Send(format!("PING :zeroclaw-{probe}")))
    );
    assert_eq!(session.tick(probe + 1), None, "one probe at a time");
    let Some(Action::Disconnect(lost)) = session.tick(probe + PING_TIMEOUT_MS + 1) else {
        panic!("expected a ping timeout");
    };
    assert_eq!(lost.retry, Retry::Backoff);
}

#[test]
fn any_traffic_answers_the_probe() {
    let config = basic();
    let mut session = registered(&config);
    let probe = IDLE_BEFORE_PING_MS + 1;
    assert!(session.tick(probe).is_some());
    session.handle_line(
        &config,
        &mut FakeSecrets::default(),
        ":s PONG s :zeroclaw",
        probe + 5,
    );
    assert_eq!(session.tick(probe + PING_TIMEOUT_MS + 1), None);
}

#[test]
fn registration_must_finish_in_time() {
    let config = basic();
    let mut session = Session::new(&config, 0);
    assert_eq!(session.tick(REGISTRATION_TIMEOUT_MS), None);
    assert!(matches!(
        session.tick(REGISTRATION_TIMEOUT_MS + 1),
        Some(Action::Disconnect(_))
    ));
}

// ── inbound ────────────────────────────────────────────────────────────────

#[test]
fn channel_and_direct_messages_map_to_reply_targets() {
    let config = basic();
    let mut session = registered(&config);
    let channel = line(&mut session, &config, ":Alice!u@h PRIVMSG #room :hello");
    assert_eq!(
        inbound(&channel),
        Some(&Inbound {
            sender: "alice".into(),
            reply_target: "#room".into(),
            content: format!("{IRC_STYLE_PREFIX}<Alice> hello"),
        })
    );
    let direct = line(&mut session, &config, ":Alice!u@h PRIVMSG bot :hi there");
    let direct = inbound(&direct).unwrap();
    assert_eq!(direct.reply_target, "Alice");
    assert_eq!(direct.content, format!("{IRC_STYLE_PREFIX}hi there"));
}

#[test]
fn messages_before_registration_are_ignored() {
    let config = basic();
    let mut session = Session::new(&config, 0);
    assert!(inbound(&line(&mut session, &config, ":a!u@h PRIVMSG #room :hi")).is_none());
}

#[test]
fn services_own_echoes_and_ctcp_queries_are_dropped() {
    let config = basic();
    let mut session = registered(&config);
    for text in [
        ":NickServ!s@services PRIVMSG bot :You are now identified",
        ":ChanServ!s@services PRIVMSG bot :hi",
        ":bot!u@h PRIVMSG #room :my own echo",
        ":a!u@h PRIVMSG bot :\u{1}VERSION\u{1}",
        ":a!u@h PRIVMSG #room :\u{2}\u{3}04\u{f}",
    ] {
        assert!(
            inbound(&line(&mut session, &config, text)).is_none(),
            "{text}"
        );
    }
}

#[test]
fn ctcp_action_and_formatting_become_plain_text() {
    let config = basic();
    let mut session = registered(&config);
    let action = line(
        &mut session,
        &config,
        ":a!u@h PRIVMSG #room :\u{1}ACTION waves\u{1}",
    );
    assert!(inbound(&action).unwrap().content.ends_with("<a> * a waves"));
    assert_eq!(
        strip_formatting("\u{2}bold\u{2} \u{3}04,12red\u{3} \u{4}ff00ffhex\u{f} 3,4"),
        "bold red hex 3,4"
    );
}

#[test]
fn nick_changes_follow_the_session() {
    let config = config(
        r##"{"server":"irc.example.net","nickname":"bot","mention_only":true,"channels":["#room"]}"##,
    );
    let mut session = registered(&config);
    line(&mut session, &config, ":bot!u@h NICK :newbot");
    assert_eq!(session.nick(), "newbot");
    assert!(inbound(&line(
        &mut session,
        &config,
        ":a!u@h PRIVMSG #room :newbot: hi"
    ))
    .is_some());
}

#[test]
fn mention_only_gates_channels_but_not_direct_messages() {
    let config = config(r#"{"server":"irc.example.net","nickname":"bot","mention_only":true}"#);
    let mut session = registered(&config);
    assert!(inbound(&line(
        &mut session,
        &config,
        ":a!u@h PRIVMSG #room :robotics"
    ))
    .is_none());
    assert!(inbound(&line(
        &mut session,
        &config,
        ":a!u@h PRIVMSG #room :bot: hi"
    ))
    .is_some());
    assert!(inbound(&line(
        &mut session,
        &config,
        ":a!u@h PRIVMSG bot :no mention"
    ))
    .is_some());
}

#[test]
fn mention_requires_a_word_boundary() {
    assert!(is_mentioned("bot", "Hello, bot!"));
    assert!(is_mentioned("bot", "HI BOT!"));
    assert!(is_mentioned("bot", "@bot status?"));
    assert!(is_mentioned("bot", "hey bot, status?"));
    assert!(!is_mentioned("bot", "robotics team update"));
    assert!(!is_mentioned("bot", "this is bothering me"));
    assert!(!is_mentioned("bot", "bot_away status update"));
    assert!(!is_mentioned("", "anything"));
}

// ── outbound ───────────────────────────────────────────────────────────────

#[test]
fn split_matches_the_built_in_channel() {
    assert_eq!(split_message("hello", 400), ["hello"]);
    assert_eq!(
        split_message(&"a".repeat(800), 400),
        ["a".repeat(400), "a".repeat(400)]
    );
    assert_eq!(split_message(&"a".repeat(400), 400).len(), 1);
    assert_eq!(split_message("ééé", 3), ["é", "é", "é"]);
    assert_eq!(
        split_message("hello\r\nworld\n\n\nend\n", 400),
        ["hello", "world", "end"]
    );
    assert!(split_message("", 400).is_empty());
    assert!(split_message("\n\n\n", 400).is_empty());
}

#[test]
fn split_prefers_word_boundaries() {
    assert_eq!(
        split_message("alpha beta gamma delta", 12),
        ["alpha beta", "gamma delta"]
    );
}

#[test]
fn privmsg_lines_fit_the_relayed_line_limit() {
    let nick = "zeroclaw";
    let lines = format_privmsg(nick, "#room", &"word ".repeat(300)).unwrap();
    assert!(lines.len() > 1);
    for line in &lines {
        let relayed = 1 + nick.len() + 1 + 10 + 1 + 64 + 1 + line.len() + 2;
        assert!(relayed <= 512, "{relayed}");
    }
}

#[test]
fn privmsg_refuses_injection_and_strips_ctcp() {
    assert!(format_privmsg("bot", "#room\r\nQUIT", "x").is_err());
    assert!(format_privmsg("bot", "#a,#b", "x").is_err());
    assert!(format_privmsg("bot", ":evil", "x").is_err());
    assert!(format_privmsg("bot", "#room", " \n \n").is_err());
    assert_eq!(
        format_privmsg("bot", "#room", "\u{1}ACTION hacks\u{1}\nline two").unwrap(),
        ["PRIVMSG #room :ACTION hacks", "PRIVMSG #room :line two"]
    );
    assert!(encode_lines(&["PRIVMSG #a :x\r\nQUIT"]).is_err());
    assert_eq!(encode_lines(&["A", "B"]).unwrap(), b"A\r\nB\r\n");
}

#[test]
fn join_lines_batch_channels_within_the_line_limit() {
    assert_eq!(join_lines(&["#a".into(), "#b".into()]), ["JOIN #a,#b"]);
    let many: Vec<String> = (0..100).map(|n| format!("#channel-{n:03}")).collect();
    let lines = join_lines(&many);
    assert!(lines.len() > 1);
    assert!(lines.iter().all(|line| line.len() + 2 <= 512));
    let joined: usize = lines.iter().map(|line| line.matches('#').count()).sum();
    assert_eq!(joined, 100);
}

#[test]
fn outbox_paces_after_a_burst() {
    let mut outbox = Outbox::default();
    outbox
        .enqueue((0..8).map(|n| n.to_string()).collect())
        .unwrap();
    let burst = usize::try_from(PACE_BURST).unwrap();
    assert_eq!(outbox.take_due(1_000).len(), burst);
    assert!(outbox.take_due(1_000).is_empty());
    assert_eq!(outbox.take_due(1_000 + PACE_INTERVAL_MS).len(), 1);
    assert_eq!(outbox.len(), 8 - burst - 1);
    outbox.requeue(vec!["again".into()]);
    assert_eq!(outbox.take_due(1_000 + 100 * PACE_INTERVAL_MS)[0], "again");
}

#[test]
fn outbox_refuses_a_reply_that_does_not_fit() {
    let mut outbox = Outbox::default();
    outbox
        .enqueue(vec!["x".into(); MAX_OUTBOUND_LINES - 1])
        .unwrap();
    assert!(outbox.enqueue(vec!["a".into(), "b".into()]).is_err());
    assert_eq!(outbox.len(), MAX_OUTBOUND_LINES - 1);
    assert_eq!(outbox.clear(), MAX_OUTBOUND_LINES - 1);
}

// ── reconnect policy ───────────────────────────────────────────────────────

#[test]
fn backoff_grows_caps_and_resets_on_registration() {
    let mut backoff = Backoff::default();
    assert!(backoff.ready(0));
    assert_eq!(backoff.failed(0, Retry::Backoff, 0), 2_000);
    assert!(!backoff.ready(1_999));
    assert!(backoff.ready(2_000));
    assert_eq!(backoff.failed(0, Retry::Backoff, 0), 4_000);
    for _ in 0..20 {
        backoff.failed(0, Retry::Backoff, 0);
    }
    assert_eq!(backoff.failed(0, Retry::Backoff, 0), 300_000);
    backoff.succeeded();
    assert_eq!(backoff.failed(0, Retry::Backoff, 0), 2_000);
    let jittered = backoff.failed(0, Retry::Backoff, u64::MAX);
    assert!((4_000..=5_000).contains(&jittered));
}

#[test]
fn refusals_and_rejections_wait_longer() {
    let mut backoff = Backoff::default();
    assert_eq!(backoff.failed(0, Retry::Refused, 0), 60_000);
    assert_eq!(backoff.failed(0, Retry::Park, 0), 900_000);
}

#[test]
fn sasl_plain_encoding() {
    assert_eq!(base64(b"\0jilles\0sesame"), "AGppbGxlcwBzZXNhbWU=");
    assert_eq!(base64(b"\0nick\0"), "AG5pY2sA");
}
