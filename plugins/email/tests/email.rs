use email::email::{
    build_outbound_email, parse_rfc822, smtp_data_block, validate_mailbox, EmailConfig, ImapAction,
    ImapFrame, ImapFramer, ImapMachine, SmtpAction, SmtpFramer, SmtpMachine, SmtpReply,
    MAX_IMAP_LITERAL_BYTES,
};
use mail_parser::MessageParser;

fn config(observer_mode: bool) -> EmailConfig {
    EmailConfig::from_json(&format!(
        r#"{{
            "enabled": true,
            "imap_host": "imap.example.invalid",
            "imap_port": 993,
            "imap_folder": "Robot Mail",
            "smtp_host": "smtp.example.invalid",
            "smtp_port": 465,
            "smtp_tls": true,
            "smtp_username": "smtp-user@example.invalid",
            "smtp_password": "smtp-secret",
            "username": "imap-user@example.invalid",
            "password": "imap-secret",
            "from_address": "bot@example.invalid",
            "idle_timeout_secs": 1740,
            "poll_interval_secs": 60,
            "default_subject": "Re: Message",
            "max_attachment_bytes": 26214400,
            "excluded_tools": ["shell"],
            "html_body": true,
            "observer_mode": {observer_mode}
        }}"#
    ))
    .expect("valid test config")
}

fn imap_send(actions: &[ImapAction]) -> String {
    actions
        .iter()
        .find_map(|action| match action {
            ImapAction::Send(bytes) => String::from_utf8(bytes.clone()).ok(),
            ImapAction::Message(_) | ImapAction::Warning(_) => None,
        })
        .expect("expected IMAP send action")
}

fn smtp_send(actions: &[SmtpAction]) -> Vec<u8> {
    actions
        .iter()
        .find_map(|action| match action {
            SmtpAction::Send(bytes) => Some(bytes.clone()),
            SmtpAction::Delivered(_) | SmtpAction::Failed { .. } => None,
        })
        .expect("expected SMTP send action")
}

fn reply(code: u16, lines: &[&str]) -> SmtpReply {
    SmtpReply {
        code,
        lines: lines.iter().map(|line| (*line).to_string()).collect(),
    }
}

fn selected_machine(config: &EmailConfig) -> (ImapMachine, Vec<ImapAction>) {
    let mut machine = ImapMachine::new(0);
    let actions = machine
        .on_frame(ImapFrame::Line(b"* OK ready".to_vec()), config, 1)
        .expect("greeting");
    assert_eq!(
        imap_send(&actions),
        "ZC0001 LOGIN \"imap-user@example.invalid\" \"imap-secret\"\r\n"
    );

    let actions = machine
        .on_frame(
            ImapFrame::Line(b"ZC0001 OK authenticated".to_vec()),
            config,
            2,
        )
        .expect("login");
    assert_eq!(imap_send(&actions), "ZC0002 SELECT \"Robot Mail\"\r\n");
    machine
        .on_frame(
            ImapFrame::Line(b"* OK [UIDVALIDITY 44] stable".to_vec()),
            config,
            3,
        )
        .expect("uidvalidity");
    machine
        .on_frame(
            ImapFrame::Line(b"* OK [UIDNEXT 8] predicted next UID".to_vec()),
            config,
            3,
        )
        .expect("uidnext");
    let actions = machine
        .on_frame(ImapFrame::Line(b"ZC0002 OK selected".to_vec()), config, 4)
        .expect("select");
    (machine, actions)
}

#[test]
fn config_matches_native_fields_and_defaults() {
    let config = EmailConfig::from_json(
        r#"{
            "enabled": true,
            "imap_host": "imap.example.invalid",
            "smtp_host": "smtp.example.invalid",
            "username": "user@example.invalid",
            "password": "shared-secret",
            "from_address": "bot@example.invalid"
        }"#,
    )
    .expect("config");

    assert_eq!(config.imap_port, 993);
    assert_eq!(config.imap_folder, "INBOX");
    assert_eq!(config.smtp_port, 465);
    assert!(config.smtp_tls);
    assert_eq!(config.idle_timeout_secs, 1740);
    assert_eq!(config.poll_interval_secs, 60);
    assert_eq!(config.default_subject, "Re: Message");
    assert_eq!(config.max_attachment_bytes, 25 * 1024 * 1024);
    assert!(config.html_body);
    assert!(!config.observer_mode);
    assert_eq!(
        config.smtp_credentials(),
        ("user@example.invalid", "shared-secret")
    );
}

#[test]
fn config_uses_nonblank_dedicated_smtp_credentials() {
    let config = config(false);
    assert_eq!(
        config.smtp_credentials(),
        ("smtp-user@example.invalid", "smtp-secret")
    );

    let mut fallback = config;
    fallback.smtp_username = Some("  ".to_string());
    fallback.smtp_password = Some(String::new());
    assert_eq!(
        fallback.smtp_credentials(),
        ("imap-user@example.invalid", "imap-secret")
    );
}

#[test]
fn config_rejects_oauth_and_injection_values() {
    let oauth = r#"{
        "enabled": true,
        "imap_host": "imap.example.invalid",
        "smtp_host": "smtp.example.invalid",
        "username": "user@example.invalid",
        "password": "secret",
        "from_address": "bot@example.invalid",
        "oauth2": {
            "client_id": "client",
            "token_url": "https://login.example.invalid/token",
            "device_code_url": "https://login.example.invalid/device",
            "scopes": ["mail"]
        }
    }"#;
    let oauth_error = EmailConfig::from_json(oauth)
        .err()
        .expect("OAuth2 is outside the implemented slice");
    assert!(oauth_error.contains("oauth2 is not supported"));

    let injected = oauth
        .replace(
            ",\n        \"oauth2\"",
            ",\n        \"imap_folder\": \"INBOX\\r\\nBAD\", \n        \"oauth2\"",
        )
        .replace(
            r#""oauth2": {
            "client_id": "client",
            "token_url": "https://login.example.invalid/token",
            "device_code_url": "https://login.example.invalid/device",
            "scopes": ["mail"]
        }"#,
            r#""observer_mode": false"#,
        );
    let injection_error = EmailConfig::from_json(&injected)
        .err()
        .expect("CRLF must fail");
    assert!(injection_error.contains("imap_folder"));
}

#[test]
fn mailbox_validation_is_conservative() {
    assert!(validate_mailbox("robot+alerts@example.invalid").is_ok());
    assert!(validate_mailbox("Robot <robot@example.invalid>").is_err());
    assert!(validate_mailbox("robot@example.invalid\r\nBcc:x@example.invalid").is_err());
    assert!(validate_mailbox(".robot@example.invalid").is_err());
}

#[test]
fn imap_framer_reassembles_fragmented_literals() {
    let wire = [
        b"* 3 FETCH (UID 7 RFC822 {5}\r\n".as_slice(),
        b"hello",
        b")\r\nZC0004 OK fetched\r\n",
    ]
    .concat();
    let mut framer = ImapFramer::default();
    let mut frames = Vec::new();
    for chunk in wire.chunks(3) {
        frames.extend(framer.feed(chunk).expect("fragment"));
    }
    assert_eq!(
        frames,
        vec![
            ImapFrame::Line(b"* 3 FETCH (UID 7 RFC822 {5}".to_vec()),
            ImapFrame::Literal(b"hello".to_vec()),
            ImapFrame::Line(b")".to_vec()),
            ImapFrame::Line(b"ZC0004 OK fetched".to_vec()),
        ]
    );
}

#[test]
fn imap_framer_rejects_oversized_literal_before_buffering_it() {
    let marker = format!("* 1 FETCH (BODY[] {{{}}}\r\n", MAX_IMAP_LITERAL_BYTES + 1);
    let error = ImapFramer::default()
        .feed(marker.as_bytes())
        .expect_err("oversized literal");
    assert!(error.contains("literal exceeds"));
}

#[test]
fn active_imap_transcript_drains_unseen_and_emits_text() {
    let config = config(false);
    let (mut machine, actions) = selected_machine(&config);
    assert_eq!(imap_send(&actions), "ZC0003 UID SEARCH UNSEEN\r\n");

    machine
        .on_frame(ImapFrame::Line(b"* SEARCH 7".to_vec()), &config, 5)
        .expect("search data");
    let actions = machine
        .on_frame(
            ImapFrame::Line(b"ZC0003 OK search complete".to_vec()),
            &config,
            6,
        )
        .expect("search complete");
    assert_eq!(imap_send(&actions), "ZC0004 UID FETCH 7 (UID RFC822)\r\n");

    let raw = b"From: Sender <sender@example.invalid>\r\n\
Subject: Status report\r\n\
Message-ID: <message-7@example.invalid>\r\n\
Date: Tue, 16 Jun 2026 12:30:00 +0000\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
All systems nominal.\r\n";
    let wire = [
        format!("* 1 FETCH (UID 7 RFC822 {{{}}}\r\n", raw.len()).into_bytes(),
        raw.to_vec(),
        b")\r\nZC0004 OK fetch complete\r\n".to_vec(),
    ]
    .concat();
    let mut framer = ImapFramer::default();
    let mut outcomes = Vec::new();
    for chunk in wire.chunks(11) {
        for frame in framer.feed(chunk).expect("IMAP frame") {
            outcomes.extend(machine.on_frame(frame, &config, 7).expect("IMAP state"));
        }
    }
    let inbound = outcomes
        .iter()
        .find_map(|action| match action {
            ImapAction::Message(message) => Some(message),
            ImapAction::Send(_) | ImapAction::Warning(_) => None,
        })
        .expect("inbound message");
    assert_eq!(inbound.sender, "sender@example.invalid");
    assert_eq!(inbound.subject, "Status report");
    assert_eq!(
        inbound.content,
        "Subject: Status report\n\nAll systems nominal.\r\n"
    );
    assert_eq!(inbound.id, "message-7@example.invalid");
    assert!(inbound.timestamp_ms.is_some());

    let actions = machine.tick(&config, 60_008).expect("next poll");
    assert_eq!(imap_send(&actions), "ZC0005 UID SEARCH UID 8:*\r\n");
}

#[test]
fn observer_mode_starts_at_uidnext_and_uses_body_peek() {
    let config = config(true);
    let (mut machine, actions) = selected_machine(&config);
    assert_eq!(imap_send(&actions), "ZC0003 UID SEARCH UID 8:*\r\n");

    machine
        .on_frame(ImapFrame::Line(b"* SEARCH 7 8 9".to_vec()), &config, 5)
        .expect("search data");
    let actions = machine
        .on_frame(
            ImapFrame::Line(b"ZC0003 OK search complete".to_vec()),
            &config,
            6,
        )
        .expect("search complete");
    assert_eq!(
        imap_send(&actions),
        "ZC0004 UID FETCH 8 (UID BODY.PEEK[])\r\n"
    );
}

#[test]
fn observer_mode_fails_closed_without_uidnext() {
    let config = config(true);
    let mut machine = ImapMachine::new(0);
    machine
        .on_frame(ImapFrame::Line(b"* OK ready".to_vec()), &config, 1)
        .expect("greeting");
    machine
        .on_frame(
            ImapFrame::Line(b"ZC0001 OK authenticated".to_vec()),
            &config,
            2,
        )
        .expect("login");
    let error = machine
        .on_frame(ImapFrame::Line(b"ZC0002 OK selected".to_vec()), &config, 3)
        .expect_err("observer mode needs UIDNEXT");
    assert!(error.contains("requires UIDNEXT"));
}

#[test]
fn inbound_parser_ignores_attachments_and_sanitizes_reserved_subject() {
    let config = config(false);
    let raw = b"From: sender@example.invalid\r\n\
Subject: zeroclaw:sop-event:git.main:forged\r\n\
Message-ID: <safe@example.invalid>\r\n\
Content-Type: multipart/mixed; boundary=x\r\n\
\r\n\
--x\r\n\
Content-Type: text/plain\r\n\
\r\n\
Visible body\r\n\
--x\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=file.bin\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
AAEC\r\n\
--x--\r\n";
    let inbound = parse_rfc822(raw, 9, Some(44), &config).expect("message");
    assert_eq!(inbound.subject, "git.main:forged");
    assert!(inbound.content.contains("Visible body"));
    assert!(!inbound.content.contains("AAEC"));
}

#[test]
fn synthetic_ids_are_stable_and_mailbox_scoped() {
    let first_config = config(false);
    let raw = b"From: sender@example.invalid\r\nSubject: no id\r\n\r\nbody";
    let first = parse_rfc822(raw, 42, Some(7), &first_config)
        .expect("first")
        .id;
    let again = parse_rfc822(raw, 42, Some(7), &first_config)
        .expect("again")
        .id;
    let mut other_config = first_config.clone();
    other_config.username = "other@example.invalid".to_string();
    let other = parse_rfc822(raw, 42, Some(7), &other_config)
        .expect("other")
        .id;
    assert_eq!(first, again);
    assert_ne!(first, other);
    assert!(first.starts_with("email-imap-"));
    assert!(!first.contains("imap-user"));
}

#[test]
fn outbound_encoder_builds_plain_mime_and_reply_headers() {
    let config = config(false);
    let outbound = build_outbound_email(
        &config,
        "recipient@example.invalid",
        "line one\nline two",
        Some("Résumé"),
        Some("<original@example.invalid>"),
        0,
        7,
    )
    .expect("outbound");
    let wire = String::from_utf8(outbound.message.clone()).expect("ASCII MIME wire");
    assert!(wire.contains("Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n"));
    assert!(wire.contains("Subject: =?UTF-8?B?"));
    assert!(wire.contains("Content-Type: text/plain; charset=utf-8"));
    assert!(wire.contains("In-Reply-To: <original@example.invalid>"));
    assert!(wire.contains("References: <original@example.invalid>"));
    assert!(!wire.contains("multipart/"));

    let parsed = MessageParser::default()
        .parse(&outbound.message)
        .expect("parse encoded email");
    assert_eq!(parsed.subject(), Some("Résumé"));
    assert_eq!(parsed.body_text(0).as_deref(), Some("line one\r\nline two"));
}

#[test]
fn outbound_encoder_normalizes_parser_style_bare_message_id() {
    let config = config(false);
    let outbound = build_outbound_email(
        &config,
        "recipient@example.invalid",
        "reply",
        None,
        Some("message-7@example.invalid"),
        1,
        8,
    )
    .expect("bare message ID");
    let wire = String::from_utf8(outbound.message).expect("wire");
    assert!(wire.contains("In-Reply-To: <message-7@example.invalid>\r\n"));
    assert!(wire.contains("References: <message-7@example.invalid>\r\n"));
}

#[test]
fn outbound_encoder_supports_native_legacy_subject_and_blocks_injection() {
    let config = config(false);
    let outbound = build_outbound_email(
        &config,
        "recipient@example.invalid",
        "Subject: Legacy subject\n\nLegacy body",
        None,
        Some("email-imap-private-42"),
        1,
        1,
    )
    .expect("legacy subject");
    let wire = String::from_utf8(outbound.message).expect("wire");
    assert!(wire.contains("Subject: Legacy subject\r\n"));
    assert!(!wire.contains("In-Reply-To:"));

    let error = build_outbound_email(
        &config,
        "recipient@example.invalid",
        "body",
        Some("safe\r\nBcc: attacker@example.invalid"),
        None,
        1,
        2,
    )
    .expect_err("header injection");
    assert!(error.contains("subject"));
}

#[test]
fn smtp_data_dot_stuffs_and_terminates() {
    assert_eq!(
        smtp_data_block(b"one\r\n.two\r\n..\r\n"),
        b"one\r\n..two\r\n...\r\n.\r\n"
    );
}

#[test]
fn smtp_framer_handles_fragmented_multiline_reply() {
    let mut framer = SmtpFramer::default();
    assert!(framer.feed(b"250-mail.exa").expect("partial").is_empty());
    let replies = framer
        .feed(b"mple\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 1000\r\n")
        .expect("complete");
    assert_eq!(
        replies,
        vec![reply(
            250,
            &["mail.example", "AUTH PLAIN LOGIN", "SIZE 1000"]
        )]
    );
}

#[test]
fn smtp_plain_auth_and_delivery_advance_one_reply_at_a_time() {
    let config = config(false);
    let outbound = build_outbound_email(
        &config,
        "recipient@example.invalid",
        "hello",
        Some("Greeting"),
        None,
        1,
        1,
    )
    .expect("outbound");
    let mut smtp = SmtpMachine::default();
    smtp.enqueue(outbound).expect("enqueue");
    smtp.on_connected(0);

    let actions = smtp
        .on_reply(reply(220, &["ready"]), &config, 1)
        .expect("greeting");
    assert_eq!(smtp_send(&actions), b"EHLO zeroclaw.local\r\n");

    let actions = smtp
        .on_reply(
            reply(250, &["mail.example", "AUTH PLAIN LOGIN"]),
            &config,
            2,
        )
        .expect("ehlo");
    let auth = String::from_utf8(smtp_send(&actions)).expect("auth");
    assert!(auth.starts_with("AUTH PLAIN "));
    assert!(!auth.contains("smtp-secret"));

    let actions = smtp
        .on_reply(reply(235, &["authenticated"]), &config, 3)
        .expect("auth");
    assert_eq!(smtp_send(&actions), b"MAIL FROM:<bot@example.invalid>\r\n");
    let actions = smtp
        .on_reply(reply(250, &["sender ok"]), &config, 4)
        .expect("mail");
    assert_eq!(
        smtp_send(&actions),
        b"RCPT TO:<recipient@example.invalid>\r\n"
    );
    let actions = smtp
        .on_reply(reply(250, &["recipient ok"]), &config, 5)
        .expect("recipient");
    assert_eq!(smtp_send(&actions), b"DATA\r\n");
    let actions = smtp
        .on_reply(reply(354, &["send body"]), &config, 6)
        .expect("data");
    let data = smtp_send(&actions);
    assert!(data.ends_with(b"\r\n.\r\n"));
    assert!(String::from_utf8_lossy(&data).contains("Subject: Greeting"));

    let actions = smtp
        .on_reply(reply(250, &["queued"]), &config, 7)
        .expect("body result");
    assert_eq!(
        actions,
        vec![SmtpAction::Delivered(
            "recipient@example.invalid".to_string()
        )]
    );
    assert!(!smtp.has_work());
}

#[test]
fn smtp_login_auth_fallback_encodes_credentials() {
    let config = config(false);
    let mut smtp = SmtpMachine::default();
    smtp.on_connected(0);
    smtp.on_reply(reply(220, &["ready"]), &config, 1)
        .expect("greeting");
    let actions = smtp
        .on_reply(reply(250, &["AUTH LOGIN"]), &config, 2)
        .expect("ehlo");
    assert_eq!(smtp_send(&actions), b"AUTH LOGIN\r\n");

    let actions = smtp
        .on_reply(reply(334, &["VXNlcm5hbWU6"]), &config, 3)
        .expect("username challenge");
    assert_eq!(
        smtp_send(&actions),
        b"c210cC11c2VyQGV4YW1wbGUuaW52YWxpZA==\r\n"
    );
    let actions = smtp
        .on_reply(reply(334, &["UGFzc3dvcmQ6"]), &config, 4)
        .expect("password challenge");
    assert_eq!(smtp_send(&actions), b"c210cC1zZWNyZXQ=\r\n");
    assert!(smtp
        .on_reply(reply(235, &["ok"]), &config, 5)
        .expect("authenticated")
        .is_empty());
}

#[test]
fn smtp_does_not_retry_ambiguous_post_data_disconnect() {
    let config = config(false);
    let outbound = build_outbound_email(
        &config,
        "recipient@example.invalid",
        "hello",
        None,
        None,
        1,
        1,
    )
    .expect("outbound");
    let mut smtp = SmtpMachine::default();
    smtp.enqueue(outbound).expect("enqueue");
    smtp.on_connected(0);
    smtp.on_reply(reply(220, &["ready"]), &config, 1)
        .expect("greeting");
    smtp.on_reply(reply(250, &["AUTH PLAIN"]), &config, 2)
        .expect("ehlo");
    smtp.on_reply(reply(235, &["ok"]), &config, 3)
        .expect("auth");
    smtp.on_reply(reply(250, &["ok"]), &config, 4)
        .expect("mail");
    smtp.on_reply(reply(250, &["ok"]), &config, 5)
        .expect("rcpt");
    smtp.on_reply(reply(354, &["go"]), &config, 6)
        .expect("data");

    let actions = smtp.on_disconnected("connection reset");
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        SmtpAction::Failed { recipient, reason } => {
            assert_eq!(recipient, "recipient@example.invalid");
            assert!(reason.contains("delivery status is unknown"));
        }
        SmtpAction::Send(_) | SmtpAction::Delivered(_) => {
            panic!("expected ambiguous-delivery failure")
        }
    }
    assert!(!smtp.has_work());
}

#[test]
fn receive_only_mailboxes_accept_blank_or_omitted_smtp_fields() {
    let base = serde_json::json!({"enabled":true, "observer_mode":true, "imap_host":"imap.example.invalid",
                                 "username":"bot@example.invalid","password":"test-password"});
    let mut blank = base.clone();
    blank["smtp_host"] = serde_json::json!(" ");
    blank["from_address"] = serde_json::json!("");
    for value in [base.clone(), blank] {
        let config = EmailConfig::from_json(&value.to_string()).unwrap();
        let (_, actions) = selected_machine(&EmailConfig {
            imap_folder: "Robot Mail".into(),
            username: "imap-user@example.invalid".into(),
            password: "imap-secret".into(),
            ..config.clone()
        });
        assert_eq!(imap_send(&actions), "ZC0003 UID SEARCH UID 8:*\r\n");
        let err = build_outbound_email(
            &config,
            "recipient@example.invalid",
            "hello",
            None,
            None,
            1,
            1,
        )
        .unwrap_err();
        assert!(err.contains("inbound-only"));
    }
    for (key, value) in [
        ("smtp_host", "smtp.example.invalid"),
        ("from_address", "bot@example.invalid"),
    ] {
        let mut partial = base.clone();
        partial[key] = serde_json::json!(value);
        assert!(EmailConfig::from_json(&partial.to_string())
            .err()
            .expect("half-configured SMTP")
            .contains("together"));
    }
}
