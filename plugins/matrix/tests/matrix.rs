use matrix::matrix::{
    build_send_body, encryption_url, matrix_id, parse_cursor, parse_room_id, parse_whoami,
    require_unencrypted, send_url, sync_url, whoami_url, Inbound, MatrixConfig, Session,
    MAX_PENDING, MAX_ROOM_METADATA,
};
use serde_json::{json, Value};

const SELF: &str = "@bot:example";
fn cfg() -> MatrixConfig {
    MatrixConfig::from_public_json(r#"{"homeserver":"https://matrix.example/"}"#).unwrap()
}
fn text(id: &str, sender: &str, content: Value) -> Value {
    json!({"type":"m.room.message", "event_id":id, "sender":sender,
        "origin_server_ts":1234, "content":content})
}
fn sync(events: Vec<Value>) -> Value {
    json!({"next_batch":"s2", "rooms":{"join":{"!room:example":{
        "summary":{"m.joined_member_count":4}, "timeline":{"events":events}}}}})
}
fn finish_bootstrap(state: &mut Session, cfg: &MatrixConfig) {
    let cursor = state.since.clone().unwrap();
    state.ingest(&json!({"next_batch":cursor}), cfg).unwrap();
    assert!(state.healthy());
}
fn messages(value: &Value, cfg: &MatrixConfig) -> Vec<Inbound> {
    let mut state = Session::new(cfg, SELF.into());
    state.ingest(&json!({"next_batch":"start"}), cfg).unwrap();
    finish_bootstrap(&mut state, cfg);
    state.ingest(value, cfg).unwrap();
    let mut messages = Vec::new();
    while let Some(message) = state.next(cfg) {
        messages.push(message);
    }
    messages
}

#[test]
fn public_config_rejects_credentials_unknown_keys_and_sensitive_urls() {
    for input in [
        r#"{"homeserver":"https://matrix.example","access_token":"secret"}"#,
        r#"{"homeserver":"https://matrix.example","password":"secret"}"#,
        r#"{"homeserver":"https://user:password@matrix.example"}"#,
        r#"{"homeserver":"https://matrix.example/?token=secret"}"#,
        r#"{"homeserver":"https://matrix.example/#fragment"}"#,
        r#"{"homeserver":"https://matrix.example","allowed_rooms":["not a room"]}"#,
        "not json",
    ] {
        assert!(MatrixConfig::from_public_json(input).is_err());
    }
    assert!(cfg().reply_in_thread);
    assert_eq!(
        parse_whoami(&json!({"user_id": SELF})).as_deref(),
        Some(SELF)
    );
    assert!(parse_whoami(&json!({"user_id": "not-an-id"})).is_none());
    assert!(parse_whoami(&json!({"errcode": "M_UNKNOWN_TOKEN"})).is_none());
}

#[test]
fn room_ids_are_opaque_without_relaxing_user_alias_or_room_policy() {
    let hash_room = format!("!{}", "A".repeat(43));
    for room in ["!legacy:example", hash_room.as_str()] {
        let input = json!({"homeserver":"https://matrix.example", "allowed_rooms":[room]});
        let config = MatrixConfig::from_public_json(&input.to_string()).unwrap();
        assert_eq!(
            parse_room_id(&json!({"room_id": room})).as_deref(),
            Some(room)
        );
        let value = json!({"next_batch":"s2", "rooms":{"join":{(room):{
            "summary":{"m.joined_member_count":4},
            "timeline":{"events":[text("$message", "@user:example", json!({"msgtype":"m.text","body":"hello"}))]}
        }, "!excluded:example":{
            "timeline":{"events":[text("$excluded", "@user:example", json!({"msgtype":"m.text","body":"blocked"}))]}
        }}}});
        let inbound = messages(&value, &config);
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].reply_target, room);
        assert_eq!(inbound[0].id, "$message");
        assert!(send_url(config.homeserver(), room, 1).contains("/rooms/%21"));
    }
    for room in [
        "",
        "!",
        "not-a-room",
        "!has space",
        "!tab\t",
        "!nul\0",
        "!del\u{7f}",
        "!control\u{80}",
    ] {
        assert!(!matrix_id(room, '!'));
        assert!(parse_room_id(&json!({"room_id": room})).is_none());
        let input = json!({"homeserver":"https://matrix.example", "allowed_rooms":[room]});
        assert!(MatrixConfig::from_public_json(&input.to_string()).is_err());
    }
    assert!(!matrix_id(&format!("!{}", "A".repeat(255)), '!'));
    for (id, prefix) in [
        ("@user", '@'),
        ("@:example", '@'),
        ("@user:", '@'),
        ("#alias", '#'),
        ("#:example", '#'),
        ("#alias:", '#'),
    ] {
        assert!(!matrix_id(id, prefix));
    }
    assert!(matrix_id("@user:example", '@'));
    assert!(matrix_id("#alias:example", '#'));
}

#[test]
fn urls_encode_room_alias_and_cursor_segments() {
    assert_eq!(
        whoami_url(cfg().homeserver()),
        "https://matrix.example/_matrix/client/v3/account/whoami"
    );
    assert_eq!(
        sync_url(cfg().homeserver(), Some("next/1")),
        "https://matrix.example/_matrix/client/v3/sync?timeout=0&since=next%2F1"
    );
    assert!(send_url(cfg().homeserver(), "!room:example", 1).contains("%21room%3Aexample"));
    assert!(encryption_url(cfg().homeserver(), "!r:example")
        .ends_with("rooms/%21r%3Aexample/state/m.room.encryption/"));
}

#[test]
fn encryption_preflight_admits_only_endpoint_specific_authenticated_absence() {
    assert!(require_unencrypted(404, br#"{"errcode":"M_NOT_FOUND"}"#).is_ok());
    for (status, body) in [
        (200, br#"{"algorithm":"m.megolm.v1.aes-sha2"}"#.as_slice()),
        (200, br#"{"algorithm":"unknown"}"#.as_slice()),
        (200, br#"{}"#.as_slice()),
        (200, b"".as_slice()),
        (404, br#"{}"#.as_slice()),
        (404, b"not json".as_slice()),
        (404, br#"{"errcode":"M_FORBIDDEN"}"#.as_slice()),
        (403, br#"{"errcode":"M_NOT_FOUND"}"#.as_slice()),
        (401, br#"{"errcode":"M_UNKNOWN_TOKEN"}"#.as_slice()),
        (302, b"".as_slice()),
        (500, b"".as_slice()),
    ] {
        assert!(
            require_unencrypted(status, body).is_err(),
            "status {status}"
        );
    }
}

#[test]
fn text_mapping_filters_echoes_media_edits_and_rooms() {
    let mut config = cfg();
    config.allowed_rooms = vec!["!room:example".into()];
    let mut value = sync(vec![
        text(
            "$plain",
            "@user:example",
            json!({"msgtype":"m.text","body":"hello"}),
        ),
        text("$self", SELF, json!({"msgtype":"m.text","body":"echo"})),
        text(
            "$image",
            "@user:example",
            json!({"msgtype":"m.image","body":"image"}),
        ),
        text(
            "$edit",
            "@user:example",
            json!({"msgtype":"m.text","body":"edit",
            "m.relates_to":{"rel_type":"m.replace","event_id":"$plain"}}),
        ),
        json!({"type":"m.room.encrypted", "event_id":"$cipher", "sender":"@user:example"}),
    ]);
    value["rooms"]["join"]["!blocked:example"] = json!({"timeline":{"events":[
        text("$blocked", "@user:example", json!({"msgtype":"m.text","body":"blocked"}))]}});
    let inbound = messages(&value, &config);
    assert_eq!(inbound.len(), 1);
    assert_eq!(inbound[0].timestamp, 1234);
    assert_eq!(inbound[0].reply_target, "!room:example");
    assert_eq!(inbound[0].thread_ts.as_deref(), Some("$plain"));
    assert_eq!(inbound[0].interruption_scope_id, None);
    let reply = build_send_body("world", inbound[0].thread_ts.as_deref(), true);
    assert_eq!(reply["m.relates_to"]["m.in_reply_to"]["event_id"], "$plain");
    assert!(build_send_body("world", Some("$plain"), false)
        .get("m.relates_to")
        .is_none());
}

#[test]
fn same_sender_threads_have_distinct_interruption_roots_not_reply_anchors() {
    let value = sync(vec![
        text(
            "$one",
            "@user:example",
            json!({"msgtype":"m.text","body":"one",
            "m.relates_to":{"rel_type":"m.thread","event_id":"$root1"}}),
        ),
        text(
            "$two",
            "@user:example",
            json!({"msgtype":"m.text","body":"two",
            "m.relates_to":{"rel_type":"m.thread","event_id":"$root2"}}),
        ),
    ]);
    let mut config = cfg();
    config.reply_in_thread = false;
    let inbound = messages(&value, &config);
    assert_eq!(inbound[0].interruption_scope_id.as_deref(), Some("$root1"));
    assert_eq!(inbound[1].interruption_scope_id.as_deref(), Some("$root2"));
    assert_eq!(inbound[0].thread_ts, inbound[0].interruption_scope_id);
}

#[test]
fn queued_delivery_uses_current_room_mention_and_reply_policy() {
    let value = sync(vec![
        text(
            "$plain",
            "@user:example",
            json!({"msgtype":"m.text","body":"hello"}),
        ),
        text(
            "$mention",
            "@user:example",
            json!({"msgtype":"m.text","body":"hello",
            "m.mentions":{"user_ids":[SELF]}}),
        ),
    ]);
    let mut config = cfg();
    let mut state = Session::new(&config, SELF.into());
    state
        .ingest(&json!({"next_batch":"start"}), &config)
        .unwrap();
    finish_bootstrap(&mut state, &config);
    state.ingest(&value, &config).unwrap();
    config.mention_only = true;
    config.reply_in_thread = false;
    let delivered = state.next(&config).unwrap();
    assert_eq!(delivered.id, "$mention");
    assert!(delivered.thread_ts.is_none());
    state.ingest(&value, &config).unwrap();
    config.allowed_rooms = vec!["!else:example".into()];
    assert!(state.next(&config).is_none());
}

#[test]
fn mention_gate_keeps_direct_room_and_explicit_mention_behavior() {
    let mut config = cfg();
    config.mention_only = true;
    let mut value = sync(vec![text(
        "$dm",
        "@user:example",
        json!({"msgtype":"m.text","body":"hello"}),
    )]);
    assert!(messages(&value, &config).is_empty());
    value["rooms"]["join"]["!room:example"]["summary"]["m.joined_member_count"] = json!(2);
    assert_eq!(messages(&value, &config).len(), 1);
    value["rooms"]["join"]["!room:example"]
        .as_object_mut()
        .unwrap()
        .remove("summary");
    value["account_data"] =
        json!({"events":[{"type":"m.direct","content":{"@user:example":["!room:example"]}}]});
    assert_eq!(messages(&value, &config).len(), 1);
}

#[test]
fn account_or_homeserver_change_discards_state_and_requires_fresh_configure() {
    for change_server in [false, true] {
        let config = cfg();
        let mut state = Session::new(&config, SELF.into());
        state
            .ingest(
                &json!({"next_batch":"start", "account_data":{"events":[
                    {"type":"m.direct","content":{"@user:example":["!room:example"]}}
                ]}}),
                &config,
            )
            .unwrap();
        finish_bootstrap(&mut state, &config);
        let value = sync(vec![text(
            "$queued",
            "@user:example",
            json!({"msgtype":"m.text","body":"hello"}),
        )]);
        state.ingest(&value, &config).unwrap();
        assert!(!state.rooms.is_empty());
        let mut changed = config.clone();
        let account = if change_server {
            changed.homeserver = "https://other.example".into();
            SELF
        } else {
            "@other:example"
        };
        assert!(state.check_binding(&changed, account).is_err());
        assert!(state.since.is_none());
        assert!(state.pending.is_empty());
        assert!(state.rooms.is_empty());
        assert!(state.check_binding(&config, SELF).is_err());
        assert!(!state.healthy());
        assert!(Session::new(&config, SELF.into())
            .check_binding(&config, SELF)
            .is_ok());
    }
}

#[test]
fn startup_suppresses_backlog_and_identity_probe_does_not_clear_sync_failure() {
    let config = cfg();
    let mut state = Session::new(&config, SELF.into());
    assert!(!state.healthy());
    let value = sync(vec![text(
        "$backlog",
        "@user:example",
        json!({"msgtype":"m.text","body":"old"}),
    )]);
    state.ingest(&value, &config).unwrap();
    assert!(state.next(&config).is_none());
    assert!(!state.healthy());
    finish_bootstrap(&mut state, &config);
    assert!(state.healthy());
    state.sync_failed = true;
    assert!(state.check_binding(&config, SELF).is_ok());
    assert!(!state.healthy());
    state
        .ingest(&json!({"next_batch":"recovered"}), &config)
        .unwrap();
    assert!(state.healthy());
}

#[test]
fn cached_startup_catch_up_is_suppressed_until_unchanged_incremental_cursor() {
    let config = cfg();
    let mut state = Session::new(&config, SELF.into());
    for cursor in ["cached", "catch-up-one", "catch-up-two"] {
        let mut batch = sync(vec![text(
            "$historical",
            "@user:example",
            json!({"msgtype":"m.text","body":"old"}),
        )]);
        batch["next_batch"] = json!(cursor);
        batch["rooms"]["join"]["!room:example"]["timeline"]["limited"] = json!(true);
        state.ingest(&batch, &config).unwrap();
        assert_eq!(state.since.as_deref(), Some(cursor));
        assert!(!state.healthy());
        assert!(state.next(&config).is_none());
    }
    let prior = state.rooms.clone();
    for invalid in [
        json!({"next_batch":"catch-up-two", "rooms":{"join":{"!new:example":{"timeline":{}}}}}),
        json!({"next_batch":"x".repeat(4097)}),
        json!({"next_batch":"catch-up-two", "account_data":{"events":[
            {"type":"m.direct","content":{"@user:example":(0..=MAX_ROOM_METADATA)
                .map(|i| format!("!overflow{i}:example")).collect::<Vec<_>>()}}
        ]}}),
    ] {
        assert!(state.ingest(&invalid, &config).is_err());
        assert_eq!(state.since.as_deref(), Some("catch-up-two"));
        assert_eq!(state.rooms, prior);
        assert!(!state.healthy());
        assert!(state.next(&config).is_none());
    }
    let mut equality = sync(vec![text(
        "$boundary",
        "@user:example",
        json!({"msgtype":"m.text","body":"still suppressed"}),
    )]);
    equality["next_batch"] = json!("catch-up-two");
    equality["rooms"]["join"]["!room:example"]["summary"]["m.joined_member_count"] = json!(2);
    state.ingest(&equality, &config).unwrap();
    assert!(state.healthy());
    assert!(state.next(&config).is_none());
    let mut fresh = sync(vec![text(
        "$fresh",
        "@user:example",
        json!({"msgtype":"m.text","body":"new"}),
    )]);
    fresh["next_batch"] = json!("fresh");
    fresh["rooms"]["join"]["!room:example"]
        .as_object_mut()
        .unwrap()
        .remove("summary");
    let mut mention_only = config.clone();
    mention_only.mention_only = true;
    state.ingest(&fresh, &mention_only).unwrap();
    assert_eq!(state.next(&mention_only).unwrap().id, "$fresh");
    assert!(state.next(&mention_only).is_none());
}

#[test]
fn sync_cursor_and_queue_limits_fail_without_advancing_session() {
    let events = (0..=MAX_PENDING)
        .map(|i| {
            text(
                &format!("$event{i}"),
                "@user:example",
                json!({"msgtype":"m.text","body":"hello"}),
            )
        })
        .collect();
    let value = sync(events);
    let config = cfg();
    let mut state = Session::new(&config, SELF.into());
    state.ingest(&value, &config).unwrap();
    assert!(state.pending.is_empty());
    finish_bootstrap(&mut state, &config);
    assert!(state.ingest(&value, &config).is_err());
    assert_eq!(state.since.as_deref(), Some("s2"));
    // Startup can suppress a backlog larger than the delivery queue.
    assert_eq!(parse_cursor(&value).unwrap(), "s2");
    assert!(parse_cursor(&json!({"next_batch":""})).is_err());
    assert!(parse_cursor(&json!({"next_batch":"x".repeat(4097)})).is_err());
    for malformed in [
        json!({"next_batch":"s3", "rooms": []}),
        json!({"next_batch":"s3", "rooms": {"join": []}}),
        json!({"next_batch":"s3", "rooms": {"join": {"!r:example": {"timeline": {}}}}}),
        json!({"next_batch":"s3", "rooms": {"join": {"!r:example": {"timeline": {"events": {}}}}}}),
    ] {
        assert!(state.ingest(&malformed, &config).is_err());
        assert_eq!(state.since.as_deref(), Some("s2"));
        assert!(!state.healthy());
    }
}

#[test]
fn excluded_room_events_do_not_consume_the_allowed_queue() {
    let mut config = cfg();
    config.allowed_rooms = vec!["!room:example".into()];
    let excluded: Vec<_> = (0..=MAX_PENDING)
        .map(|i| {
            text(
                &format!("$blocked{i}"),
                "@user:example",
                json!({"msgtype":"m.text","body":"blocked"}),
            )
        })
        .collect();
    let mut value = sync(vec![text(
        "$allowed",
        "@user:example",
        json!({"msgtype":"m.text","body":"allowed"}),
    )]);
    value["rooms"]["join"]["!excluded:example"] =
        json!({"timeline":{"events":excluded,"limited":true}});
    let delivered = messages(&value, &config);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].id, "$allowed");
}

#[test]
fn startup_room_metadata_survives_omission_but_not_replacement_or_leave() {
    for via_direct in [true, false] {
        let mut config = cfg();
        config.mention_only = true;
        let mut state = Session::new(&config, SELF.into());
        let mut initial = sync(Vec::new());
        if via_direct {
            initial["account_data"] = json!({"events":[{"type":"m.direct","content":{"@user:example":["!room:example"]}}]});
        } else {
            initial["rooms"]["join"]["!room:example"]["summary"]["m.joined_member_count"] =
                json!(2);
        }
        state.ingest(&initial, &config).unwrap();
        finish_bootstrap(&mut state, &config);
        let mut later = sync(vec![text(
            "$later",
            "@user:example",
            json!({"msgtype":"m.text","body":"hello"}),
        )]);
        later["rooms"]["join"]["!room:example"]
            .as_object_mut()
            .unwrap()
            .remove("summary");
        state.ingest(&later, &config).unwrap();
        assert_eq!(state.next(&config).unwrap().id, "$later");

        // A present empty summary is a delta with no count change.
        later["rooms"]["join"]["!room:example"]["summary"] = json!({});
        state.ingest(&later, &config).unwrap();
        assert!(state.next(&config).is_some());

        let mut replacement = json!({"next_batch":"replacement"});
        if via_direct {
            replacement["account_data"] = json!({"events":[{"type":"m.direct","content":{}}]});
        } else {
            replacement["rooms"] =
                json!({"join":{"!room:example":{"summary":{"m.joined_member_count":4}}}});
        }
        state.ingest(&replacement, &config).unwrap();
        state.ingest(&later, &config).unwrap();
        assert!(state.next(&config).is_none());

        state.ingest(&initial, &config).unwrap();
        state
            .ingest(
                &json!({"next_batch":"leave", "rooms":{"leave":{"!room:example":{}}}}),
                &config,
            )
            .unwrap();
        assert!(state.rooms.is_empty());
        state.ingest(&later, &config).unwrap();
        assert!(state.next(&config).is_none());
    }
}

#[test]
fn leave_removes_pending_messages_and_all_room_provenance() {
    let config = cfg();
    let mut state = Session::new(&config, SELF.into());
    state
        .ingest(
            &json!({"next_batch":"start", "account_data":{"events":[
                {"type":"m.direct", "content":{"@user:example":["!room:example"]}}
            ]}}),
            &config,
        )
        .unwrap();
    finish_bootstrap(&mut state, &config);
    state
        .ingest(
            &sync(vec![text(
                "$queued",
                "@user:example",
                json!({"msgtype":"m.text","body":"hello"}),
            )]),
            &config,
        )
        .unwrap();
    assert_eq!(state.pending.len(), 1);
    state
        .ingest(
            &json!({"next_batch":"left", "rooms":{"leave":{"!room:example":{}}}}),
            &config,
        )
        .unwrap();
    assert!(state.pending.is_empty());
    assert!(state.rooms.is_empty());
}

#[test]
fn limited_and_malformed_batches_do_not_commit_cursor_queue_or_metadata() {
    let config = cfg();
    let mut state = Session::new(&config, SELF.into());
    let mut initial = sync(vec![text(
        "$old",
        "@user:example",
        json!({"msgtype":"m.text","body":"old"}),
    )]);
    initial["rooms"]["join"]["!room:example"]["timeline"]["limited"] = json!(true);
    state.ingest(&initial, &config).unwrap();
    assert!(state.pending.is_empty());
    assert!(!state.healthy());
    finish_bootstrap(&mut state, &config);
    assert!(state.healthy());
    state
        .ingest(
            &sync(vec![text(
                "$queued",
                "@user:example",
                json!({"msgtype":"m.text","body":"queued"}),
            )]),
            &config,
        )
        .unwrap();
    let prior = state.rooms.clone();
    for timeline in [
        json!({"events":[], "limited":true}),
        json!({}),
        json!({"events":[], "limited":"true"}),
        json!({"events":[], "limited":null}),
        json!({"events":{}, "limited":false}),
        json!([]),
    ] {
        let value = json!({"next_batch":"must-not-commit", "account_data":{"events":[
            {"type":"m.direct", "content":{"@user:example":["!new:example"]}}
        ]}, "rooms":{"join":{"!room:example":{"summary":{"m.joined_member_count":2}, "timeline":timeline}}}});
        if timeline.get("limited") != Some(&json!(true)) {
            let mut fresh = Session::new(&config, SELF.into());
            assert!(fresh.ingest(&value, &config).is_err());
            assert!(fresh.since.is_none());
            assert!(fresh.rooms.is_empty());
        }
        assert!(state.ingest(&value, &config).is_err());
        assert_eq!(state.since.as_deref(), Some("s2"));
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.rooms, prior);
        assert!(!state.healthy());
    }
    assert_eq!(state.next(&config).unwrap().id, "$queued");
    assert!(state.check_binding(&config, SELF).is_ok());
    assert!(!state.healthy());
}

#[test]
fn metadata_overflow_does_not_partially_admit_replacement_or_cursor() {
    let config = cfg();
    let mut state = Session::new(&config, SELF.into());
    state.ingest(&sync(Vec::new()), &config).unwrap();
    finish_bootstrap(&mut state, &config);
    let prior = state.rooms.clone();
    let rooms: Vec<_> = (0..MAX_ROOM_METADATA)
        .map(|i| format!("!direct{i}:example"))
        .collect();
    let value = json!({"next_batch":"overflow", "account_data":{"events":[
        {"type":"m.direct", "content":{"@user:example":rooms}}
    ]}});
    // The existing member-count record and replacement together exceed 256.
    assert!(state.ingest(&value, &config).is_err());
    assert_eq!(state.since.as_deref(), Some("s2"));
    assert_eq!(state.rooms, prior);
    assert!(!state.healthy());
    let fitting: Vec<_> = (0..MAX_ROOM_METADATA - 1)
        .map(|i| format!("!direct{i}:example"))
        .collect();
    state
        .ingest(
            &json!({"next_batch":"fits", "account_data":{"events":[
                {"type":"m.direct", "content":{"@user:example":fitting}}
            ]}}),
            &config,
        )
        .unwrap();
    assert_eq!(state.rooms.len(), MAX_ROOM_METADATA);
    state
        .ingest(
            &json!({"next_batch":"cleared", "account_data":{"events":[
                {"type":"m.direct", "content":{}}
            ]}}),
            &config,
        )
        .unwrap();
    assert_eq!(state.rooms, prior);
    assert!(state.healthy());
}

#[test]
fn departures_free_metadata_capacity_before_additions_and_reject_malformed_entries() {
    let config = cfg();
    let mut state = Session::new(&config, SELF.into());
    let joined: serde_json::Map<String, Value> = (0..MAX_ROOM_METADATA)
        .map(|i| {
            (
                format!("!room{i}:example"),
                json!({"summary":{"m.joined_member_count":4}}),
            )
        })
        .collect();
    state
        .ingest(
            &json!({"next_batch":"full", "rooms":{"join":joined}}),
            &config,
        )
        .unwrap();
    assert_eq!(state.rooms.len(), MAX_ROOM_METADATA);
    state.ingest(&json!({"next_batch":"replacement", "rooms":{"leave":{"!room0:example":{}}},
        "account_data":{"events":[{"type":"m.direct", "content":{"@user:example":["!new:example", "!room0:example"]}}]}}), &config).unwrap();
    assert_eq!(state.rooms.len(), MAX_ROOM_METADATA);
    assert!(!state.rooms.contains_key("!room0:example"));
    assert!(state.rooms.contains_key("!new:example"));
    let prior = state.rooms.clone();
    for leave in [json!({"not-a-room":{}}), json!({"!new:example":null})] {
        assert!(state
            .ingest(
                &json!({"next_batch":"must-not-commit", "rooms":{"leave":leave}}),
                &config
            )
            .is_err());
        assert_eq!(state.since.as_deref(), Some("replacement"));
        assert_eq!(state.rooms, prior);
        assert!(!state.healthy());
    }
}
