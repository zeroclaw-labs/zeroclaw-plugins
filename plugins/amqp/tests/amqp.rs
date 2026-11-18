use amqp::amqp::{
    encode_ack, encode_heartbeat, map_delivery, Action, AmqpConfig, Delivery, Dispatch, Endpoint,
    Session, PROTOCOL_HEADER,
};

const FRAME_METHOD: u8 = 1;
const FRAME_HEADER: u8 = 2;
const FRAME_BODY: u8 = 3;
const FRAME_END: u8 = 0xce;

fn config_json(extra: &str) -> String {
    format!(
        r#"{{
            "enabled": true,
            "amqp_url": "amqp://alice:s%40cret@broker.example:5673/%2Fteam",
            "exchange": "events.topic",
            "routing_keys": ["build.completed", "release.#"],
            "queue": "zeroclaw-events",
            "sender_label": "release-bus",
            "content_template": "Release {{project.name}} {{version}}",
            "thread_id_field": "project.name",
            "durable_ack": true,
            "dispatch": "agent_loop"
            {extra}
        }}"#
    )
}

fn config() -> AmqpConfig {
    AmqpConfig::from_json(&config_json("")).expect("valid AMQP config")
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_shortstr(output: &mut Vec<u8>, value: &str) {
    output.push(value.len() as u8);
    output.extend_from_slice(value.as_bytes());
}

fn put_longstr(output: &mut Vec<u8>, value: &[u8]) {
    put_u32(output, value.len() as u32);
    output.extend_from_slice(value);
}

fn frame(frame_type: u8, channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(frame_type);
    put_u16(&mut output, channel);
    put_u32(&mut output, payload.len() as u32);
    output.extend_from_slice(payload);
    output.push(FRAME_END);
    output
}

fn method(channel: u16, class_id: u16, method_id: u16, args: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    put_u16(&mut payload, class_id);
    put_u16(&mut payload, method_id);
    payload.extend_from_slice(args);
    frame(FRAME_METHOD, channel, &payload)
}

fn connection_start() -> Vec<u8> {
    let mut args = vec![0, 9];
    put_u32(&mut args, 0);
    put_longstr(&mut args, b"AMQPLAIN PLAIN");
    put_longstr(&mut args, b"en_US");
    method(0, 10, 10, &args)
}

fn connection_tune(frame_max: u32, heartbeat: u16) -> Vec<u8> {
    let mut args = Vec::new();
    put_u16(&mut args, 2047);
    put_u32(&mut args, frame_max);
    put_u16(&mut args, heartbeat);
    method(0, 10, 30, &args)
}

fn longstr_ok(channel: u16, class_id: u16, method_id: u16) -> Vec<u8> {
    let mut args = Vec::new();
    put_longstr(&mut args, b"");
    method(channel, class_id, method_id, &args)
}

fn queue_declare_ok(queue: &str) -> Vec<u8> {
    let mut args = Vec::new();
    put_shortstr(&mut args, queue);
    put_u32(&mut args, 0);
    put_u32(&mut args, 0);
    method(1, 50, 11, &args)
}

fn consume_ok() -> Vec<u8> {
    let mut args = Vec::new();
    put_shortstr(&mut args, "zeroclaw-amqp-plugin");
    method(1, 60, 21, &args)
}

fn method_id(bytes: &[u8]) -> (u16, u16, u16) {
    assert_eq!(bytes[0], FRAME_METHOD);
    (
        u16::from_be_bytes([bytes[1], bytes[2]]),
        u16::from_be_bytes([bytes[7], bytes[8]]),
        u16::from_be_bytes([bytes[9], bytes[10]]),
    )
}

fn only_send(actions: Vec<Action>) -> Vec<u8> {
    assert_eq!(actions.len(), 1);
    match actions.into_iter().next().expect("one action") {
        Action::Send(bytes) => bytes,
        other => panic!("expected send action, got {other:?}"),
    }
}

fn ready_session(config: &AmqpConfig, frame_max: u32) -> Session {
    let mut session = Session::new();
    assert_eq!(
        method_id(&only_send(
            session.receive(config, &connection_start()).unwrap()
        )),
        (0, 10, 11)
    );

    let tune_actions = session
        .receive(config, &connection_tune(frame_max, 60))
        .expect("connection.tune");
    assert_eq!(tune_actions.len(), 2);
    let sent: Vec<(u16, u16, u16)> = tune_actions
        .into_iter()
        .map(|action| match action {
            Action::Send(bytes) => method_id(&bytes),
            other => panic!("expected tune send, got {other:?}"),
        })
        .collect();
    assert_eq!(sent, vec![(0, 10, 31), (0, 10, 40)]);

    let channel_open = only_send(
        session
            .receive(config, &longstr_ok(0, 10, 41))
            .expect("connection.open-ok"),
    );
    assert_eq!(method_id(&channel_open), (1, 20, 10));

    let queue_declare = only_send(
        session
            .receive(config, &longstr_ok(1, 20, 11))
            .expect("channel.open-ok"),
    );
    assert_eq!(method_id(&queue_declare), (1, 50, 10));

    let first_bind = only_send(
        session
            .receive(config, &queue_declare_ok("zeroclaw-events"))
            .expect("queue.declare-ok"),
    );
    assert_eq!(method_id(&first_bind), (1, 50, 20));

    for index in 0..config.routing_keys.len() {
        let action = only_send(
            session
                .receive(config, &method(1, 50, 21, &[]))
                .expect("queue.bind-ok"),
        );
        if index + 1 < config.routing_keys.len() {
            assert_eq!(method_id(&action), (1, 50, 20));
        } else if config.durable_ack {
            assert_eq!(method_id(&action), (1, 60, 10));
        } else {
            assert_eq!(method_id(&action), (1, 60, 20));
        }
    }

    if config.durable_ack {
        let consume = only_send(
            session
                .receive(config, &method(1, 60, 11, &[]))
                .expect("basic.qos-ok"),
        );
        assert_eq!(method_id(&consume), (1, 60, 20));
    }

    assert_eq!(
        session.receive(config, &consume_ok()).unwrap(),
        vec![Action::Ready]
    );
    assert!(session.is_ready());
    session
}

fn decode_frames(mut bytes: &[u8]) -> Vec<(u8, u16, Vec<u8>)> {
    let mut decoded = Vec::new();
    while !bytes.is_empty() {
        assert!(bytes.len() >= 8);
        let payload_len = u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as usize;
        let total = payload_len + 8;
        assert!(bytes.len() >= total);
        assert_eq!(bytes[total - 1], FRAME_END);
        decoded.push((
            bytes[0],
            u16::from_be_bytes([bytes[1], bytes[2]]),
            bytes[7..total - 1].to_vec(),
        ));
        bytes = &bytes[total..];
    }
    decoded
}

#[test]
fn parses_endpoint_auth_tls_ipv6_and_vhost() {
    let endpoint =
        Endpoint::parse("amqps://user:p%40ss@[2001:db8::7]:5679/%2Fteam").expect("valid endpoint");
    assert_eq!(
        endpoint,
        Endpoint {
            host: "2001:db8::7".to_string(),
            port: 5679,
            tls: true,
            username: "user".to_string(),
            password: "p@ss".to_string(),
            virtual_host: "/team".to_string(),
        }
    );
    assert_eq!(Endpoint::parse("amqp://broker").unwrap().virtual_host, "/");
}

#[test]
fn validates_native_config_and_rejects_unrepresentable_modes() {
    let cfg = config();
    assert_eq!(cfg.dispatch, Dispatch::AgentLoop);
    assert!(cfg.durable_ack);
    assert_eq!(cfg.endpoint().unwrap().password, "s@cret");

    let sop = config_json("").replace("\"dispatch\": \"agent_loop\"", "\"dispatch\": \"sop\"");
    assert!(AmqpConfig::from_json(&sop)
        .unwrap_err()
        .contains("SOP engine"));

    let mtls = config_json(",\n\"client_cert\": \"client.pem\", \"client_key\": \"key.pem\"");
    assert!(AmqpConfig::from_json(&mtls)
        .unwrap_err()
        .contains("host TLS profile"));

    let tls = config_json("").replace("amqp://", "amqps://");
    assert!(AmqpConfig::from_json(&tls).unwrap().endpoint().unwrap().tls);

    let profiled = config_json(",\n\"tls_profile\": \"broker\"");
    assert!(AmqpConfig::from_json(&profiled)
        .unwrap_err()
        .contains("requires amqps://"));
    let secure = profiled.replace("amqp://", "amqps://");
    assert_eq!(
        AmqpConfig::from_json(&secure)
            .unwrap()
            .tls_profile
            .as_deref(),
        Some("broker")
    );
}

#[test]
fn fragmented_start_frame_emits_plain_start_ok() {
    let config = config();
    let mut session = Session::new();
    let start = connection_start();
    assert!(session.receive(&config, &start[..5]).unwrap().is_empty());
    let response = only_send(session.receive(&config, &start[5..]).unwrap());
    assert_eq!(method_id(&response), (0, 10, 11));
    assert!(response
        .windows(b"\0alice\0s@cret".len())
        .any(|window| window == b"\0alice\0s@cret"));
    assert_eq!(PROTOCOL_HEADER, b"AMQP\0\0\x09\x01");
}

#[test]
fn handshake_binds_all_routes_negotiates_qos_and_becomes_ready() {
    let session = ready_session(&config(), 65_536);
    assert_eq!(session.frame_max(), 65_536);
    assert_eq!(session.heartbeat_secs(), 30);
}

#[test]
fn no_ack_consumers_skip_qos() {
    let raw = config_json("").replace("\"durable_ack\": true", "\"durable_ack\": false");
    let config = AmqpConfig::from_json(&raw).unwrap();
    let session = ready_session(&config, 4096);
    assert!(session.is_ready());
}

#[test]
fn assembles_delivery_across_arbitrary_frame_and_body_boundaries() {
    let config = config();
    let mut session = ready_session(&config, 4096);
    let body = br#"{"project":{"name":"zeroclaw"},"version":"1.2.3"}"#;

    let mut deliver_args = Vec::new();
    put_shortstr(&mut deliver_args, "zeroclaw-amqp-plugin");
    put_u64(&mut deliver_args, 42);
    deliver_args.push(1); // redelivered
    put_shortstr(&mut deliver_args, "events.topic");
    put_shortstr(&mut deliver_args, "release.created");

    let mut header = Vec::new();
    put_u16(&mut header, 60);
    put_u16(&mut header, 0);
    put_u64(&mut header, body.len() as u64);
    put_u16(&mut header, 0);

    let mut wire = method(1, 60, 60, &deliver_args);
    wire.extend_from_slice(&frame(FRAME_HEADER, 1, &header));
    wire.extend_from_slice(&frame(FRAME_BODY, 1, &body[..13]));
    wire.extend_from_slice(&frame(FRAME_BODY, 1, &body[13..]));

    let mut actions = Vec::new();
    for chunk in wire.chunks(7) {
        actions.extend(session.receive(&config, chunk).unwrap());
    }
    assert_eq!(actions.len(), 1);
    let delivery = match actions.pop().unwrap() {
        Action::Delivery(delivery) => delivery,
        other => panic!("expected delivery, got {other:?}"),
    };
    assert_eq!(delivery.delivery_tag, 42);
    assert!(delivery.redelivered);
    assert_eq!(delivery.routing_key, "release.created");
    assert_eq!(delivery.body, body);

    let mapped = map_delivery(&config, &delivery);
    assert_eq!(mapped.sender, "release-bus");
    assert_eq!(mapped.reply_target, "release-bus");
    assert_eq!(mapped.content, "Release zeroclaw 1.2.3");
    assert_eq!(mapped.thread_ts.as_deref(), Some("zeroclaw"));
}

#[test]
fn encodes_individual_ack_and_heartbeat_frames() {
    let ack = encode_ack(0x0102_0304_0506_0708);
    assert_eq!(method_id(&ack), (1, 60, 80));
    assert_eq!(&ack[11..19], &0x0102_0304_0506_0708_u64.to_be_bytes());
    assert_eq!(ack[19], 0); // multiple=false
    assert_eq!(encode_heartbeat(), vec![8, 0, 0, 0, 0, 0, 0, FRAME_END]);
}

#[test]
fn publish_uses_recipient_route_properties_and_negotiated_body_frames() {
    let config = config();
    let session = ready_session(&config, 4096);
    let body = vec![b'x'; 5000];
    let encoded = session
        .encode_publish(
            &config.exchange,
            "reply.route",
            &body,
            Some("build-result"),
            Some("corr-7"),
        )
        .unwrap();
    let frames = decode_frames(&encoded);
    assert_eq!(frames[0].0, FRAME_METHOD);
    assert_eq!(frames[0].1, 1);
    assert_eq!(
        (
            u16::from_be_bytes([frames[0].2[0], frames[0].2[1]]),
            u16::from_be_bytes([frames[0].2[2], frames[0].2[3]])
        ),
        (60, 40)
    );
    assert!(frames[0]
        .2
        .windows("events.topic".len())
        .any(|w| w == b"events.topic"));
    assert!(frames[0]
        .2
        .windows("reply.route".len())
        .any(|w| w == b"reply.route"));

    assert_eq!(frames[1].0, FRAME_HEADER);
    let flags = u16::from_be_bytes([frames[1].2[12], frames[1].2[13]]);
    assert_eq!(flags & 0x9400, 0x9400); // content-type, persistent, correlation-id
    assert_eq!(flags & 0x0020, 0x0020); // type/subject

    assert_eq!(frames.len(), 4);
    assert!(frames[2..]
        .iter()
        .all(|(kind, channel, _)| { *kind == FRAME_BODY && *channel == 1 }));
    let reassembled: Vec<u8> = frames[2..]
        .iter()
        .flat_map(|(_, _, payload)| payload.iter().copied())
        .collect();
    assert_eq!(reassembled, body);
}

#[test]
fn broker_channel_close_requests_close_ok_and_reconnect() {
    let config = config();
    let mut session = ready_session(&config, 4096);
    let mut args = Vec::new();
    put_u16(&mut args, 404);
    put_shortstr(&mut args, "NOT_FOUND - no exchange");
    put_u16(&mut args, 50);
    put_u16(&mut args, 20);
    let actions = session.receive(&config, &method(1, 20, 40, &args)).unwrap();
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        Action::Reconnect {
            reply: Some(reply),
            reason,
        } => {
            assert_eq!(method_id(reply), (1, 20, 41));
            assert!(reason.contains("404"));
            assert!(reason.contains("NOT_FOUND"));
        }
        other => panic!("expected reconnect, got {other:?}"),
    }
}

#[test]
fn malformed_frame_terminator_fails_closed() {
    let config = config();
    let mut session = Session::new();
    let mut start = connection_start();
    *start.last_mut().unwrap() = 0;
    assert!(session
        .receive(&config, &start)
        .unwrap_err()
        .contains("terminator"));
}

#[test]
fn raw_non_json_delivery_falls_back_to_text() {
    let config = config();
    let delivery = Delivery {
        delivery_tag: 1,
        redelivered: false,
        exchange: "events.topic".to_string(),
        routing_key: "build.completed".to_string(),
        body: b"plain event".to_vec(),
    };
    assert_eq!(map_delivery(&config, &delivery).content, "plain event");
}
