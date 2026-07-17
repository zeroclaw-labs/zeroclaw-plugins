//! Pure Nostr private-message protocol logic.
//!
//! The WASM component owns relay I/O. This module owns key parsing, event
//! signing and verification, NIP-04, NIP-44 v2, NIP-17/NIP-59 wrapping, and
//! relay frame encoding. It deliberately has no socket or WIT dependency so
//! the cryptographic path can be exercised by ordinary host tests.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chacha20::cipher::StreamCipher;
use chacha20::ChaCha20;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub const SUBSCRIPTION_ID: &str = "zeroclaw-dms";
pub const KIND_NIP04_DM: u32 = 4;
pub const KIND_SEAL: u32 = 13;
pub const KIND_NIP17_DM: u32 = 14;
pub const KIND_GIFT_WRAP: u32 = 1059;
pub const KIND_RELAY_AUTH: u32 = 22242;

const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_BASE64_PAYLOAD_BYTES: usize = 1_500_000;
const MAX_RELAY_FRAME_BYTES: usize = 2 * 1024 * 1024;
const NIP44_VERSION: u8 = 2;
const NIP44_MIN_BASE64_BYTES: usize = 132;
const NIP44_MIN_DECODED_BYTES: usize = 99;
const NIP44_NONCE_BYTES: usize = 32;
const NIP44_MAC_BYTES: usize = 32;
const NIP44_EXTENDED_PREFIX_THRESHOLD: usize = 65_536;
const TIMESTAMP_TWEAK_SECS: u64 = 2 * 24 * 60 * 60;

#[derive(Clone)]
pub struct NostrKeys {
    signing_key: SigningKey,
}

impl std::fmt::Debug for NostrKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrKeys")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl NostrKeys {
    pub fn from_private_key(value: &str) -> Result<Self, String> {
        let value = value.trim();
        let bytes = if value.starts_with("nsec1") {
            decode_bech32_key(value, "nsec")?
        } else {
            decode_hex_array::<32>(value.strip_prefix("0x").unwrap_or(value), "private key")?
        };
        Self::from_secret_bytes(bytes)
    }

    fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self, String> {
        let field_bytes = k256::FieldBytes::from(bytes);
        let signing_key = SigningKey::from_bytes(&field_bytes)
            .map_err(|_| "nostr private key is not a valid secp256k1 scalar".to_string())?;
        Ok(Self { signing_key })
    }

    fn generate() -> Result<Self, String> {
        for _ in 0..8 {
            let mut bytes = [0_u8; 32];
            fill_random(&mut bytes)?;
            if let Ok(keys) = Self::from_secret_bytes(bytes) {
                return Ok(keys);
            }
        }
        Err("random source did not produce a valid secp256k1 key".to_string())
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    fn shared_x(&self, peer_public_key: &str) -> Result<[u8; 32], String> {
        let peer = parse_public_key(peer_public_key)?;
        let mut compressed = [0_u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&peer);
        let public_key = k256::PublicKey::from_sec1_bytes(&compressed)
            .map_err(|_| "nostr peer public key is not on secp256k1".to_string())?;
        let secret_bytes = self.signing_key.to_bytes();
        let secret_key = k256::SecretKey::from_slice(&secret_bytes)
            .map_err(|_| "nostr private key could not be converted for ECDH".to_string())?;
        let shared =
            k256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
        let mut output = [0_u8; 32];
        output.copy_from_slice(shared.raw_secret_bytes());
        Ok(output)
    }

    fn sign_id(&self, id: &[u8; 32]) -> Result<String, String> {
        let mut auxiliary_random = [0_u8; 32];
        fill_random(&mut auxiliary_random)?;
        let signature = self
            .signing_key
            .sign_raw(id, &auxiliary_random)
            .map_err(|_| "failed to create BIP-340 signature".to_string())?;
        Ok(hex::encode(signature.to_bytes()))
    }
}

#[derive(Debug, Clone)]
pub struct NostrConfig {
    pub keys: NostrKeys,
    pub relays: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    relays: Vec<String>,
}

impl NostrConfig {
    pub fn from_json(config_json: &str) -> Result<Self, String> {
        let raw: RawConfig = serde_json::from_str(config_json)
            .map_err(|error| format!("invalid Nostr config JSON: {error}"))?;
        if raw.private_key.trim().is_empty() {
            return Err("nostr private_key is required".to_string());
        }
        let keys = NostrKeys::from_private_key(&raw.private_key)?;
        let relays = dedup_nonempty(raw.relays);
        for relay in &relays {
            if !(relay.starts_with("wss://") || relay.starts_with("ws://")) {
                return Err(format!(
                    "invalid Nostr relay `{relay}`: expected ws:// or wss://"
                ));
            }
        }
        Ok(Self { keys, relays })
    }

    pub fn subscription_frame(&self) -> Result<String, String> {
        serde_json::to_string(&json!([
            "REQ",
            SUBSCRIPTION_ID,
            {
                "kinds": [KIND_NIP04_DM, KIND_GIFT_WRAP],
                "#p": [self.keys.public_key()],
                "limit": 10
            }
        ]))
        .map_err(|error| format!("failed to encode Nostr subscription: {error}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    #[serde(default)]
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl NostrEvent {
    fn new(created_at: u64, kind: u32, tags: Vec<Vec<String>>, content: String) -> Self {
        Self {
            id: None,
            pubkey: String::new(),
            created_at,
            kind,
            tags,
            content,
            sig: None,
        }
    }

    fn sign(&mut self, keys: &NostrKeys) -> Result<(), String> {
        self.pubkey = keys.public_key();
        let id = self.compute_id()?;
        self.id = Some(hex::encode(id));
        self.sig = Some(keys.sign_id(&id)?);
        Ok(())
    }

    fn set_rumor_id(&mut self, keys: &NostrKeys) -> Result<(), String> {
        self.pubkey = keys.public_key();
        let id = self.compute_id()?;
        self.id = Some(hex::encode(id));
        self.sig = None;
        Ok(())
    }

    fn compute_id(&self) -> Result<[u8; 32], String> {
        let canonical = serde_json::to_vec(&(
            0_u8,
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        ))
        .map_err(|error| format!("failed to encode Nostr event id input: {error}"))?;
        Ok(Sha256::digest(canonical).into())
    }

    pub fn verify_signed(&self) -> Result<(), String> {
        let expected_id = self.compute_id()?;
        let stored_id = self
            .id
            .as_deref()
            .ok_or_else(|| "signed Nostr event is missing id".to_string())?;
        let stored_id = decode_hex_array::<32>(stored_id, "event id")?;
        if stored_id != expected_id {
            return Err("Nostr event id does not match its content".to_string());
        }
        let public_key = parse_public_key(&self.pubkey)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| "Nostr event has an invalid public key".to_string())?;
        let signature_bytes = decode_hex_array::<64>(
            self.sig
                .as_deref()
                .ok_or_else(|| "signed Nostr event is missing sig".to_string())?,
            "event signature",
        )?;
        let signature = Signature::try_from(signature_bytes.as_slice())
            .map_err(|_| "Nostr event signature is malformed".to_string())?;
        verifying_key
            .verify_prehash(&expected_id, &signature)
            .map_err(|_| "Nostr event signature verification failed".to_string())
    }

    fn verify_rumor(&self) -> Result<(), String> {
        if self.sig.is_some() {
            return Err("NIP-59 rumor must not be signed".to_string());
        }
        let expected_id = self.compute_id()?;
        let stored_id = decode_hex_array::<32>(
            self.id
                .as_deref()
                .ok_or_else(|| "NIP-59 rumor is missing id".to_string())?,
            "rumor id",
        )?;
        if stored_id != expected_id {
            return Err("NIP-59 rumor id does not match its content".to_string());
        }
        parse_public_key(&self.pubkey)?;
        Ok(())
    }

    fn id_string(&self) -> Result<String, String> {
        let id = self
            .id
            .as_deref()
            .ok_or_else(|| "Nostr event is missing id".to_string())?;
        Ok(hex::encode(decode_hex_array::<32>(id, "event id")?))
    }

    fn is_addressed_to(&self, public_key: &str) -> bool {
        self.tags.iter().any(|tag| {
            tag.first().is_some_and(|name| name == "p")
                && tag
                    .get(1)
                    .and_then(|value| normalize_public_key(value).ok())
                    .is_some_and(|value| value == public_key)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmProtocol {
    Nip04,
    Nip17,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedDm {
    pub id: String,
    pub sender: String,
    pub content: String,
    pub timestamp_ms: u64,
    pub protocol: DmProtocol,
}

pub fn build_direct_message(
    keys: &NostrKeys,
    recipient: &str,
    content: &str,
    protocol: DmProtocol,
    now_secs: u64,
) -> Result<NostrEvent, String> {
    if content.is_empty() {
        return Err("Nostr direct message content cannot be empty".to_string());
    }
    if content.len() > MAX_MESSAGE_BYTES {
        return Err(format!(
            "Nostr direct message exceeds {MAX_MESSAGE_BYTES} bytes"
        ));
    }
    let recipient = normalize_public_key(recipient)?;
    match protocol {
        DmProtocol::Nip04 => build_nip04_event(keys, &recipient, content, now_secs),
        DmProtocol::Nip17 => build_nip17_event(keys, &recipient, content, now_secs),
    }
}

pub fn decode_direct_message(
    keys: &NostrKeys,
    event: &NostrEvent,
    listen_started_at_secs: u64,
) -> Result<Option<DecodedDm>, String> {
    event.verify_signed()?;
    let own_public_key = keys.public_key();
    if !event.is_addressed_to(&own_public_key) {
        return Ok(None);
    }

    match event.kind {
        KIND_NIP04_DM => {
            let sender = normalize_public_key(&event.pubkey)?;
            if event.created_at < listen_started_at_secs || sender == own_public_key {
                return Ok(None);
            }
            let content = nip04_decrypt(keys, &sender, &event.content)?;
            Ok(Some(DecodedDm {
                id: event.id_string()?,
                sender,
                content,
                timestamp_ms: event.created_at.saturating_mul(1_000),
                protocol: DmProtocol::Nip04,
            }))
        }
        KIND_GIFT_WRAP => {
            let seal_json = nip44_decrypt(keys, &event.pubkey, &event.content)?;
            let seal: NostrEvent = serde_json::from_str(&seal_json)
                .map_err(|error| format!("invalid NIP-59 seal JSON: {error}"))?;
            seal.verify_signed()?;
            if seal.kind != KIND_SEAL || !seal.tags.is_empty() {
                return Err("NIP-59 seal must be kind 13 with no tags".to_string());
            }

            let rumor_json = nip44_decrypt(keys, &seal.pubkey, &seal.content)?;
            let rumor: NostrEvent = serde_json::from_str(&rumor_json)
                .map_err(|error| format!("invalid NIP-59 rumor JSON: {error}"))?;
            rumor.verify_rumor()?;
            let seal_sender = normalize_public_key(&seal.pubkey)?;
            let rumor_sender = normalize_public_key(&rumor.pubkey)?;
            if rumor_sender != seal_sender {
                return Err("NIP-59 seal signer does not match rumor author".to_string());
            }
            if rumor.kind != KIND_NIP17_DM || !rumor.is_addressed_to(&own_public_key) {
                return Ok(None);
            }
            if rumor.created_at < listen_started_at_secs || rumor_sender == own_public_key {
                return Ok(None);
            }
            Ok(Some(DecodedDm {
                id: event.id_string()?,
                sender: rumor_sender,
                content: rumor.content,
                timestamp_ms: rumor.created_at.saturating_mul(1_000),
                protocol: DmProtocol::Nip17,
            }))
        }
        _ => Ok(None),
    }
}

fn build_nip04_event(
    keys: &NostrKeys,
    recipient: &str,
    content: &str,
    now_secs: u64,
) -> Result<NostrEvent, String> {
    let encrypted = nip04_encrypt(keys, recipient, content)?;
    let mut event = NostrEvent::new(
        now_secs,
        KIND_NIP04_DM,
        vec![vec!["p".to_string(), recipient.to_string()]],
        encrypted,
    );
    event.sign(keys)?;
    Ok(event)
}

fn build_nip17_event(
    keys: &NostrKeys,
    recipient: &str,
    content: &str,
    now_secs: u64,
) -> Result<NostrEvent, String> {
    let mut rumor = NostrEvent::new(
        now_secs,
        KIND_NIP17_DM,
        vec![vec!["p".to_string(), recipient.to_string()]],
        content.to_string(),
    );
    rumor.set_rumor_id(keys)?;
    let rumor_json = serde_json::to_string(&rumor)
        .map_err(|error| format!("failed to encode NIP-17 rumor: {error}"))?;

    let mut seal = NostrEvent::new(
        random_past_timestamp(now_secs)?,
        KIND_SEAL,
        Vec::new(),
        nip44_encrypt(keys, recipient, &rumor_json)?,
    );
    seal.sign(keys)?;
    let seal_json = serde_json::to_string(&seal)
        .map_err(|error| format!("failed to encode NIP-59 seal: {error}"))?;

    let ephemeral_keys = NostrKeys::generate()?;
    let mut gift_wrap = NostrEvent::new(
        random_past_timestamp(now_secs)?,
        KIND_GIFT_WRAP,
        vec![vec!["p".to_string(), recipient.to_string()]],
        nip44_encrypt(&ephemeral_keys, recipient, &seal_json)?,
    );
    gift_wrap.sign(&ephemeral_keys)?;
    Ok(gift_wrap)
}

pub fn build_relay_auth_event(
    keys: &NostrKeys,
    relay_url: &str,
    challenge: &str,
    now_secs: u64,
) -> Result<NostrEvent, String> {
    if challenge.is_empty() {
        return Err("NIP-42 auth challenge cannot be empty".to_string());
    }
    let mut event = NostrEvent::new(
        now_secs,
        KIND_RELAY_AUTH,
        vec![
            vec!["relay".to_string(), relay_url.to_string()],
            vec!["challenge".to_string(), challenge.to_string()],
        ],
        String::new(),
    );
    event.sign(keys)?;
    Ok(event)
}

pub fn build_event_frame(event: &NostrEvent) -> Result<String, String> {
    serde_json::to_string(&json!(["EVENT", event]))
        .map_err(|error| format!("failed to encode Nostr EVENT frame: {error}"))
}

pub fn build_auth_frame(event: &NostrEvent) -> Result<String, String> {
    serde_json::to_string(&json!(["AUTH", event]))
        .map_err(|error| format!("failed to encode Nostr AUTH frame: {error}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMessage {
    Event {
        subscription_id: String,
        event: NostrEvent,
    },
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    Auth {
        challenge: String,
    },
    Closed {
        subscription_id: String,
        message: String,
    },
    Other,
}

pub fn decode_relay_message(frame: &str) -> Result<RelayMessage, String> {
    if frame.len() > MAX_RELAY_FRAME_BYTES {
        return Err(format!(
            "Nostr relay frame exceeds {MAX_RELAY_FRAME_BYTES} bytes"
        ));
    }
    let value: Value = serde_json::from_str(frame)
        .map_err(|error| format!("invalid Nostr relay JSON: {error}"))?;
    let values = value
        .as_array()
        .ok_or_else(|| "Nostr relay frame must be a JSON array".to_string())?;
    let tag = values.first().and_then(Value::as_str).unwrap_or_default();
    match tag {
        "EVENT" => {
            let subscription_id = values
                .get(1)
                .and_then(Value::as_str)
                .ok_or_else(|| "Nostr EVENT frame is missing subscription id".to_string())?;
            let event = values
                .get(2)
                .cloned()
                .ok_or_else(|| "Nostr EVENT frame is missing event".to_string())?;
            let event = serde_json::from_value(event)
                .map_err(|error| format!("invalid Nostr event: {error}"))?;
            Ok(RelayMessage::Event {
                subscription_id: subscription_id.to_string(),
                event,
            })
        }
        "OK" => Ok(RelayMessage::Ok {
            event_id: values
                .get(1)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            accepted: values.get(2).and_then(Value::as_bool).unwrap_or(false),
            message: values
                .get(3)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }),
        "AUTH" => Ok(RelayMessage::Auth {
            challenge: values
                .get(1)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }),
        "CLOSED" => Ok(RelayMessage::Closed {
            subscription_id: values
                .get(1)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            message: values
                .get(2)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }),
        _ => Ok(RelayMessage::Other),
    }
}

fn nip04_encrypt(keys: &NostrKeys, peer: &str, plaintext: &str) -> Result<String, String> {
    let shared_x = keys.shared_x(peer)?;
    let mut iv = [0_u8; 16];
    fill_random(&mut iv)?;
    let ciphertext = Aes256CbcEncryptor::new(&shared_x.into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());
    Ok(format!(
        "{}?iv={}",
        BASE64.encode(ciphertext),
        BASE64.encode(iv)
    ))
}

fn nip04_decrypt(keys: &NostrKeys, peer: &str, payload: &str) -> Result<String, String> {
    if payload.len() > MAX_BASE64_PAYLOAD_BYTES {
        return Err("NIP-04 payload exceeds the plugin size limit".to_string());
    }
    let (ciphertext, iv) = payload
        .split_once("?iv=")
        .ok_or_else(|| "invalid NIP-04 payload format".to_string())?;
    let ciphertext = BASE64
        .decode(ciphertext)
        .map_err(|_| "invalid NIP-04 ciphertext base64".to_string())?;
    let iv = BASE64
        .decode(iv)
        .map_err(|_| "invalid NIP-04 IV base64".to_string())?;
    let iv: [u8; 16] = iv
        .try_into()
        .map_err(|_| "NIP-04 IV must be 16 bytes".to_string())?;
    let shared_x = keys.shared_x(peer)?;
    let plaintext = Aes256CbcDecryptor::new(&shared_x.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|_| "NIP-04 decryption or padding validation failed".to_string())?;
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err("NIP-04 plaintext exceeds the plugin size limit".to_string());
    }
    String::from_utf8(plaintext).map_err(|_| "NIP-04 plaintext is not UTF-8".to_string())
}

fn nip44_conversation_key(keys: &NostrKeys, peer: &str) -> Result<[u8; 32], String> {
    let shared_x = keys.shared_x(peer)?;
    let (pseudorandom_key, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), &shared_x);
    let mut conversation_key = [0_u8; 32];
    conversation_key.copy_from_slice(&pseudorandom_key);
    Ok(conversation_key)
}

struct Nip44MessageKeys {
    chacha_key: [u8; 32],
    chacha_nonce: [u8; 12],
    hmac_key: [u8; 32],
}

fn nip44_message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8; NIP44_NONCE_BYTES],
) -> Result<Nip44MessageKeys, String> {
    let hkdf = Hkdf::<Sha256>::from_prk(conversation_key)
        .map_err(|_| "invalid NIP-44 conversation key".to_string())?;
    let mut output = [0_u8; 76];
    hkdf.expand(nonce, &mut output)
        .map_err(|_| "failed to derive NIP-44 message keys".to_string())?;
    let mut chacha_key = [0_u8; 32];
    chacha_key.copy_from_slice(&output[..32]);
    let mut chacha_nonce = [0_u8; 12];
    chacha_nonce.copy_from_slice(&output[32..44]);
    let mut hmac_key = [0_u8; 32];
    hmac_key.copy_from_slice(&output[44..]);
    Ok(Nip44MessageKeys {
        chacha_key,
        chacha_nonce,
        hmac_key,
    })
}

fn nip44_encrypt(keys: &NostrKeys, peer: &str, plaintext: &str) -> Result<String, String> {
    let conversation_key = nip44_conversation_key(keys, peer)?;
    let mut nonce = [0_u8; NIP44_NONCE_BYTES];
    fill_random(&mut nonce)?;
    nip44_encrypt_with_nonce(plaintext, &conversation_key, nonce)
}

fn nip44_encrypt_with_nonce(
    plaintext: &str,
    conversation_key: &[u8; 32],
    nonce: [u8; NIP44_NONCE_BYTES],
) -> Result<String, String> {
    let keys = nip44_message_keys(conversation_key, &nonce)?;
    let mut ciphertext = nip44_pad(plaintext.as_bytes())?;
    let mut cipher = ChaCha20::new(&keys.chacha_key.into(), &keys.chacha_nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&keys.hmac_key)
        .map_err(|_| "failed to initialize NIP-44 HMAC".to_string())?;
    mac.update(&nonce);
    mac.update(&ciphertext);
    let mac = mac.finalize().into_bytes();

    let mut payload = Vec::with_capacity(1 + nonce.len() + ciphertext.len() + mac.len());
    payload.push(NIP44_VERSION);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&mac);
    Ok(BASE64.encode(payload))
}

fn nip44_decrypt(keys: &NostrKeys, peer: &str, payload: &str) -> Result<String, String> {
    if payload.starts_with('#') {
        return Err("unsupported non-base64 NIP-44 payload version".to_string());
    }
    if payload.len() < NIP44_MIN_BASE64_BYTES || payload.len() > MAX_BASE64_PAYLOAD_BYTES {
        return Err("invalid NIP-44 payload size".to_string());
    }
    let decoded = BASE64
        .decode(payload)
        .map_err(|_| "invalid NIP-44 payload base64".to_string())?;
    if decoded.len() < NIP44_MIN_DECODED_BYTES {
        return Err("decoded NIP-44 payload is too short".to_string());
    }
    if decoded[0] != NIP44_VERSION {
        return Err(format!("unsupported NIP-44 version {}", decoded[0]));
    }

    let nonce: [u8; NIP44_NONCE_BYTES] = decoded[1..1 + NIP44_NONCE_BYTES]
        .try_into()
        .map_err(|_| "invalid NIP-44 nonce".to_string())?;
    let mac_start = decoded
        .len()
        .checked_sub(NIP44_MAC_BYTES)
        .ok_or_else(|| "invalid NIP-44 payload boundaries".to_string())?;
    let ciphertext = &decoded[1 + NIP44_NONCE_BYTES..mac_start];
    let transmitted_mac = &decoded[mac_start..];

    let conversation_key = nip44_conversation_key(keys, peer)?;
    let keys = nip44_message_keys(&conversation_key, &nonce)?;
    let mut verifier = <HmacSha256 as Mac>::new_from_slice(&keys.hmac_key)
        .map_err(|_| "failed to initialize NIP-44 HMAC".to_string())?;
    verifier.update(&nonce);
    verifier.update(ciphertext);
    verifier
        .verify_slice(transmitted_mac)
        .map_err(|_| "NIP-44 MAC verification failed".to_string())?;

    let mut padded = ciphertext.to_vec();
    let mut cipher = ChaCha20::new(&keys.chacha_key.into(), &keys.chacha_nonce.into());
    cipher.apply_keystream(&mut padded);
    let plaintext = nip44_unpad(&padded)?;
    String::from_utf8(plaintext).map_err(|_| "NIP-44 plaintext is not UTF-8".to_string())
}

fn nip44_pad(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let length = plaintext.len();
    if length == 0 || length > MAX_PLAINTEXT_BYTES {
        return Err(format!(
            "NIP-44 plaintext length must be between 1 and {MAX_PLAINTEXT_BYTES} bytes"
        ));
    }
    let padded_length = nip44_padded_length(length)?;
    let prefix_length = if length < NIP44_EXTENDED_PREFIX_THRESHOLD {
        2
    } else {
        6
    };
    let mut output = vec![0_u8; prefix_length + padded_length];
    if prefix_length == 2 {
        let encoded = u16::try_from(length)
            .map_err(|_| "NIP-44 short length did not fit u16".to_string())?
            .to_be_bytes();
        output[..2].copy_from_slice(&encoded);
    } else {
        let encoded = u32::try_from(length)
            .map_err(|_| "NIP-44 extended length did not fit u32".to_string())?
            .to_be_bytes();
        output[2..6].copy_from_slice(&encoded);
    }
    output[prefix_length..prefix_length + length].copy_from_slice(plaintext);
    Ok(output)
}

fn nip44_unpad(padded: &[u8]) -> Result<Vec<u8>, String> {
    if padded.len() < 2 {
        return Err("NIP-44 padded plaintext is too short".to_string());
    }
    let short_length = usize::from(u16::from_be_bytes([padded[0], padded[1]]));
    let (prefix_length, plaintext_length): (usize, usize) = if short_length == 0 {
        if padded.len() < 6 {
            return Err("NIP-44 extended length prefix is truncated".to_string());
        }
        let extended = u32::from_be_bytes([padded[2], padded[3], padded[4], padded[5]]);
        let extended = usize::try_from(extended)
            .map_err(|_| "NIP-44 extended length does not fit this platform".to_string())?;
        if extended < NIP44_EXTENDED_PREFIX_THRESHOLD {
            return Err("NIP-44 extended length is below its threshold".to_string());
        }
        (6, extended)
    } else {
        (2, short_length)
    };
    if plaintext_length == 0 || plaintext_length > MAX_PLAINTEXT_BYTES {
        return Err("NIP-44 plaintext length is outside the plugin limit".to_string());
    }
    let expected = prefix_length
        .checked_add(nip44_padded_length(plaintext_length)?)
        .ok_or_else(|| "NIP-44 padded length overflow".to_string())?;
    if padded.len() != expected {
        return Err("NIP-44 padding length is invalid".to_string());
    }
    let end = prefix_length
        .checked_add(plaintext_length)
        .ok_or_else(|| "NIP-44 plaintext boundary overflow".to_string())?;
    if padded[end..].iter().any(|byte| *byte != 0) {
        return Err("NIP-44 padding contains non-zero bytes".to_string());
    }
    Ok(padded[prefix_length..end].to_vec())
}

fn nip44_padded_length(unpadded_length: usize) -> Result<usize, String> {
    if unpadded_length == 0 || unpadded_length > MAX_PLAINTEXT_BYTES {
        return Err("NIP-44 plaintext length is outside the plugin limit".to_string());
    }
    if unpadded_length <= 32 {
        return Ok(32);
    }
    let next_power = unpadded_length
        .checked_next_power_of_two()
        .ok_or_else(|| "NIP-44 padding power overflow".to_string())?;
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    let chunks = unpadded_length
        .checked_sub(1)
        .and_then(|value| value.checked_div(chunk))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| "NIP-44 padding chunk overflow".to_string())?;
    chunk
        .checked_mul(chunks)
        .ok_or_else(|| "NIP-44 padded length overflow".to_string())
}

fn random_past_timestamp(now_secs: u64) -> Result<u64, String> {
    let mut bytes = [0_u8; 8];
    fill_random(&mut bytes)?;
    let offset = u64::from_le_bytes(bytes) % TIMESTAMP_TWEAK_SECS;
    Ok(now_secs.saturating_sub(offset))
}

fn fill_random(output: &mut [u8]) -> Result<(), String> {
    getrandom::fill(output).map_err(|error| format!("secure random source failed: {error}"))
}

fn decode_bech32_key(value: &str, expected_hrp: &str) -> Result<[u8; 32], String> {
    let (hrp, bytes) =
        bech32::decode(value).map_err(|error| format!("invalid Nostr bech32 key: {error}"))?;
    if hrp.as_str() != expected_hrp {
        return Err(format!(
            "invalid Nostr bech32 key prefix `{}`; expected `{expected_hrp}`",
            hrp.as_str()
        ));
    }
    bytes
        .try_into()
        .map_err(|_| "Nostr bech32 key must contain 32 bytes".to_string())
}

fn parse_public_key(value: &str) -> Result<[u8; 32], String> {
    let normalized = value.trim();
    let bytes = if normalized.starts_with("npub1") {
        decode_bech32_key(normalized, "npub")?
    } else {
        decode_hex_array::<32>(
            normalized.strip_prefix("0x").unwrap_or(normalized),
            "public key",
        )?
    };
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| "Nostr public key is not a valid BIP-340 x-only key".to_string())?;
    Ok(bytes)
}

pub fn normalize_public_key(value: &str) -> Result<String, String> {
    Ok(hex::encode(parse_public_key(value)?))
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("Nostr {label} must be {} hex characters", N * 2));
    }
    let mut output = [0_u8; N];
    hex::decode_to_slice(value, &mut output)
        .map_err(|_| format!("Nostr {label} contains invalid hex"))?;
    Ok(output)
}

fn dedup_nonempty(values: Vec<String>) -> Vec<String> {
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let value = value.trim().to_string();
        if !value.is_empty() && !output.contains(&value) {
            output.push(value);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const BOB_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    fn keys(secret: &str) -> NostrKeys {
        NostrKeys::from_private_key(secret).unwrap()
    }

    #[test]
    fn config_uses_only_canonical_fields() {
        let config = NostrConfig::from_json(&format!(
            r#"{{"private_key":"{ALICE_SECRET}","relays":["wss://one","wss://one","wss://two"]}}"#
        ))
        .unwrap();
        assert_eq!(config.relays, vec!["wss://one", "wss://two"]);
        assert_eq!(
            config.keys.public_key(),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert!(NostrConfig::from_json(r#"{"private_key":""}"#).is_err());
        assert!(
            NostrConfig::from_json(&format!(r#"{{"private_key":"{ALICE_SECRET}"}}"#))
                .unwrap()
                .relays
                .is_empty()
        );
        assert!(NostrConfig::from_json(&format!(
            r#"{{"private_key":"{ALICE_SECRET}","relays":["https://not-ws"]}}"#
        ))
        .is_err());
    }

    #[test]
    fn parses_nsec_and_npub() {
        let key = NostrKeys::from_private_key(
            "nsec14xfqzxvqxql233plvcy8vdpgxqnww7tw0l823dshzq3eux0w9ryqulcv53",
        )
        .unwrap();
        assert_eq!(
            key.public_key(),
            "689403d3808274889e371cfe53c2d78eb05743a964cc60d3b2e55824e8fe740a"
        );
        let npub = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("npub").unwrap(),
            &parse_public_key(&key.public_key()).unwrap(),
        )
        .unwrap();
        assert_eq!(normalize_public_key(&npub).unwrap(), key.public_key());
    }

    #[test]
    fn subscription_is_private_dm_only() {
        let config = NostrConfig::from_json(&format!(
            r#"{{"private_key":"{ALICE_SECRET}","relays":["wss://relay"]}}"#
        ))
        .unwrap();
        let frame: Value = serde_json::from_str(&config.subscription_frame().unwrap()).unwrap();
        assert_eq!(frame[0], json!("REQ"));
        assert_eq!(frame[1], json!(SUBSCRIPTION_ID));
        assert_eq!(frame[2]["kinds"], json!([4, 1059]));
        assert_eq!(frame[2]["#p"], json!([config.keys.public_key()]));
    }

    #[test]
    fn nip44_matches_official_vector() {
        let alice = keys(ALICE_SECRET);
        let bob = keys(BOB_SECRET);
        let conversation_key = nip44_conversation_key(&alice, &bob.public_key()).unwrap();
        assert_eq!(
            hex::encode(conversation_key),
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
        );
        let mut nonce = [0_u8; 32];
        nonce[31] = 1;
        let payload = nip44_encrypt_with_nonce("a", &conversation_key, nonce).unwrap();
        assert_eq!(
            payload,
            "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"
        );
        assert_eq!(
            nip44_decrypt(&bob, &alice.public_key(), &payload).unwrap(),
            "a"
        );
    }

    #[test]
    fn nip44_rejects_tampered_mac() {
        let alice = keys(ALICE_SECRET);
        let bob = keys(BOB_SECRET);
        let payload = nip44_encrypt(&alice, &bob.public_key(), "secret").unwrap();
        let mut decoded = BASE64.decode(payload).unwrap();
        let last = decoded.len() - 1;
        decoded[last] ^= 1;
        let tampered = BASE64.encode(decoded);
        assert!(nip44_decrypt(&bob, &alice.public_key(), &tampered).is_err());
    }

    #[test]
    fn nip44_extended_padding_boundaries_match_spec() {
        assert_eq!(nip44_padded_length(65_535).unwrap(), 65_536);
        assert_eq!(nip44_padded_length(65_536).unwrap(), 65_536);
        assert_eq!(nip44_padded_length(65_537).unwrap(), 81_920);
        let text = "a".repeat(65_536);
        let padded = nip44_pad(text.as_bytes()).unwrap();
        assert_eq!(&padded[..2], &[0, 0]);
        assert_eq!(&padded[2..6], &(65_536_u32.to_be_bytes()));
        assert_eq!(nip44_unpad(&padded).unwrap(), text.as_bytes());
    }

    #[test]
    fn nip04_round_trip_is_signed_and_decrypted() {
        let alice = keys(ALICE_SECRET);
        let bob = keys(BOB_SECRET);
        let event = build_direct_message(
            &alice,
            &bob.public_key(),
            "legacy hello",
            DmProtocol::Nip04,
            1_700_000_000,
        )
        .unwrap();
        event.verify_signed().unwrap();
        let decoded = decode_direct_message(&bob, &event, 1_699_999_999)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.sender, alice.public_key());
        assert_eq!(decoded.content, "legacy hello");
        assert_eq!(decoded.protocol, DmProtocol::Nip04);
    }

    #[test]
    fn nip17_round_trip_validates_both_wrappers() {
        let alice = keys(ALICE_SECRET);
        let bob = keys(BOB_SECRET);
        let event = build_direct_message(
            &alice,
            &bob.public_key(),
            "gift wrapped hello",
            DmProtocol::Nip17,
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(event.kind, KIND_GIFT_WRAP);
        event.verify_signed().unwrap();
        let decoded = decode_direct_message(&bob, &event, 1_699_999_999)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.sender, alice.public_key());
        assert_eq!(decoded.content, "gift wrapped hello");
        assert_eq!(decoded.protocol, DmProtocol::Nip17);
        assert_eq!(decoded.timestamp_ms, 1_700_000_000_000);
    }

    #[test]
    fn old_or_self_messages_are_not_emitted() {
        let alice = keys(ALICE_SECRET);
        let bob = keys(BOB_SECRET);
        let old =
            build_direct_message(&alice, &bob.public_key(), "old", DmProtocol::Nip04, 10).unwrap();
        assert!(decode_direct_message(&bob, &old, 11).unwrap().is_none());
        let own =
            build_direct_message(&bob, &bob.public_key(), "self", DmProtocol::Nip04, 12).unwrap();
        assert!(decode_direct_message(&bob, &own, 11).unwrap().is_none());
    }

    #[test]
    fn event_tampering_is_detected_before_decryption() {
        let alice = keys(ALICE_SECRET);
        let bob = keys(BOB_SECRET);
        let mut event = build_direct_message(
            &alice,
            &bob.public_key(),
            "authentic",
            DmProtocol::Nip04,
            100,
        )
        .unwrap();
        event.content.push('x');
        assert!(decode_direct_message(&bob, &event, 0).is_err());
    }

    #[test]
    fn relay_auth_event_is_signed_and_scoped() {
        let alice = keys(ALICE_SECRET);
        let event = build_relay_auth_event(&alice, "wss://relay.example", "challenge", 42).unwrap();
        event.verify_signed().unwrap();
        assert_eq!(event.kind, KIND_RELAY_AUTH);
        assert!(event.tags.contains(&vec![
            "relay".to_string(),
            "wss://relay.example".to_string()
        ]));
        assert!(event
            .tags
            .contains(&vec!["challenge".to_string(), "challenge".to_string()]));
    }

    #[test]
    fn relay_frames_decode_without_treating_controls_as_messages() {
        let alice = keys(ALICE_SECRET);
        let bob = keys(BOB_SECRET);
        let event =
            build_direct_message(&alice, &bob.public_key(), "hello", DmProtocol::Nip04, 100)
                .unwrap();
        let frame = serde_json::to_string(&json!(["EVENT", SUBSCRIPTION_ID, event])).unwrap();
        assert!(matches!(
            decode_relay_message(&frame).unwrap(),
            RelayMessage::Event { .. }
        ));
        assert!(matches!(
            decode_relay_message(r#"["AUTH","challenge"]"#).unwrap(),
            RelayMessage::Auth { .. }
        ));
        assert!(matches!(
            decode_relay_message(r#"["EOSE","zeroclaw-dms"]"#).unwrap(),
            RelayMessage::Other
        ));
    }
}
