//! LSP/1 framing and closed request metadata validation.

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

pub const TA_UUID: &str = "c86d23b9-e568-509e-a9b2-0ad40668caf5";
pub const CMD_EXCHANGE: u32 = 0x1000;
pub const GP_PARAM_TYPES: u32 = 0x0265;
pub const HEADER_BYTES: usize = 64;
pub const LEGACY_INPUT_FRAME_MAX: usize = 16384;
pub const INPUT_FRAME_MAX: usize = 61440;
pub const OUTPUT_FRAME_MAX: usize = 32768;
pub const METADATA_MAX: usize = 4096;
pub const MAX_JSON_DEPTH: usize = 8;
pub const HELLO: u16 = 0x0001;
pub const CREDENTIAL_PUT: u16 = 0x0010;
pub const CREDENTIAL_QUERY: u16 = 0x0011;
pub const CREDENTIAL_DELETE: u16 = 0x0012;
pub const REQUEST_OPEN: u16 = 0x0100;
pub const BODY_CHUNK: u16 = 0x0101;
pub const BODY_COMMIT: u16 = 0x0102;
pub const STEP: u16 = 0x0103;
pub const FINISH: u16 = 0x0104;
pub const CANCEL: u16 = 0x0105;
pub const STATUS: u16 = 0x0106;
pub const OK: u32 = 0;
pub const E_OUTPUT_CAPACITY: u32 = 0x1001;
pub const E_WIRE_FORMAT: u32 = 0x1002;
pub const E_VERSION: u32 = 0x1003;
pub const E_ROLE: u32 = 0x1004;
pub const E_STATE: u32 = 0x1101;
pub const E_STALE_EPOCH: u32 = 0x1102;
pub const E_SEQUENCE: u32 = 0x1103;
pub const E_REQUEST_ID: u32 = 0x1104;
pub const E_CREDENTIAL_NOT_FOUND: u32 = 0x1201;
pub const E_VERSION_CONFLICT: u32 = 0x1202;
pub const E_OPERATION_CONFLICT: u32 = 0x1203;
pub const E_PROFILE_DENIED: u32 = 0x1204;
pub const E_STORAGE: u32 = 0x1205;
pub const E_CREDENTIAL_REVOKED: u32 = 0x1206;
pub const E_STORAGE_NOT_COMMITTED: u32 = 0x1207;
pub const E_BUSY: u32 = 0x1301;
pub const E_LIMIT: u32 = 0x1302;
pub const E_BODY_LENGTH: u32 = 0x1303;
pub const E_BODY_OFFSET: u32 = 0x1304;
pub const E_BODY_DIGEST: u32 = 0x1305;
pub const E_TLS: u32 = 0x1401;
pub const E_HTTP_PARSE: u32 = 0x1402;
pub const E_NETWORK: u32 = 0x1403;
pub const E_DEADLINE: u32 = 0x1404;
pub const E_HTTP_LIMIT: u32 = 0x1405;
pub const E_INTERNAL: u32 = 0x1fff;

#[derive(Clone, Debug, PartialEq)]
pub struct Frame {
    pub opcode: u16,
    pub request_id: [u8; 16],
    pub call_seq: u64,
    pub status: u32,
    pub metadata: Value,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireError {
    pub status: u32,
    pub detail: &'static str,
}

impl WireError {
    fn new(status: u32, detail: &'static str) -> Self {
        Self { status, detail }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.detail)
    }
}

impl std::error::Error for WireError {}

fn invalid(detail: &'static str) -> WireError {
    WireError::new(E_WIRE_FORMAT, detail)
}

impl Frame {
    pub fn decode_request(bytes: &[u8]) -> Result<Self, WireError> {
        if !(HEADER_BYTES..=INPUT_FRAME_MAX).contains(&bytes.len()) {
            return Err(invalid("input frame length"));
        }
        let u16_at = |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
        let u32_at = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let u64_at = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        if &bytes[..4] != b"LSP1" {
            return Err(invalid("frame magic"));
        }
        if u16_at(4) != 1 || u16_at(6) != 0 {
            return Err(WireError::new(E_VERSION, "unsupported frame version"));
        }
        if u16_at(10) != 0 || u16_at(12) != 64 || u16_at(14) != 0 || u64_at(56) != 0 {
            return Err(invalid("flags, header length or reserved fields"));
        }
        let meta_len = u32_at(20) as usize;
        let payload_len = u32_at(52) as usize;
        if u32_at(16) as usize != bytes.len()
            || meta_len > METADATA_MAX
            || HEADER_BYTES
                .checked_add(meta_len)
                .and_then(|n| n.checked_add(payload_len))
                != Some(bytes.len())
            || u32_at(48) != OK
        {
            return Err(invalid("frame lengths or request status"));
        }
        let opcode = u16_at(8);
        if !known_opcode(opcode) {
            return Err(invalid("unknown opcode"));
        }
        let request_id = bytes[24..40].try_into().unwrap();
        let management = matches!(
            opcode,
            HELLO | CREDENTIAL_PUT | CREDENTIAL_QUERY | CREDENTIAL_DELETE
        );
        if management != (request_id == [0; 16]) {
            return Err(WireError::new(
                E_REQUEST_ID,
                "request ID does not match channel",
            ));
        }
        let call_seq = u64_at(40);
        if call_seq == 0 {
            return Err(WireError::new(
                E_SEQUENCE,
                "call sequence must start at one",
            ));
        }
        let frame = Self {
            opcode,
            request_id,
            call_seq,
            status: OK,
            metadata: strict_json(&bytes[HEADER_BYTES..HEADER_BYTES + meta_len])?,
            payload: bytes[HEADER_BYTES + meta_len..].to_vec(),
        };
        validate_request_metadata(&frame)?;
        Ok(frame)
    }

    pub fn encode_reply(&self) -> Result<Vec<u8>, WireError> {
        self.encode(1, OUTPUT_FRAME_MAX)
    }

    pub fn encode_request(&self) -> Result<Vec<u8>, WireError> {
        let management = matches!(
            self.opcode,
            HELLO | CREDENTIAL_PUT | CREDENTIAL_QUERY | CREDENTIAL_DELETE
        );
        if management != (self.request_id == [0; 16]) {
            return Err(WireError::new(E_REQUEST_ID, "request ID does not match channel"));
        }
        if self.status != OK {
            return Err(invalid("request status"));
        }
        validate_request_metadata(self)?;
        self.encode(0, INPUT_FRAME_MAX)
    }

    fn encode(&self, flags: u16, frame_limit: usize) -> Result<Vec<u8>, WireError> {
        if !known_opcode(self.opcode) || self.call_seq == 0 || !self.metadata.is_object() {
            return Err(invalid("frame opcode, sequence or metadata"));
        }
        let metadata =
            serde_json::to_vec(&self.metadata).map_err(|_| invalid("frame JSON encoding"))?;
        if metadata.len() > METADATA_MAX {
            return Err(invalid("frame metadata limit"));
        }
        // Revalidate recursively so locally constructed floats/deep objects cannot escape.
        strict_json(&metadata)?;
        let frame_len = HEADER_BYTES + metadata.len() + self.payload.len();
        if frame_len > frame_limit {
            return Err(invalid("frame limit"));
        }
        let mut bytes = vec![0; HEADER_BYTES];
        bytes[..4].copy_from_slice(b"LSP1");
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.opcode.to_le_bytes());
        bytes[10..12].copy_from_slice(&flags.to_le_bytes());
        bytes[12..14].copy_from_slice(&64u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&(frame_len as u32).to_le_bytes());
        bytes[20..24].copy_from_slice(&(metadata.len() as u32).to_le_bytes());
        bytes[24..40].copy_from_slice(&self.request_id);
        bytes[40..48].copy_from_slice(&self.call_seq.to_le_bytes());
        bytes[48..52].copy_from_slice(&self.status.to_le_bytes());
        bytes[52..56].copy_from_slice(&(self.payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&metadata);
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }
}

fn known_opcode(opcode: u16) -> bool {
    matches!(
        opcode,
        HELLO
            | CREDENTIAL_PUT
            | CREDENTIAL_QUERY
            | CREDENTIAL_DELETE
            | REQUEST_OPEN
            | BODY_CHUNK
            | BODY_COMMIT
            | STEP
            | FINISH
            | CANCEL
            | STATUS
    )
}

/// Strict JSON parser shared with the persistent snapshot decoder.
/// Parser errors are deliberately generic, avoiding metadata/key disclosure.
pub(crate) fn strict_json(bytes: &[u8]) -> Result<Value, WireError> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue { depth: 0 }
        .deserialize(&mut decoder)
        .map_err(|_| invalid("invalid strict JSON"))?;
    decoder.end().map_err(|_| invalid("trailing JSON data"))?;
    if !value.is_object() {
        return Err(invalid("JSON root must be object"));
    }
    Ok(value)
}

struct StrictValue {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for StrictValue {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded JSON with unique keys and unsigned integers")
    }

    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        if v > u32::MAX as u64 {
            return Err(E::custom("integer range"));
        }
        Ok(Value::Number(v.into()))
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Value, E> {
        Err(E::custom("signed integer"))
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Value, E> {
        Err(E::custom("floating point"))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(A::Error::custom("JSON depth"));
        }
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValue {
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(A::Error::custom("JSON depth"));
        }
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate key"));
            }
            let value = map.next_value_seed(StrictValue {
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

pub(crate) fn text<'a>(object: &'a Value, name: &str) -> Result<&'a str, WireError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("missing or invalid string"))
}

pub(crate) fn u64_string(object: &Value, name: &str) -> Result<u64, WireError> {
    let value = text(object, name)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid("non-canonical u64 string"));
    }
    value.parse().map_err(|_| invalid("u64 overflow"))
}

pub(crate) fn identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub(crate) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn u32_field(object: &Value, name: &str, positive: bool) -> Result<u32, WireError> {
    let value = object
        .get(name)
        .and_then(Value::as_u64)
        .filter(|v| *v <= u32::MAX as u64)
        .ok_or_else(|| invalid("invalid u32 field"))? as u32;
    if positive && value == 0 {
        return Err(invalid("zero positive field"));
    }
    Ok(value)
}

fn choice<'a>(object: &'a Value, name: &str, allowed: &[&str]) -> Result<&'a str, WireError> {
    let value = text(object, name)?;
    if !allowed.contains(&value) {
        return Err(invalid("unknown enum value"));
    }
    Ok(value)
}

fn closed(object: &Value, required: &[&str], optional: &[&str]) -> Result<(), WireError> {
    let map = object
        .as_object()
        .ok_or_else(|| invalid("object required"))?;
    if required.iter().any(|key| !map.contains_key(*key))
        || map
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(invalid("missing or unknown field"));
    }
    Ok(())
}

pub fn validate_request_metadata(frame: &Frame) -> Result<(), WireError> {
    let m = &frame.metadata;
    let (required, optional): (&[&str], &[&str]) = match frame.opcode {
        HELLO => (&["role", "supported_versions"], &["client_name"]),
        CREDENTIAL_PUT => (
            &[
                "ta_epoch",
                "session_nonce",
                "operation_id",
                "credential_ref",
                "namespace",
                "profile_id",
                "expected_version",
            ],
            &["temporary", "ttl_ms", "provider_config", "reuse_existing_key"],
        ),
        CREDENTIAL_QUERY => (
            &["ta_epoch", "session_nonce", "credential_ref", "namespace"],
            &[],
        ),
        CREDENTIAL_DELETE => (
            &[
                "ta_epoch",
                "session_nonce",
                "operation_id",
                "credential_ref",
                "namespace",
                "expected_version",
            ],
            &[],
        ),
        REQUEST_OPEN => (
            &[
                "ta_epoch",
                "session_nonce",
                "namespace",
                "profile_id",
                "credential_ref",
                "expected_version",
                "operation",
                "body_length",
                "overall_timeout_ms",
                "response_mode",
                "completion_policy",
            ],
            &["headers", "remaining_ms", "model_id"],
        ),
        BODY_CHUNK => (
            &["ta_epoch", "session_nonce", "body_offset"],
            &["remaining_ms"],
        ),
        BODY_COMMIT => (
            &[
                "ta_epoch",
                "session_nonce",
                "body_sha256",
                "net_tx_credit",
                "app_rx_credit",
            ],
            &["remaining_ms"],
        ),
        STEP => (
            &[
                "ta_epoch",
                "session_nonce",
                "input_kind",
                "tls_rx_offset",
                "net_tx_credit",
                "app_rx_credit",
            ],
            &["remaining_ms", "network_error_code"],
        ),
        FINISH | CANCEL => (&["ta_epoch", "session_nonce", "reason"], &["remaining_ms"]),
        STATUS => (&["ta_epoch", "session_nonce"], &["remaining_ms"]),
        _ => return Err(invalid("unknown opcode")),
    };
    closed(m, required, optional)?;
    for name in [
        "ta_epoch",
        "session_nonce",
        "operation_id",
        "credential_ref",
    ] {
        if m.get(name).is_some() && !hex(text(m, name)?, 32) {
            return Err(invalid("invalid 128 bit identifier"));
        }
    }
    for name in ["namespace", "profile_id"] {
        if m.get(name).is_some() && !identifier(text(m, name)?) {
            return Err(invalid("invalid ASCII identifier"));
        }
    }
    for name in [
        "expected_version",
        "body_length",
        "body_offset",
        "tls_rx_offset",
    ] {
        if m.get(name).is_some() {
            u64_string(m, name)?;
        }
    }
    for name in ["remaining_ms", "net_tx_credit", "app_rx_credit"] {
        if m.get(name).is_some() {
            u32_field(m, name, false)?;
        }
    }
    let permits_payload = matches!(frame.opcode, CREDENTIAL_PUT | BODY_CHUNK)
        || (frame.opcode == STEP && m["input_kind"] == "tls_rx");
    if permits_payload == frame.payload.is_empty() {
        return Err(invalid("opcode payload requirement"));
    }
    match frame.opcode {
        HELLO => {
            choice(m, "role", &["request", "management"])?;
            let versions = m["supported_versions"]
                .as_array()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| invalid("supported_versions"))?;
            let mut unique = std::collections::BTreeSet::new();
            for version in versions {
                closed(version, &["major", "minor"], &[])?;
                let major = u32_field(version, "major", true)?;
                let minor = u32_field(version, "minor", false)?;
                if major > u16::MAX as u32
                    || minor > u16::MAX as u32
                    || !unique.insert((major, minor))
                {
                    return Err(invalid("version range or duplicate"));
                }
            }
            if m.get("client_name").is_some() && text(m, "client_name")?.len() > 64 {
                return Err(invalid("client name limit"));
            }
        }
        CREDENTIAL_PUT => {
            if let Some(reuse) = m.get("reuse_existing_key") {
                let reuse = reuse.as_bool().ok_or_else(|| invalid("key reuse type"))?;
                if reuse && !frame.payload.is_empty() { return Err(invalid("key reuse payload")); }
            }
            if let Some(config) = m.get("provider_config") {
                closed(config, &["provider_type", "base_url"], &[])?;
                choice(
                    config,
                    "provider_type",
                    &[
                        "openai_compatible",
                        "openai_responses",
                        "anthropic_messages",
                        "google_gemini",
                        "ollama_native",
                    ],
                )?;
                if text(config, "base_url")?.len() > 1024 {
                    return Err(invalid("provider base URL limit"));
                }
            }
            let temporary = match m.get("temporary") {
                None => false,
                Some(v) => v.as_bool().ok_or_else(|| invalid("temporary type"))?,
            };
            if temporary {
                u32_field(m, "ttl_ms", true)?;
            } else if m.get("ttl_ms").is_some() {
                return Err(invalid("permanent TTL"));
            }
            if frame.payload.len() > 4096
                || std::str::from_utf8(&frame.payload).is_err()
                || frame.payload.iter().any(|b| matches!(b, 0 | b'\r' | b'\n'))
            {
                return Err(invalid("credential payload"));
            }
        }
        REQUEST_OPEN => {
            let operation = choice(
                m,
                "operation",
                &[
                    "CHAT",
                    "RESPONSES",
                    "MESSAGES",
                    "GENERATE",
                    "OLLAMA_CHAT",
                    "MODELS",
                ],
            )?;
            let mode = choice(m, "response_mode", &["json", "sse", "ndjson"])?;
            let completion = choice(m, "completion_policy", &["HTTP_COMPLETE", "MODEL_TERMINAL"])?;
            u32_field(m, "overall_timeout_ms", true)?;
            if (operation == "GENERATE") != m.get("model_id").is_some()
                || m.get("model_id").is_some_and(|value| {
                    value
                        .as_str()
                        .is_none_or(|id| id.is_empty() || id.len() > 256)
                })
                || (mode == "ndjson" && operation != "OLLAMA_CHAT")
                || (operation == "OLLAMA_CHAT" && mode == "sse")
            {
                return Err(invalid("operation model or response mode"));
            }
            if (mode == "json" && completion != "HTTP_COMPLETE")
                || (operation == "MODELS"
                    && (u64_string(m, "body_length")? != 0
                        || mode != "json"
                        || completion != "HTTP_COMPLETE"))
            {
                return Err(invalid("operation completion policy"));
            }
            if let Some(headers) = m.get("headers") {
                let headers = headers
                    .as_array()
                    .filter(|h| h.len() <= 32)
                    .ok_or_else(|| invalid("headers count/type"))?;
                for header in headers {
                    closed(header, &["name", "value"], &[])?;
                    let name = text(header, "name")?;
                    let value = text(header, "value")?;
                    let lower = name.to_ascii_lowercase();
                    if name.is_empty()
                        || name.len() > 256
                        || !name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                        || [
                            "host",
                            "authorization",
                            "x-api-key",
                            "x-goog-api-key",
                            "anthropic-version",
                            "content-length",
                            "transfer-encoding",
                            "connection",
                        ]
                        .contains(&lower.as_str())
                        || lower.starts_with("proxy-")
                        || value.len() > 4096
                        || value.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n'))
                    {
                        return Err(invalid("invalid or reserved HTTP header"));
                    }
                }
            }
        }
        BODY_COMMIT => {
            if !hex(text(m, "body_sha256")?, 64) {
                return Err(invalid("body digest"));
            }
        }
        STEP => {
            let kind = choice(
                m,
                "input_kind",
                &["none", "tls_rx", "tcp_eof", "network_error"],
            )?;
            if kind == "network_error" {
                choice(
                    m,
                    "network_error_code",
                    &[
                        "dns_failed",
                        "connect_failed",
                        "connect_timeout",
                        "read_failed",
                        "write_failed",
                        "reset",
                        "idle_timeout",
                    ],
                )?;
            } else if m.get("network_error_code").is_some() {
                return Err(invalid("unexpected network error code"));
            }
        }
        FINISH => {
            choice(m, "reason", &["consumer_complete", "response_consumed"])?;
        }
        CANCEL => {
            choice(m, "reason", &["user", "caller_gone", "timeout", "shutdown"])?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hello_bytes(metadata: &[u8]) -> Vec<u8> {
        let frame = Frame {
            opcode: HELLO,
            request_id: [0; 16],
            call_seq: 1,
            status: 0,
            metadata: json!({}),
            payload: vec![],
        };
        let mut bytes = frame.encode_reply().unwrap();
        bytes.truncate(64);
        bytes[10..12].copy_from_slice(&0u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&((64 + metadata.len()) as u32).to_le_bytes());
        bytes[20..24].copy_from_slice(&(metadata.len() as u32).to_le_bytes());
        bytes.extend_from_slice(metadata);
        bytes
    }

    #[test]
    fn hello_and_little_endian_header() {
        let metadata = br#"{"role":"request","supported_versions":[{"major":1,"minor":0}]}"#;
        let bytes = hello_bytes(metadata);
        let frame = Frame::decode_request(&bytes).unwrap();
        assert_eq!(frame.opcode, HELLO);
        assert_eq!(frame.call_seq, 1);
        let reply = frame.encode_reply().unwrap();
        assert_eq!(&reply[10..12], &[1, 0]);
        assert_eq!(
            u32::from_le_bytes(reply[16..20].try_into().unwrap()) as usize,
            reply.len()
        );
    }

    #[test]
    fn strict_json_rejects_nested_duplicate_floats_and_depth() {
        for bytes in [
            br#"{"a":{"x":1,"x":2}}"#.as_slice(),
            br#"{"a":1.0}"#,
            br#"{"a":1e0}"#,
            br#"{"a":-0}"#,
            br#"{"a":4294967296}"#,
            br#"{"a":"\ud800"}"#,
            br#"{} {}"#,
        ] {
            assert!(strict_json(bytes).is_err());
        }
        assert!(strict_json(br#"{"a":[[[[[[[0]]]]]]]}"#).is_ok());
        assert!(strict_json(br#"{"a":[[[[[[[[0]]]]]]]]}"#).is_err());
        assert!(strict_json(b"{\"a\":\"\xff\"}").is_err());
    }

    #[test]
    fn rejects_reserved_trailing_and_unknown_metadata() {
        let valid = br#"{"role":"request","supported_versions":[{"major":1,"minor":0}]}"#;
        for index in [14, 56] {
            let mut bytes = hello_bytes(valid);
            bytes[index] = 1;
            assert_eq!(
                Frame::decode_request(&bytes).unwrap_err().status,
                E_WIRE_FORMAT
            );
        }
        let mut bytes = hello_bytes(valid);
        bytes.push(0);
        assert!(Frame::decode_request(&bytes).is_err());
        assert!(
            Frame::decode_request(&hello_bytes(
                br#"{"role":"request","supported_versions":[{"major":1,"minor":0,"extra":0}]}"#
            ))
            .is_err()
        );
    }

    #[test]
    fn metadata_scalars_and_payload_rules() {
        let mut frame = Frame {
            opcode: CREDENTIAL_PUT,
            request_id: [0; 16],
            call_seq: 2,
            status: 0,
            metadata: json!({"ta_epoch":"0".repeat(32),"session_nonce":"1".repeat(32),"operation_id":"2".repeat(32),"credential_ref":"3".repeat(32),"namespace":"test","profile_id":"deepseek-prod-v1","expected_version":"0"}),
            payload: b"fake-test-key".to_vec(),
        };
        assert!(validate_request_metadata(&frame).is_ok());
        frame.metadata["expected_version"] = json!("00");
        assert!(validate_request_metadata(&frame).is_err());
        frame.metadata["expected_version"] = json!("18446744073709551615");
        frame.metadata["temporary"] = json!(true);
        assert!(validate_request_metadata(&frame).is_err());
        frame.metadata["ttl_ms"] = json!(1);
        assert!(validate_request_metadata(&frame).is_ok());
        frame.payload.push(b'\n');
        assert!(validate_request_metadata(&frame).is_err());
    }

    fn fixture_request(value: &Value) -> Frame {
        let h = &value["header"];
        let mut request_id = [0; 16];
        for (index, byte) in request_id.iter_mut().enumerate() {
            let encoded = h["request_id"].as_str().unwrap();
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).unwrap();
        }
        let encoded = value["payload_hex"].as_str().unwrap();
        let payload = (0..encoded.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&encoded[index..index + 2], 16).unwrap())
            .collect();
        Frame {
            opcode: h["opcode"].as_u64().unwrap() as u16,
            request_id,
            call_seq: h["call_seq"].as_str().unwrap().parse().unwrap(),
            status: 0,
            metadata: value["metadata"].clone(),
            payload,
        }
    }

    #[test]
    fn all_shared_business_and_edge_requests_decode() {
        let business: Value = serde_json::from_str(include_str!(
            "../docs/contracts/lsp-v1-business-examples.json"
        ))
        .unwrap();
        let edges: Value =
            serde_json::from_str(include_str!("../docs/contracts/lsp-v1-edge-examples.json"))
                .unwrap();
        let mut requests = Vec::new();
        for trace in business["traces"].as_array().unwrap() {
            for step in trace["steps"].as_array().unwrap() {
                requests.push(&step["request"]);
            }
        }
        for case in edges["cases"].as_array().unwrap() {
            requests.push(&case["request"]);
        }
        assert!(requests.len() >= 30);
        for request in requests {
            let expected = fixture_request(request);
            let mut bytes = expected.encode_reply().unwrap();
            bytes[10..12].copy_from_slice(&0u16.to_le_bytes());
            assert_eq!(Frame::decode_request(&bytes).unwrap(), expected);
        }
    }

    #[test]
    fn exact_input_output_limits_and_header_request_id_order() {
        let mut frame = Frame {
            opcode: BODY_CHUNK,
            request_id: [0; 16],
            call_seq: 2,
            status: 0,
            metadata: json!({"ta_epoch":"0".repeat(32),"session_nonce":"1".repeat(32),"body_offset":"0"}),
            payload: vec![],
        };
        for (index, byte) in frame.request_id.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let metadata_len = serde_json::to_vec(&frame.metadata).unwrap().len();
        frame.payload = vec![0; INPUT_FRAME_MAX - HEADER_BYTES - metadata_len];
        let mut bytes = frame.encode_request().unwrap();
        assert_eq!(bytes.len(), INPUT_FRAME_MAX);
        assert_eq!(
            &bytes[24..40],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert!(Frame::decode_request(&bytes).is_ok());
        bytes.push(0);
        assert!(Frame::decode_request(&bytes).is_err());
        frame.payload = vec![0; OUTPUT_FRAME_MAX - HEADER_BYTES - metadata_len];
        assert_eq!(frame.encode_reply().unwrap().len(), OUTPUT_FRAME_MAX);
        frame.payload.push(0);
        assert!(frame.encode_reply().is_err());
    }

    #[test]
    fn bulk_input_maximum_offsets_and_legacy_frames_preserve_bytes() {
        use sha2::{Digest, Sha256};
        let mut frame = Frame {
            opcode: BODY_CHUNK,
            request_id: [1; 16],
            call_seq: u64::MAX,
            status: OK,
            metadata: json!({"ta_epoch":"f".repeat(32),"session_nonce":"e".repeat(32),
                "body_offset":u64::MAX.to_string(),"remaining_ms":u32::MAX}),
            payload: Vec::new(),
        };
        let metadata_bytes = serde_json::to_vec(&frame.metadata).unwrap().len();
        for frame_limit in [LEGACY_INPUT_FRAME_MAX, INPUT_FRAME_MAX] {
            frame.payload = (0..frame_limit - HEADER_BYTES - metadata_bytes)
                .map(|index| (index % 251) as u8)
                .collect();
            let encoded = frame.encode_request().unwrap();
            assert_eq!(encoded.len(), frame_limit);
            assert_eq!(encoded[4..8], [1, 0, 0, 0]);
            assert_eq!(encoded[10..12], [0, 0]);
            let decoded = Frame::decode_request(&encoded).unwrap();
            assert_eq!(decoded, frame);
            assert_eq!(Sha256::digest(&decoded.payload), Sha256::digest(&frame.payload));
            if frame_limit == LEGACY_INPUT_FRAME_MAX {
                // Reconstruct the byte-compatible pre-extension CA encoder.
                let mut legacy = frame.encode_reply().unwrap();
                legacy[10..12].copy_from_slice(&0u16.to_le_bytes());
                assert_eq!(encoded, legacy);
            }
        }
        assert!(frame.encode_reply().is_err());
        frame.payload.push(0);
        assert!(frame.encode_request().is_err());
        let mut oversized = frame.payload;
        oversized.resize(INPUT_FRAME_MAX + 1, 0);
        assert!(Frame::decode_request(&oversized).is_err());
    }

    #[test]
    fn request_encoder_preserves_strict_input_identity_and_metadata_bounds() {
        let mut frame = Frame {
            opcode: REQUEST_OPEN,
            request_id: [1; 16],
            call_seq: 2,
            status: OK,
            metadata: json!({"ta_epoch":"f".repeat(32),"session_nonce":"e".repeat(32),
                "namespace":"test","profile_id":"deepseek-prod-v1","credential_ref":"d".repeat(32),
                "expected_version":u64::MAX.to_string(),"operation":"CHAT","body_length":u64::MAX.to_string(),
                "overall_timeout_ms":600000,"response_mode":"json","completion_policy":"HTTP_COMPLETE",
                "headers":[{"name":"X-Test","value":""}]}),
            payload: Vec::new(),
        };
        let initial = serde_json::to_vec(&frame.metadata).unwrap().len();
        frame.metadata["headers"][0]["value"] = json!("x".repeat(METADATA_MAX - initial));
        let encoded = frame.encode_request().unwrap();
        assert_eq!(encoded.len(), HEADER_BYTES + METADATA_MAX);
        assert_eq!(Frame::decode_request(&encoded).unwrap(), frame);
        frame.metadata["headers"][0]["value"] = json!("x".repeat(METADATA_MAX - initial + 1));
        assert!(frame.encode_request().is_err());
        frame.metadata["headers"][0]["value"] = json!("");
        frame.request_id = [0; 16];
        assert_eq!(frame.encode_request().unwrap_err().status, E_REQUEST_ID);
        frame.request_id = [1; 16];
        frame.status = E_BUSY;
        assert!(frame.encode_request().is_err());
        frame.status = OK;
        frame.call_seq = 0;
        assert!(frame.encode_request().is_err());
    }
}
