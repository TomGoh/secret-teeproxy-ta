//! Single-writer credential catalog and complete, checksummed vault snapshots.
//!
//! Persistence owns the exclusive GP anchor and validates both durable slots.
//! Its load result is authoritative, including after a failed commit call.

use crate::wire::{
    self, E_BUSY, E_CREDENTIAL_NOT_FOUND, E_CREDENTIAL_REVOKED, E_LIMIT, E_OPERATION_CONFLICT,
    E_PROFILE_DENIED, E_STORAGE, E_STORAGE_NOT_COMMITTED, E_VERSION_CONFLICT, E_WIRE_FORMAT,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::provider::ProviderProfile;

pub const SNAPSHOT_MAX: usize = 524288;
pub const MAX_LIVE_REFS: usize = 64;
pub const MAX_RECORDS: usize = 192;
pub const TOMBSTONE_RETENTION_MS: u64 = 600000;
pub const PROFILE_ID: &str = "deepseek-prod-v1";

/// All calls are made by the same long-lived storage worker.
pub trait Persistence: Send {
    fn load(&mut self) -> Result<Option<Vec<u8>>, String>;
    fn commit(&mut self, bytes: &[u8]) -> Result<(), String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreError {
    pub status: u32,
    pub detail: &'static str,
    pub retry: &'static str,
}

impl StoreError {
    fn new(status: u32, detail: &'static str) -> Self {
        Self {
            status,
            detail,
            retry: "none",
        }
    }

    fn unknown() -> Self {
        Self {
            status: E_STORAGE,
            detail: "management commit requires reconciliation",
            retry: "reconcile_management",
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.detail)
    }
}
impl std::error::Error for StoreError {}

impl From<wire::WireError> for StoreError {
    fn from(_: wire::WireError) -> Self {
        Self::new(E_WIRE_FORMAT, "invalid credential metadata")
    }
}

/// Secrets deliberately omit Debug and serialization implementations.
pub(crate) struct SecretKey(Vec<u8>);

impl SecretKey {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone)]
pub(crate) struct CredentialSnapshot {
    pub(crate) key: Arc<SecretKey>,
    pub(crate) revoked: Arc<AtomicBool>,
    pub(crate) version: u64,
    pub(crate) profile_id: String,
    pub(crate) provider: ProviderProfile,
    expiry: Arc<Mutex<Option<Instant>>>,
}

impl CredentialSnapshot {
    pub(crate) fn revoked(&self) -> bool {
        // A long GP commit cannot delay TTL enforcement in an existing relay.
        let expired = self
            .expiry
            .lock()
            .map(|expiry| expiry.is_some_and(|at| at <= Instant::now()))
            .unwrap_or(true);
        if expired {
            self.revoked.store(true, Ordering::Release);
        }
        self.revoked.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
struct Receipt {
    operation_id: String,
    operation: &'static str,
    committed_version: u64,
    fingerprint: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Live,
    Deleted,
    Expired,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Deleted => "deleted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone)]
struct Record {
    namespace: String,
    reference: String,
    profile: String,
    provider: ProviderProfile,
    version: u64,
    state: State,
    key: Option<Arc<SecretKey>>,
    receipt: Receipt,
    temporary: bool,
    expires_at: Option<Instant>,
    retire_at: Option<Instant>,
    revoked: Arc<AtomicBool>,
    expiry: Arc<Mutex<Option<Instant>>>,
}

type Catalog = BTreeMap<(String, String), Record>;

pub struct Vault<P: Persistence> {
    persistence: P,
    vault_id: [u8; 16],
    generation: u64,
    durable: Vec<u8>,
    records: Catalog,
    quarantined: bool,
}

pub struct SnapshotInfo {
    pub vault_id: [u8; 16],
    pub generation: u64,
}

impl<P: Persistence> Vault<P> {
    /// Ordinary startup requires an initialized, validated durable vault.
    pub fn new(persistence: P) -> Result<Self, StoreError> {
        Self::from_storage(persistence)
    }

    pub fn from_storage(mut persistence: P) -> Result<Self, StoreError> {
        let durable = persistence
            .load()
            .map_err(|_| storage("vault load failed"))?
            .ok_or_else(|| storage("vault not initialized"))?;
        let (info, records) = decode_snapshot(&durable, Instant::now())?;
        Ok(Self {
            persistence,
            vault_id: info.vault_id,
            generation: info.generation,
            durable,
            records,
            quarantined: false,
        })
    }

    /// Explicit maintenance initialization. The backend must independently enforce
    /// exclusive BOOTSTRAP ownership and initialize both durable generation-0 slots.
    pub fn initialize(mut persistence: P, vault_id: [u8; 16]) -> Result<Self, StoreError> {
        if vault_id == [0; 16] {
            return Err(storage("invalid vault identity"));
        }
        if persistence
            .load()
            .map_err(|_| storage("initialization preflight failed"))?
            .is_some()
        {
            return Err(storage("vault already initialized"));
        }
        let durable = encode_snapshot(vault_id, 0, &Catalog::new())?;
        let _commit_result = persistence.commit(&durable);
        let readback = persistence
            .load()
            .map_err(|_| storage("initialization readback failed"))?;
        if readback.as_deref() != Some(durable.as_slice()) {
            return Err(storage("initialization not confirmed"));
        }
        Self::from_storage(persistence)
    }

    pub fn put(&mut self, metadata: &Value, key: &[u8]) -> Result<Value, StoreError> {
        self.ready()?;
        self.expire(Instant::now());
        let namespace = checked_identifier(metadata, "namespace")?.to_owned();
        let reference = checked_hex(metadata, "credential_ref")?.to_owned();
        let operation_id = checked_hex(metadata, "operation_id")?.to_owned();
        let profile = checked_identifier(metadata, "profile_id")?.to_owned();
        let provider = ProviderProfile::from_metadata(&profile, metadata.get("provider_config"))
            .map_err(|_| StoreError::new(E_PROFILE_DENIED, "provider configuration denied"))?;
        let provider_config = provider.config();
        let expected = wire::u64_string(metadata, "expected_version")?;
        let reuse_existing_key = metadata.get("reuse_existing_key")
            .map(|value| value.as_bool().ok_or_else(|| field("reuse_existing_key must be boolean")))
            .transpose()?.unwrap_or(false);
        if reuse_existing_key {
            if !key.is_empty() { return Err(field("key reuse requires an empty payload")); }
        } else {
            validate_key(key)?;
        }
        let temporary = match metadata.get("temporary") {
            None => false,
            Some(v) => v
                .as_bool()
                .ok_or_else(|| field("temporary must be boolean"))?,
        };
        let ttl = if temporary {
            metadata
                .get("ttl_ms")
                .and_then(Value::as_u64)
                .filter(|v| (1..=u32::MAX as u64).contains(v))
                .ok_or_else(|| field("invalid temporary TTL"))? as u32
        } else {
            if metadata.get("ttl_ms").is_some() {
                return Err(field("permanent credential has TTL"));
            }
            0
        };
        let fingerprint = fingerprint(
            wire::CREDENTIAL_PUT,
            &namespace,
            &reference,
            expected,
            &profile,
            temporary,
            ttl,
            provider_config.as_ref(),
            reuse_existing_key,
            key,
        );
        let index = (namespace.clone(), reference.clone());
        if let Some(record) = self.records.get(&index) {
            if let Some(result) = replay(record, &operation_id, &fingerprint)? {
                return Ok(result);
            }
            compare_version(record, expected)?;
            if record.temporary != temporary {
                return Err(field("credential lifetime is immutable"));
            }
        } else {
            if reuse_existing_key {
                return Err(StoreError::new(E_CREDENTIAL_NOT_FOUND, "credential absent"));
            }
            if expected != 0 {
                return Err(StoreError::new(
                    E_VERSION_CONFLICT,
                    "new credential expects version zero",
                ));
            }
            self.capacity(temporary)?;
        }
        let previous = self.records.get(&index);
        let secret = if reuse_existing_key {
            previous.and_then(|record| record.key.clone())
                .ok_or_else(|| StoreError::new(E_CREDENTIAL_REVOKED, "credential revoked"))?
        } else {
            Arc::new(SecretKey(key.to_vec()))
        };
        let version = next_version(previous.map_or(0, |record| record.version))?;
        let revoked = previous
            .map(|r| Arc::clone(&r.revoked))
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        let expiry = previous
            .map(|r| Arc::clone(&r.expiry))
            .unwrap_or_else(|| Arc::new(Mutex::new(None)));
        let now = Instant::now();
        let record = Record {
            namespace,
            reference,
            profile,
            provider,
            version,
            state: State::Live,
            key: Some(secret),
            receipt: Receipt {
                operation_id,
                operation: "put",
                committed_version: version,
                fingerprint,
            },
            temporary,
            expires_at: temporary.then(|| now + Duration::from_millis(ttl as u64)),
            retire_at: None,
            revoked,
            expiry,
        };
        if temporary {
            self.records.insert(index.clone(), record);
        } else {
            let mut candidate = self.records.clone();
            candidate.insert(index.clone(), record);
            self.publish(candidate)?;
        }
        let record = self.records.get(&index).unwrap();
        *record
            .expiry
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = record.expires_at;
        Ok(result(record, false, Instant::now()))
    }

    pub fn query(&mut self, metadata: &Value) -> Result<Value, StoreError> {
        self.ready()?;
        let now = Instant::now();
        self.expire(now);
        let namespace = checked_identifier(metadata, "namespace")?;
        let reference = checked_hex(metadata, "credential_ref")?;
        match self
            .records
            .get(&(namespace.to_owned(), reference.to_owned()))
        {
            Some(record) => Ok(result(record, false, now)),
            None => Ok(
                json!({"credential_ref":reference,"namespace":namespace,"state":"absent","version":"0","profile_id":null,"temporary":null,"ttl_remaining_ms":null,"receipt":null,"replayed":false}),
            ),
        }
    }

    pub fn delete(&mut self, metadata: &Value) -> Result<Value, StoreError> {
        self.ready()?;
        self.expire(Instant::now());
        let namespace = checked_identifier(metadata, "namespace")?;
        let reference = checked_hex(metadata, "credential_ref")?;
        let operation_id = checked_hex(metadata, "operation_id")?;
        let expected = wire::u64_string(metadata, "expected_version")?;
        let fingerprint = fingerprint(
            wire::CREDENTIAL_DELETE,
            namespace,
            reference,
            expected,
            "",
            false,
            0,
            None,
            false,
            &[],
        );
        let index = (namespace.to_owned(), reference.to_owned());
        let previous = self
            .records
            .get(&index)
            .ok_or_else(|| StoreError::new(E_CREDENTIAL_NOT_FOUND, "credential absent"))?;
        if let Some(result) = replay(previous, operation_id, &fingerprint)? {
            return Ok(result);
        }
        compare_version(previous, expected)?;
        let mut record = previous.clone();
        record.version = next_version(record.version)?;
        record.state = State::Deleted;
        record.key = None;
        record.expires_at = None;
        record.retire_at = Some(Instant::now() + Duration::from_millis(TOMBSTONE_RETENTION_MS));
        record.receipt = Receipt {
            operation_id: operation_id.to_owned(),
            operation: "delete",
            committed_version: record.version,
            fingerprint,
        };
        if record.temporary {
            self.records.insert(index.clone(), record);
        } else {
            let mut candidate = self.records.clone();
            candidate.insert(index.clone(), record);
            self.publish(candidate)?;
            // Retention begins at confirmed publication, after potentially slow I/O.
            self.records.get_mut(&index).unwrap().retire_at =
                Some(Instant::now() + Duration::from_millis(TOMBSTONE_RETENTION_MS));
        }
        let record = self.records.get(&index).unwrap();
        record.revoked.store(true, Ordering::Release);
        Ok(result(record, false, Instant::now()))
    }

    /// Run from the independent bounded sweeper through the same storage actor.
    pub fn sweep(&mut self) -> Result<(), StoreError> {
        self.sweep_at(Instant::now())
    }

    fn sweep_at(&mut self, now: Instant) -> Result<(), StoreError> {
        self.ready()?;
        self.expire(now);
        let mut candidate = self.records.clone();
        candidate.retain(|_, r| r.temporary || !r.retire_at.is_some_and(|at| at <= now));
        if candidate.len() != self.records.len() {
            self.publish(candidate)?;
        }
        self.records
            .retain(|_, r| !r.temporary || !r.retire_at.is_some_and(|at| at <= now));
        Ok(())
    }

    pub(crate) fn snapshot(
        &mut self,
        namespace: &str,
        reference: &str,
        expected_version: u64,
        profile: &str,
    ) -> Result<CredentialSnapshot, StoreError> {
        self.ready()?;
        self.expire(Instant::now());
        let record = self
            .records
            .get(&(namespace.to_owned(), reference.to_owned()))
            .ok_or_else(|| StoreError::new(E_CREDENTIAL_NOT_FOUND, "credential absent"))?;
        compare_version(record, expected_version)?;
        if record.profile != profile {
            return Err(StoreError::new(
                E_PROFILE_DENIED,
                "credential profile mismatch",
            ));
        }
        Ok(CredentialSnapshot {
            key: Arc::clone(record.key.as_ref().unwrap()),
            revoked: Arc::clone(&record.revoked),
            version: record.version,
            profile_id: record.profile.clone(),
            provider: record.provider.clone(),
            expiry: Arc::clone(&record.expiry),
        })
    }

    fn ready(&self) -> Result<(), StoreError> {
        if self.quarantined {
            return Err(storage("vault quarantined"));
        }
        Ok(())
    }

    fn capacity(&self, temporary: bool) -> Result<(), StoreError> {
        let records: Vec<_> = self
            .records
            .values()
            .filter(|r| r.temporary == temporary)
            .collect();
        if records.iter().filter(|r| r.state == State::Live).count() >= MAX_LIVE_REFS {
            return Err(StoreError::new(E_LIMIT, "credential live capacity"));
        }
        if records.len() >= MAX_RECORDS {
            return Err(StoreError::new(E_BUSY, "credential retirement capacity"));
        }
        Ok(())
    }

    fn expire(&mut self, now: Instant) {
        for record in self
            .records
            .values_mut()
            .filter(|r| r.temporary && r.state == State::Live)
        {
            if record.expires_at.is_some_and(|at| at <= now) {
                record.state = State::Expired;
                record.key = None;
                record.expires_at = None;
                record.retire_at = Some(now + Duration::from_millis(TOMBSTONE_RETENTION_MS));
                record.revoked.store(true, Ordering::Release);
            }
        }
    }

    fn publish(&mut self, candidate: Catalog) -> Result<(), StoreError> {
        let generation = next_version(self.generation)?;
        let encoded = encode_snapshot(self.vault_id, generation, &candidate)?;
        let _commit_result = self.persistence.commit(&encoded);
        // A successful Create is insufficient. Every commit needs authoritative readback.
        match self.persistence.load() {
            Ok(Some(bytes)) if bytes == encoded => {
                self.records = candidate;
                self.generation = generation;
                self.durable = encoded;
                Ok(())
            }
            Ok(Some(bytes)) if bytes == self.durable => Err(StoreError::new(
                E_STORAGE_NOT_COMMITTED,
                "management commit confirmed absent",
            )),
            _ => {
                self.quarantined = true;
                for record in self.records.values() {
                    record.revoked.store(true, Ordering::Release);
                }
                Err(StoreError::unknown())
            }
        }
    }
}

fn storage(detail: &'static str) -> StoreError {
    StoreError::new(E_STORAGE, detail)
}
fn field(detail: &'static str) -> StoreError {
    StoreError::new(E_WIRE_FORMAT, detail)
}

fn checked_identifier<'a>(metadata: &'a Value, field_name: &str) -> Result<&'a str, StoreError> {
    let value = wire::text(metadata, field_name)?;
    if !wire::identifier(value) {
        return Err(field("invalid credential identifier"));
    }
    Ok(value)
}

fn checked_hex<'a>(metadata: &'a Value, field_name: &str) -> Result<&'a str, StoreError> {
    let value = wire::text(metadata, field_name)?;
    if !wire::hex(value, 32) {
        return Err(field("invalid credential reference or operation ID"));
    }
    Ok(value)
}

fn validate_key(key: &[u8]) -> Result<(), StoreError> {
    if !(1..=4096).contains(&key.len())
        || std::str::from_utf8(key).is_err()
        || key.iter().any(|b| matches!(b, 0 | b'\r' | b'\n'))
    {
        return Err(field("invalid credential bytes"));
    }
    Ok(())
}

fn next_version(version: u64) -> Result<u64, StoreError> {
    version
        .checked_add(1)
        .ok_or_else(|| StoreError::new(E_LIMIT, "monotonic counter exhausted"))
}

fn compare_version(record: &Record, expected: u64) -> Result<(), StoreError> {
    if record.version != expected {
        return Err(StoreError::new(
            E_VERSION_CONFLICT,
            "credential version conflict",
        ));
    }
    if record.state != State::Live {
        return Err(StoreError::new(E_CREDENTIAL_REVOKED, "credential revoked"));
    }
    Ok(())
}

fn replay(
    record: &Record,
    operation_id: &str,
    fingerprint: &str,
) -> Result<Option<Value>, StoreError> {
    if record.receipt.operation_id != operation_id {
        return Ok(None);
    }
    if record.receipt.fingerprint != fingerprint {
        return Err(StoreError::new(
            E_OPERATION_CONFLICT,
            "operation contents conflict",
        ));
    }
    Ok(Some(result(record, true, Instant::now())))
}

fn result(record: &Record, replayed: bool, now: Instant) -> Value {
    let ttl = if record.temporary {
        Some(record.expires_at.map_or(0, |deadline| {
            deadline
                .saturating_duration_since(now)
                .as_millis()
                .min(u32::MAX as u128) as u32
        }))
    } else {
        None
    };
    let mut response = json!({
        "credential_ref":record.reference,"namespace":record.namespace,"state":record.state.name(),
        "version":record.version.to_string(),"profile_id":record.profile,"temporary":record.temporary,
        "ttl_remaining_ms":ttl,"receipt":{"operation_id":record.receipt.operation_id,"operation":record.receipt.operation,"committed_version":record.receipt.committed_version.to_string()},"replayed":replayed
    });
    if let Some(config) = record.provider.config() {
        response["provider_config"] = config;
    }
    response
}

fn fingerprint(
    opcode: u16,
    namespace: &str,
    reference: &str,
    expected: u64,
    profile: &str,
    temporary: bool,
    ttl: u32,
    provider_config: Option<&Value>,
    reuse_existing_key: bool,
    key: &[u8],
) -> String {
    let mut hash = Sha256::new();
    hash.update(opcode.to_le_bytes());
    hash.update((namespace.len() as u32).to_le_bytes());
    hash.update(namespace.as_bytes());
    hash.update(decode_hex128(reference).unwrap());
    hash.update(expected.to_le_bytes());
    hash.update((profile.len() as u32).to_le_bytes());
    hash.update(profile.as_bytes());
    hash.update([temporary as u8]);
    hash.update(ttl.to_le_bytes());
    hash.update((key.len() as u32).to_le_bytes());
    hash.update(key);
    if reuse_existing_key {
        hash.update(b"LSP-REUSE-EXISTING-KEY-v1\0");
    }
    // Built-in fingerprints retain their original byte sequence so durable
    // pre-extension receipts remain replayable after loading old snapshots.
    if let Some(config) = provider_config {
        let bytes = serde_json::to_vec(config).expect("provider configuration is serializable");
        hash.update(b"LSP-PROVIDER-CONFIG-v1\0");
        hash.update((bytes.len() as u32).to_le_bytes());
        hash.update(bytes);
    }
    lower_hex(&hash.finalize())
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 15) as usize] as char);
    }
    value
}

fn decode_hex128(value: &str) -> Result<[u8; 16], StoreError> {
    if !wire::hex(value, 32) {
        return Err(storage("invalid stored identity"));
    }
    let mut bytes = [0; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| storage("invalid stored identity"))?;
    }
    Ok(bytes)
}

fn encode_snapshot(
    vault_id: [u8; 16],
    generation: u64,
    records: &Catalog,
) -> Result<Vec<u8>, StoreError> {
    let records: Vec<_> = records
        .values()
        .filter(|record| !record.temporary)
        .map(|record| {
            let mut row = json!({
                "namespace":record.namespace,"ref":record.reference,"profile":record.profile,
                "version":record.version.to_string(),"state":record.state.name(),
                "key_b64":record.key.as_ref().map(|key| STANDARD.encode(key.as_bytes())),
                "receipt":{"operation_id":record.receipt.operation_id,"operation":record.receipt.operation,"committed_version":record.receipt.committed_version.to_string(),"fingerprint":record.receipt.fingerprint}
            });
            if let Some(config) = record.provider.config() {
                row["provider_config"] = config;
            }
            row
        })
        .collect();
    if records.len() > MAX_RECORDS
        || records.iter().filter(|r| r["state"] == "live").count() > MAX_LIVE_REFS
    {
        return Err(StoreError::new(E_LIMIT, "snapshot record capacity"));
    }
    let payload = serde_json::to_vec(&json!({"vault_id":lower_hex(&vault_id),"records":records}))
        .map_err(|_| storage("snapshot encoding"))?;
    if payload.len() + 64 > SNAPSHOT_MAX {
        return Err(StoreError::new(E_LIMIT, "snapshot byte capacity"));
    }
    let mut bytes = vec![0; 64];
    bytes[..8].copy_from_slice(b"LSPVLT1\0");
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    bytes[10..12].copy_from_slice(&64u16.to_le_bytes());
    bytes[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&generation.to_le_bytes());
    bytes[24..28].copy_from_slice(&(records.len() as u32).to_le_bytes());
    let mut hash = Sha256::new();
    hash.update(b"LSP-VAULT-CHECK-v1\0");
    hash.update(&bytes[..32]);
    hash.update(&payload);
    bytes[32..64].copy_from_slice(&hash.finalize());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

/// Validates checksum, canonical payload, every record, and bounded live/total counts.
pub fn validate_snapshot(bytes: &[u8]) -> Result<SnapshotInfo, StoreError> {
    decode_snapshot(bytes, Instant::now()).map(|(info, _)| info)
}

fn decode_snapshot(bytes: &[u8], now: Instant) -> Result<(SnapshotInfo, Catalog), StoreError> {
    if !(64..=SNAPSHOT_MAX).contains(&bytes.len())
        || &bytes[..8] != b"LSPVLT1\0"
        || bytes[8..12] != [1, 0, 64, 0]
        || bytes[28..32] != [0; 4]
    {
        return Err(storage("invalid snapshot header"));
    }
    let payload_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let generation = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let record_count = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
    if payload_len + 64 != bytes.len() || record_count > MAX_RECORDS {
        return Err(storage("snapshot length or count"));
    }
    let mut hash = Sha256::new();
    hash.update(b"LSP-VAULT-CHECK-v1\0");
    hash.update(&bytes[..32]);
    hash.update(&bytes[64..]);
    if hash.finalize().as_slice() != &bytes[32..64] {
        return Err(storage("snapshot checksum"));
    }
    let payload = wire::strict_json(&bytes[64..]).map_err(|_| storage("snapshot JSON"))?;
    stored_fields(&payload, &["vault_id", "records"])?;
    let vault_id =
        decode_hex128(wire::text(&payload, "vault_id").map_err(|_| storage("vault identity"))?)?;
    if vault_id == [0; 16] {
        return Err(storage("empty vault identity"));
    }
    if serde_json::to_vec(&payload).map_err(|_| storage("snapshot canonical encoding"))?
        != bytes[64..]
    {
        return Err(storage("snapshot payload is not canonical"));
    }
    let rows = payload["records"]
        .as_array()
        .filter(|r| r.len() == record_count)
        .ok_or_else(|| storage("snapshot records"))?;
    let mut catalog = Catalog::new();
    let mut previous: Option<(String, String)> = None;
    let mut live_count = 0;
    for row in rows {
        let mut fields = vec![
            "namespace",
            "ref",
            "profile",
            "version",
            "state",
            "key_b64",
            "receipt",
        ];
        if row.get("provider_config").is_some() {
            fields.push("provider_config");
        }
        stored_fields(row, &fields)?;
        let namespace = checked_identifier(row, "namespace")
            .map_err(|_| storage("stored namespace"))?
            .to_owned();
        let reference = checked_hex(row, "ref")
            .map_err(|_| storage("stored credential reference"))?
            .to_owned();
        let profile = checked_identifier(row, "profile")
            .map_err(|_| storage("stored profile"))?
            .to_owned();
        let version = wire::u64_string(row, "version").map_err(|_| storage("stored version"))?;
        let provider = ProviderProfile::from_metadata(&profile, row.get("provider_config"))
            .map_err(|_| storage("stored provider configuration"))?;
        if row.get("provider_config") != provider.config().as_ref() {
            return Err(storage("noncanonical stored provider configuration"));
        }
        if version == 0 {
            return Err(storage("stored profile or version"));
        }
        let state = match row["state"].as_str() {
            Some("live") => State::Live,
            Some("deleted") => State::Deleted,
            _ => return Err(storage("stored credential state")),
        };
        let key = if state == State::Live {
            live_count += 1;
            let encoded = row["key_b64"]
                .as_str()
                .ok_or_else(|| storage("stored key encoding"))?;
            let key = STANDARD
                .decode(encoded)
                .map_err(|_| storage("stored key encoding"))?;
            validate_key(&key).map_err(|_| storage("stored key bytes"))?;
            if STANDARD.encode(&key) != encoded {
                return Err(storage("noncanonical key encoding"));
            }
            Some(Arc::new(SecretKey(key)))
        } else {
            if !row["key_b64"].is_null() {
                return Err(storage("deleted credential retains key"));
            }
            None
        };
        let receipt = &row["receipt"];
        stored_fields(
            receipt,
            &[
                "operation_id",
                "operation",
                "committed_version",
                "fingerprint",
            ],
        )?;
        let operation_id = checked_hex(receipt, "operation_id")
            .map_err(|_| storage("stored receipt identity"))?
            .to_owned();
        let operation = match receipt["operation"].as_str() {
            Some("put") if state == State::Live => "put",
            Some("delete") if state == State::Deleted => "delete",
            _ => return Err(storage("stored receipt operation")),
        };
        let committed_version = wire::u64_string(receipt, "committed_version")
            .map_err(|_| storage("stored receipt version"))?;
        let fingerprint = wire::text(receipt, "fingerprint")
            .map_err(|_| storage("stored receipt fingerprint"))?
            .to_owned();
        if committed_version != version || !wire::hex(&fingerprint, 64) {
            return Err(storage("stored receipt consistency"));
        }
        let index = (namespace.clone(), reference.clone());
        if previous.as_ref().is_some_and(|previous| previous >= &index) {
            return Err(storage("snapshot order or duplicate record"));
        }
        previous = Some(index.clone());
        catalog.insert(
            index,
            Record {
                namespace,
                reference,
                profile,
                provider,
                version,
                state,
                key,
                receipt: Receipt {
                    operation_id,
                    operation,
                    committed_version,
                    fingerprint,
                },
                temporary: false,
                expires_at: None,
                retire_at: (state == State::Deleted)
                    .then(|| now + Duration::from_millis(TOMBSTONE_RETENTION_MS)),
                revoked: Arc::new(AtomicBool::new(state != State::Live)),
                expiry: Arc::new(Mutex::new(None)),
            },
        );
    }
    if live_count > MAX_LIVE_REFS {
        return Err(storage("snapshot live count"));
    }
    Ok((
        SnapshotInfo {
            vault_id,
            generation,
        },
        catalog,
    ))
}

fn stored_fields(value: &Value, fields: &[&str]) -> Result<(), StoreError> {
    let object = value
        .as_object()
        .ok_or_else(|| storage("stored object type"))?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(storage("stored object fields"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Memory {
        bytes: Option<Vec<u8>>,
        writes: usize,
        failure: u8,
    }

    impl Persistence for Memory {
        fn load(&mut self) -> Result<Option<Vec<u8>>, String> {
            if self.failure == 3 {
                return Err("synthetic read failure".to_owned());
            }
            Ok(self.bytes.clone())
        }
        fn commit(&mut self, bytes: &[u8]) -> Result<(), String> {
            self.writes += 1;
            match self.failure {
                1 => Err("synthetic precommit failure".to_owned()),
                2 => {
                    self.bytes = Some(bytes.to_vec());
                    Err("synthetic postcommit failure".to_owned())
                }
                4 => {
                    self.bytes = Some(vec![0]);
                    Ok(())
                }
                _ => {
                    self.bytes = Some(bytes.to_vec());
                    Ok(())
                }
            }
        }
    }

    fn vault() -> Vault<Memory> {
        Vault::initialize(Memory::default(), [1; 16]).unwrap()
    }
    fn put_metadata() -> Value {
        json!({"namespace":"fixture","credential_ref":"a".repeat(32),"operation_id":"b".repeat(32),"profile_id":PROFILE_ID,"expected_version":"0"})
    }
    fn delete_metadata() -> Value {
        json!({"namespace":"fixture","credential_ref":"a".repeat(32),"operation_id":"c".repeat(32),"expected_version":"1"})
    }
    fn status<T>(result: Result<T, StoreError>) -> u32 {
        result.err().unwrap().status
    }

    #[test]
    fn ordinary_startup_rejects_missing_and_corrupt_storage() {
        assert_eq!(status(Vault::new(Memory::default())), E_STORAGE);
        assert_eq!(
            status(Vault::new(Memory {
                bytes: Some(vec![0; 64]),
                ..Memory::default()
            })),
            E_STORAGE
        );
        let mut v = vault();
        v.persistence.failure = 3;
        assert_eq!(status(Vault::from_storage(v.persistence)), E_STORAGE);
    }

    #[test]
    fn receipt_replay_precedes_cas_and_survives_restart() {
        let mut v = vault();
        let put = put_metadata();
        let first = v.put(&put, b"fake-fixture-key").unwrap();
        assert_eq!(first["version"], "1");
        let writes = v.persistence.writes;
        assert_eq!(v.put(&put, b"fake-fixture-key").unwrap()["replayed"], true);
        assert_eq!(v.persistence.writes, writes);
        assert_eq!(
            status(v.put(&put, b"different-fixture-key")),
            E_OPERATION_CONFLICT
        );
        let mut v = Vault::from_storage(v.persistence).unwrap();
        assert_eq!(v.put(&put, b"fake-fixture-key").unwrap()["replayed"], true);
        assert!(
            !serde_json::to_string(&v.query(&put).unwrap())
                .unwrap()
                .contains("fake-fixture-key")
        );
        let mut stale = put.clone();
        stale["operation_id"] = json!("d".repeat(32));
        assert_eq!(
            status(v.put(&stale, b"fake-fixture-key")),
            E_VERSION_CONFLICT
        );
    }

    #[test]
    fn provider_binding_is_durable_replay_bound_and_request_immutable() {
        let mut vault = vault();
        let mut put = put_metadata();
        put["profile_id"] = json!(crate::provider::CUSTOM_PROFILE_ID);
        put["provider_config"] =
            json!({"provider_type":"google_gemini","base_url":"https://first.example/v1beta/"});
        let committed = vault.put(&put, b"fake-provider-key").unwrap();
        assert_eq!(committed["provider_config"], put["provider_config"]);
        assert_eq!(
            vault.query(&put).unwrap()["provider_config"],
            put["provider_config"]
        );
        let old = vault
            .snapshot(
                "fixture",
                &"a".repeat(32),
                1,
                crate::provider::CUSTOM_PROFILE_ID,
            )
            .unwrap();
        let mut changed = put.clone();
        changed["provider_config"]["base_url"] = json!("https://second.example/v1beta/");
        assert_eq!(
            status(vault.put(&changed, b"fake-provider-key")),
            E_OPERATION_CONFLICT
        );
        let mut vault = Vault::from_storage(vault.persistence).unwrap();
        assert_eq!(
            vault.query(&put).unwrap()["provider_config"],
            put["provider_config"]
        );
        assert_eq!(
            vault.put(&put, b"fake-provider-key").unwrap()["replayed"],
            true
        );
        let restored = vault
            .snapshot(
                "fixture",
                &"a".repeat(32),
                1,
                crate::provider::CUSTOM_PROFILE_ID,
            )
            .unwrap();
        assert_eq!(restored.provider.host(), "first.example");
        assert_eq!(restored.key.as_bytes(), b"fake-provider-key");
        changed["operation_id"] = json!("d".repeat(32));
        changed["expected_version"] = json!("1");
        vault.put(&changed, b"fake-provider-key").unwrap();
        let updated = vault
            .snapshot(
                "fixture",
                &"a".repeat(32),
                2,
                crate::provider::CUSTOM_PROFILE_ID,
            )
            .unwrap();
        assert_eq!(updated.provider.host(), "second.example");
        assert_eq!(old.provider.host(), "first.example");
        assert_eq!(restored.provider.host(), "first.example");
        let mut delete = delete_metadata();
        delete["expected_version"] = json!("2");
        vault.delete(&delete).unwrap();
        let mut vault = Vault::from_storage(vault.persistence).unwrap();
        assert_eq!(vault.query(&put).unwrap()["state"], "deleted");
        assert!(restored.revoked());
        assert!(updated.revoked());
    }

    #[test]
    fn metadata_only_rebind_keeps_key_and_reconciles_across_restart() {
        let mut vault = vault();
        let mut put = put_metadata();
        put["profile_id"] = json!(crate::provider::CUSTOM_PROFILE_ID);
        put["provider_config"] = json!({"provider_type":"openai_compatible","base_url":"https://first.example/v1/"});
        vault.put(&put, b"fake-preserved-key").unwrap();
        let before = vault.snapshot("fixture", &"a".repeat(32), 1, crate::provider::CUSTOM_PROFILE_ID).unwrap();
        let mut rebind = put.clone();
        rebind["expected_version"] = json!("1");
        rebind["operation_id"] = json!("c".repeat(32));
        rebind["reuse_existing_key"] = json!(true);
        rebind["provider_config"]["base_url"] = json!("https://second.example/v2/");
        assert_eq!(vault.put(&rebind, b"").unwrap()["version"], "2");
        let after = vault.snapshot("fixture", &"a".repeat(32), 2, crate::provider::CUSTOM_PROFILE_ID).unwrap();
        assert!(Arc::ptr_eq(&before.key, &after.key));
        assert_eq!(before.provider.host(), "first.example");
        assert_eq!(after.provider.host(), "second.example");
        let mut conflict = rebind.clone();
        conflict["provider_config"]["base_url"] = json!("https://third.example/");
        assert_eq!(status(vault.put(&conflict, b"")), E_OPERATION_CONFLICT);
        let persistence = vault.persistence;
        let mut restored = Vault::from_storage(persistence).unwrap();
        assert_eq!(restored.put(&rebind, b"").unwrap()["replayed"], true);
        let snapshot = restored.snapshot("fixture", &"a".repeat(32), 2, crate::provider::CUSTOM_PROFILE_ID).unwrap();
        assert_eq!(snapshot.key.as_bytes(), b"fake-preserved-key");
        assert_eq!(snapshot.provider.host(), "second.example");
    }

    #[test]
    fn rebind_requires_live_existing_key_and_empty_payload() {
        let mut vault = vault();
        let mut rebind = put_metadata();
        rebind["reuse_existing_key"] = json!(true);
        assert_eq!(status(vault.put(&rebind, b"unexpected-key")), E_WIRE_FORMAT);
        assert_eq!(status(vault.put(&rebind, b"")), E_CREDENTIAL_NOT_FOUND);
        vault.put(&put_metadata(), b"fake-key").unwrap();
        rebind["expected_version"] = json!("1");
        rebind["operation_id"] = json!("d".repeat(32));
        vault.delete(&delete_metadata()).unwrap();
        assert_eq!(status(vault.put(&rebind, b"")), E_VERSION_CONFLICT);
        rebind["expected_version"] = json!("2");
        assert_eq!(status(vault.put(&rebind, b"")), E_CREDENTIAL_REVOKED);
    }

    #[test]
    fn legacy_deepseek_snapshot_and_receipt_load_without_migration() {
        // Frozen pre-extension LSPVLT1 record, including its original PUT hash.
        let bytes = include_bytes!("../tests/fixtures/legacy-deepseek-vault-v1.bin");
        let mut vault = Vault::from_storage(Memory {
            bytes: Some(bytes.to_vec()),
            ..Memory::default()
        })
        .unwrap();
        let put = put_metadata();
        assert_eq!(
            vault.put(&put, b"fake-fixture-key").unwrap()["replayed"],
            true
        );
        assert_eq!(vault.persistence.bytes.as_deref(), Some(bytes.as_slice()));
        let snapshot = vault
            .snapshot("fixture", &"a".repeat(32), 1, PROFILE_ID)
            .unwrap();
        assert_eq!(snapshot.provider, ProviderProfile::deepseek());
        assert_eq!(snapshot.key.as_bytes(), b"fake-fixture-key");
    }

    #[test]
    fn provider_configuration_is_required_for_custom_and_fixed_for_builtin() {
        let mut vault = vault();
        let mut put = put_metadata();
        put["provider_config"] =
            json!({"provider_type":"openai_compatible","base_url":"https://other.example/"});
        assert_eq!(status(vault.put(&put, b"fake-key")), E_PROFILE_DENIED);
        put["profile_id"] = json!(crate::provider::CUSTOM_PROFILE_ID);
        put.as_object_mut().unwrap().remove("provider_config");
        assert_eq!(status(vault.put(&put, b"fake-key")), E_PROFILE_DENIED);
        put["provider_config"] =
            json!({"provider_type":"openai_compatible","base_url":"http://other.example/"});
        assert_eq!(status(vault.put(&put, b"fake-key")), E_PROFILE_DENIED);
        assert_eq!(vault.query(&put).unwrap()["state"], "absent");
    }

    #[test]
    fn update_preserves_old_snapshot_and_delete_revokes_all_versions() {
        let mut v = vault();
        let mut put = put_metadata();
        v.put(&put, b"fake-original").unwrap();
        let old = v
            .snapshot("fixture", &"a".repeat(32), 1, PROFILE_ID)
            .unwrap();
        put["operation_id"] = json!("d".repeat(32));
        put["expected_version"] = json!("1");
        v.put(&put, b"fake-replacement").unwrap();
        let new = v
            .snapshot("fixture", &"a".repeat(32), 2, PROFILE_ID)
            .unwrap();
        assert_eq!(old.key.as_bytes(), b"fake-original");
        assert_eq!(new.key.as_bytes(), b"fake-replacement");
        assert!(!old.revoked());
        let mut delete = delete_metadata();
        delete["expected_version"] = json!("2");
        assert_eq!(v.delete(&delete).unwrap()["version"], "3");
        assert!(old.revoked() && new.revoked());
        let writes = v.persistence.writes;
        assert_eq!(v.delete(&delete).unwrap()["replayed"], true);
        assert_eq!(v.persistence.writes, writes);
        assert_eq!(
            status(v.snapshot("fixture", &"a".repeat(32), 3, PROFILE_ID)),
            E_CREDENTIAL_REVOKED
        );
    }

    #[test]
    fn absent_delete_and_retired_reference_rules() {
        let mut v = vault();
        assert_eq!(status(v.delete(&delete_metadata())), E_CREDENTIAL_NOT_FOUND);
        let mut put = put_metadata();
        v.put(&put, b"fake-key").unwrap();
        v.delete(&delete_metadata()).unwrap();
        put["expected_version"] = json!("2");
        put["operation_id"] = json!("d".repeat(32));
        assert_eq!(status(v.put(&put, b"fake-key")), E_CREDENTIAL_REVOKED);
        assert_eq!(v.query(&put).unwrap()["state"], "deleted");
    }

    #[test]
    fn temporary_expiration_replay_does_not_renew_and_never_persists() {
        let mut v = vault();
        let writes = v.persistence.writes;
        let mut put = put_metadata();
        put["temporary"] = json!(true);
        put["ttl_ms"] = json!(1000);
        v.put(&put, b"fake-temporary").unwrap();
        let snapshot = v
            .snapshot("fixture", &"a".repeat(32), 1, PROFILE_ID)
            .unwrap();
        v.expire(Instant::now() + Duration::from_secs(2));
        assert!(snapshot.revoked());
        let result = v.put(&put, b"fake-temporary").unwrap();
        assert_eq!(result["state"], "expired");
        assert_eq!(result["replayed"], true);
        assert_eq!(result["ttl_remaining_ms"], 0);
        assert_eq!(v.persistence.writes, writes);
        let mut restarted = Vault::from_storage(v.persistence).unwrap();
        assert_eq!(restarted.query(&put).unwrap()["state"], "absent");
    }

    #[test]
    fn failed_writes_are_classified_from_authoritative_readback() {
        let mut v = vault();
        v.persistence.failure = 1;
        assert_eq!(
            status(v.put(&put_metadata(), b"fake-key")),
            E_STORAGE_NOT_COMMITTED
        );
        assert_eq!(v.query(&put_metadata()).unwrap()["state"], "absent");
        v.persistence.failure = 2;
        assert_eq!(
            v.put(&put_metadata(), b"fake-key").unwrap()["state"],
            "live"
        );
        let snapshot = v
            .snapshot("fixture", &"a".repeat(32), 1, PROFILE_ID)
            .unwrap();
        v.persistence.failure = 4;
        let error = v.delete(&delete_metadata()).unwrap_err();
        assert_eq!(error.status, E_STORAGE);
        assert_eq!(error.retry, "reconcile_management");
        assert!(snapshot.revoked());
        assert_eq!(status(v.query(&put_metadata())), E_STORAGE);
    }

    #[test]
    fn checksum_and_snapshot_metadata_tampering_are_detected() {
        let mut v = vault();
        v.put(&put_metadata(), b"fake-key").unwrap();
        assert_eq!(validate_snapshot(&v.durable).unwrap().generation, 1);
        let mut corrupted = v.durable.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert_eq!(status(validate_snapshot(&corrupted)), E_STORAGE);
        let mut catalog = v.records.clone();
        catalog
            .values_mut()
            .next()
            .unwrap()
            .receipt
            .committed_version = 2;
        let invalid = encode_snapshot([1; 16], 2, &catalog).unwrap();
        assert_eq!(status(validate_snapshot(&invalid)), E_STORAGE);
    }

    #[test]
    fn garbage_collection_preserves_receipt_window_and_live_capacity() {
        let mut v = vault();
        let put = put_metadata();
        v.put(&put, b"fake-key").unwrap();
        let old = v
            .snapshot("fixture", &"a".repeat(32), 1, PROFILE_ID)
            .unwrap();
        v.delete(&delete_metadata()).unwrap();
        let generation = v.generation;
        v.sweep_at(Instant::now() + Duration::from_secs(599))
            .unwrap();
        assert_eq!(v.generation, generation);
        assert_eq!(v.query(&put).unwrap()["state"], "deleted");
        v.sweep_at(Instant::now() + Duration::from_secs(601))
            .unwrap();
        assert_eq!(v.generation, generation + 1);
        assert_eq!(v.query(&put).unwrap()["state"], "absent");
        assert!(old.revoked());
        // The limited retirement guarantee ends after collection.
        v.put(&put, b"fake-new-lifecycle").unwrap();
        assert!(
            !v.snapshot("fixture", &"a".repeat(32), 1, PROFILE_ID)
                .unwrap()
                .revoked()
        );
        assert!(old.revoked());
    }

    #[test]
    fn separate_live_and_retirement_quotas_allow_updates_and_deletes() {
        let mut v = vault();
        let mut put = put_metadata();
        put["temporary"] = json!(true);
        put["ttl_ms"] = json!(100000);
        for index in 0..MAX_LIVE_REFS {
            put["credential_ref"] = json!(format!("{index:032x}"));
            v.put(&put, b"fake-key").unwrap();
        }
        put["credential_ref"] = json!(format!("{:032x}", MAX_LIVE_REFS));
        assert_eq!(status(v.put(&put, b"fake-key")), E_LIMIT);
        // Retire one entry and refill its live slot repeatedly until the total
        // retention quota is full, preserving every earlier operation receipt.
        for index in 0..MAX_RECORDS {
            let delete = json!({"namespace":"fixture","credential_ref":format!("{index:032x}"),"operation_id":"c".repeat(32),"expected_version":"1"});
            if index >= MAX_LIVE_REFS {
                put["credential_ref"] = json!(format!("{index:032x}"));
                v.put(&put, b"fake-key").unwrap();
            }
            v.delete(&delete).unwrap();
        }
        put["credential_ref"] = json!(format!("{:032x}", MAX_RECORDS));
        assert_eq!(status(v.put(&put, b"fake-key")), E_BUSY);
        assert_eq!(v.records.len(), MAX_RECORDS);
        assert_eq!(
            v.records
                .values()
                .filter(|record| record.state == State::Live)
                .count(),
            0
        );
        assert_eq!(v.persistence.writes, 1);
    }

    #[test]
    fn maximum_documented_snapshot_shape_fits_bound() {
        let mut v = vault();
        let mut put = put_metadata();
        put["namespace"] = json!("n".repeat(64));
        let key = vec![b'k'; 4096];
        v.put(&put, &key).unwrap();
        let template = v.records.values().next().unwrap().clone();
        let mut records = Catalog::new();
        for index in 0..MAX_RECORDS {
            let mut record = template.clone();
            record.reference = format!("{index:032x}");
            record.version = u64::MAX;
            record.receipt.committed_version = u64::MAX;
            if index >= MAX_LIVE_REFS {
                record.state = State::Deleted;
                record.key = None;
                record.receipt.operation = "delete";
            }
            records.insert((record.namespace.clone(), record.reference.clone()), record);
        }
        let bytes = encode_snapshot([1; 16], u64::MAX, &records).unwrap();
        assert!(bytes.len() < SNAPSHOT_MAX);
        assert_eq!(validate_snapshot(&bytes).unwrap().generation, u64::MAX);
    }

    #[test]
    fn snapshot_enforces_expiry_without_waiting_for_storage_worker() {
        let mut v = vault();
        let mut put = put_metadata();
        put["temporary"] = json!(true);
        put["ttl_ms"] = json!(100000);
        v.put(&put, b"fake-key").unwrap();
        let snapshot = v
            .snapshot("fixture", &"a".repeat(32), 1, PROFILE_ID)
            .unwrap();
        *snapshot.expiry.lock().unwrap() = Some(Instant::now());
        assert!(snapshot.revoked());
        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.profile_id, PROFILE_ID);
    }
}
