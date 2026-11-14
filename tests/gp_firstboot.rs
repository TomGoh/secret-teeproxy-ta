//! Execute the production GP adapter against a deterministic, fault-injectable GP object API.
#![allow(non_snake_case, non_camel_case_types)]

extern crate self as rust_libutee;
pub use secret_teeproxy_ta::store;
#[path = "../src/gp.rs"]
mod gp;

use gp::{GpPersistence, VaultEnsureResult};
use serde_json::json;
use std::{
    collections::BTreeMap,
    ffi::c_void,
    ptr,
    sync::{Mutex, MutexGuard, OnceLock},
};

pub const TEE_SUCCESS: u32 = 0;
pub const TEE_ERROR_ITEM_NOT_FOUND: u32 = 0xffff0008;
const ERROR_CONFLICT: u32 = 0xffff0003;
const ERROR_GENERIC: u32 = 0xffff0000;
pub const TEE_STORAGE_PRIVATE: u32 = 1;
pub type TEE_ObjectHandle = *mut c_void;
#[derive(Default)]
pub struct TEE_ObjectInfo {
    pub dataSize: usize,
}
pub enum TEE_Whence {
    TEE_DATA_SEEK_SET,
}

const ANCHOR: &[u8] = b"lsp.v1.vault.anchor";
const SLOT0: &[u8] = b"lsp.v1.vault.0";
const SLOT1: &[u8] = b"lsp.v1.vault.1";
struct Handle {
    id: Vec<u8>,
    offset: usize,
}
#[derive(Default)]
struct Backend {
    objects: BTreeMap<Vec<u8>, Vec<u8>>,
    handles: BTreeMap<usize, Handle>,
    next: usize,
    creates: usize,
    writes: usize,
    fail_create: Option<Vec<u8>>,
    fail_anchor_write: bool,
}
static CASE_LOCK: Mutex<()> = Mutex::new(());
static BACKEND: OnceLock<Mutex<Backend>> = OnceLock::new();
fn backend() -> MutexGuard<'static, Backend> {
    BACKEND
        .get_or_init(|| Mutex::new(Backend::default()))
        .lock()
        .unwrap()
}
fn case() -> MutexGuard<'static, ()> {
    let guard = CASE_LOCK.lock().unwrap();
    *backend() = Backend::default();
    guard
}
fn snapshot() -> BTreeMap<Vec<u8>, Vec<u8>> {
    backend().objects.clone()
}
fn counters() -> (usize, usize) {
    let state = backend();
    (state.creates, state.writes)
}
fn allocate(state: &mut Backend, id: Vec<u8>) -> TEE_ObjectHandle {
    state.next += 1;
    let token = state.next;
    state.handles.insert(token, Handle { id, offset: 0 });
    token as TEE_ObjectHandle
}
fn input(id: *const c_void, length: usize) -> Vec<u8> {
    // SAFETY: The production adapter passes a live object-id or snapshot slice of this length.
    unsafe { std::slice::from_raw_parts(id.cast::<u8>(), length).to_vec() }
}
pub fn TEE_OpenPersistentObject(
    _: u32,
    id: *const c_void,
    length: usize,
    _: u32,
    output: *mut TEE_ObjectHandle,
) -> u32 {
    let id = input(id, length);
    let mut state = backend();
    if !state.objects.contains_key(&id) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    if id == ANCHOR && state.handles.values().any(|handle| handle.id == id) {
        return ERROR_CONFLICT;
    }
    let handle = allocate(&mut state, id);
    // SAFETY: The production adapter supplies its live local output handle.
    unsafe {
        *output = handle;
    }
    TEE_SUCCESS
}
pub fn TEE_CreatePersistentObject(
    _: u32,
    id: *const c_void,
    length: usize,
    flags: u32,
    _: TEE_ObjectHandle,
    bytes: *const c_void,
    count: usize,
    output: *mut TEE_ObjectHandle,
) -> u32 {
    let id = input(id, length);
    let data = input(bytes, count);
    let mut state = backend();
    if state.fail_create.as_ref() == Some(&id) {
        return ERROR_GENERIC;
    }
    if state.objects.contains_key(&id) && flags & 0x400 == 0 {
        return ERROR_CONFLICT;
    }
    state.objects.insert(id.clone(), data);
    state.creates += 1;
    let handle = allocate(&mut state, id);
    // SAFETY: The production adapter supplies its live local output handle.
    unsafe {
        *output = handle;
    }
    TEE_SUCCESS
}
pub fn TEE_CloseObject(handle: TEE_ObjectHandle) {
    backend().handles.remove(&(handle as usize));
}
pub fn TEE_GetObjectInfo1(handle: TEE_ObjectHandle, info: *mut TEE_ObjectInfo) -> u32 {
    let state = backend();
    let id = &state.handles.get(&(handle as usize)).unwrap().id;
    // SAFETY: The adapter owns a live local ObjectInfo value for this synchronous call.
    unsafe {
        (*info).dataSize = state.objects[id].len();
    }
    TEE_SUCCESS
}
pub fn TEE_SeekObjectData(handle: TEE_ObjectHandle, position: usize, _: TEE_Whence) -> u32 {
    backend()
        .handles
        .get_mut(&(handle as usize))
        .unwrap()
        .offset = position;
    TEE_SUCCESS
}
pub fn TEE_ReadObjectData(
    handle: TEE_ObjectHandle,
    bytes: *mut c_void,
    count: usize,
    received: *mut usize,
) -> u32 {
    let mut state = backend();
    let object = &state.handles[&(handle as usize)];
    let data = &state.objects[&object.id];
    let end = object.offset.saturating_add(count).min(data.len());
    let offset = object.offset.min(data.len());
    let amount = end - offset;
    // SAFETY: The adapter provides a writable buffer of count bytes and a live count output.
    unsafe {
        ptr::copy_nonoverlapping(data[offset..end].as_ptr(), bytes.cast(), amount);
        *received = amount;
    }
    state.handles.get_mut(&(handle as usize)).unwrap().offset = end;
    TEE_SUCCESS
}
pub fn TEE_WriteObjectData(handle: TEE_ObjectHandle, bytes: *const c_void, count: usize) -> u32 {
    let data = input(bytes, count);
    let mut state = backend();
    let object = &state.handles[&(handle as usize)];
    let id = object.id.clone();
    let offset = object.offset;
    if id == ANCHOR && state.fail_anchor_write {
        return ERROR_GENERIC;
    }
    let target = state.objects.get_mut(&id).unwrap();
    target.resize(target.len().max(offset + count), 0);
    target[offset..offset + count].copy_from_slice(&data);
    state.writes += 1;
    state.handles.get_mut(&(handle as usize)).unwrap().offset += count;
    TEE_SUCCESS
}

#[test]
fn new_empty_vault_initializes_then_ensure_is_read_only() {
    let _case = case();
    assert_eq!(
        GpPersistence::ensure_initialized().unwrap(),
        VaultEnsureResult::Initialized
    );
    let original = snapshot();
    let written = counters();
    assert_eq!(original.len(), 3);
    assert_eq!(
        GpPersistence::ensure_initialized().unwrap(),
        VaultEnsureResult::AlreadyReady
    );
    assert_eq!(snapshot(), original);
    assert_eq!(counters(), written);
    assert!(backend().handles.is_empty());
}

#[test]
fn existing_ready_credentials_are_validated_without_rewriting() {
    let _case = case();
    GpPersistence::ensure_initialized().unwrap();
    let persistence = GpPersistence::open(false).unwrap();
    let mut vault = store::Vault::from_storage(persistence).unwrap();
    let put = json!({"namespace":"fixture","credential_ref":"a".repeat(32),
        "operation_id":"b".repeat(32),"profile_id":"deepseek-prod-v1","expected_version":"0"});
    vault.put(&put, b"synthetic-firstboot-fixture-key").unwrap();
    drop(vault);
    let original = snapshot();
    let written = counters();
    assert_eq!(
        GpPersistence::ensure_initialized().unwrap(),
        VaultEnsureResult::AlreadyReady
    );
    assert_eq!(snapshot(), original);
    assert_eq!(counters(), written);
}

#[test]
fn legal_partial_bootstrap_resumes_with_the_same_anchor_and_slot() {
    let _case = case();
    backend().fail_create = Some(SLOT1.to_vec());
    assert!(GpPersistence::ensure_initialized().is_err());
    let partial = snapshot();
    assert!(partial.contains_key(ANCHOR));
    assert!(partial.contains_key(SLOT0));
    assert!(!partial.contains_key(SLOT1));
    assert!(backend().handles.is_empty());
    backend().fail_create = None;
    assert_eq!(
        GpPersistence::ensure_initialized().unwrap(),
        VaultEnsureResult::Initialized
    );
    assert_eq!(snapshot()[SLOT0], partial[SLOT0]);
    assert_eq!(&snapshot()[ANCHOR][16..32], &partial[ANCHOR][16..32]);
    assert_eq!(snapshot()[SLOT0], snapshot()[SLOT1]);
}

#[test]
fn completed_bootstrap_slots_resume_after_anchor_publish_failure() {
    let _case = case();
    backend().fail_anchor_write = true;
    assert!(GpPersistence::ensure_initialized().is_err());
    let partial = snapshot();
    assert_eq!(partial.len(), 3);
    let creates = counters().0;
    backend().fail_anchor_write = false;
    assert_eq!(
        GpPersistence::ensure_initialized().unwrap(),
        VaultEnsureResult::Initialized
    );
    assert_eq!(counters().0, creates);
    assert_eq!(snapshot()[SLOT0], partial[SLOT0]);
}

#[test]
fn orphan_slots_without_anchor_are_never_initialized_over() {
    let _case = case();
    backend()
        .objects
        .insert(SLOT0.to_vec(), b"existing-orphan-slot".to_vec());
    let original = snapshot();
    assert!(GpPersistence::ensure_initialized().is_err());
    assert_eq!(snapshot(), original);
    assert_eq!(counters(), (0, 0));
}

#[test]
fn corrupt_anchor_or_ready_slot_is_never_repaired_by_ensure() {
    let _case = case();
    for object in [ANCHOR, SLOT0, SLOT1] {
        *backend() = Backend::default();
        GpPersistence::ensure_initialized().unwrap();
        backend().objects.get_mut(object).unwrap()[0] ^= 1;
        let original = snapshot();
        let written = counters();
        assert!(GpPersistence::ensure_initialized().is_err());
        assert_eq!(snapshot(), original);
        assert_eq!(counters(), written);
    }
}

#[test]
fn corrupt_bootstrap_slot_is_never_overwritten() {
    let _case = case();
    backend().fail_create = Some(SLOT1.to_vec());
    assert!(GpPersistence::ensure_initialized().is_err());
    backend().fail_create = None;
    backend().objects.get_mut(SLOT0).unwrap()[0] ^= 1;
    let original = snapshot();
    let written = counters();
    assert!(GpPersistence::ensure_initialized().is_err());
    assert_eq!(snapshot(), original);
    assert_eq!(counters(), written);
}

#[test]
fn missing_ready_slot_fails_without_reinitialization() {
    let _case = case();
    GpPersistence::ensure_initialized().unwrap();
    backend().objects.remove(SLOT1);
    let original = snapshot();
    let written = counters();
    assert!(GpPersistence::ensure_initialized().is_err());
    assert_eq!(snapshot(), original);
    assert_eq!(counters(), written);
}

#[test]
fn existing_storage_owner_prevents_competing_ensure() {
    let _case = case();
    GpPersistence::ensure_initialized().unwrap();
    let persistence = GpPersistence::open(false).unwrap();
    let original = snapshot();
    let written = counters();
    assert!(GpPersistence::ensure_initialized().is_err());
    assert_eq!(snapshot(), original);
    assert_eq!(counters(), written);
    drop(persistence);
    assert_eq!(
        GpPersistence::ensure_initialized().unwrap(),
        VaultEnsureResult::AlreadyReady
    );
}

#[test]
fn original_open_modes_keep_their_fail_closed_contracts() {
    let _case = case();
    assert!(GpPersistence::open(false).is_err());
    assert!(snapshot().is_empty());
    let bootstrap = GpPersistence::open(true).unwrap();
    drop(bootstrap);
    assert!(GpPersistence::open(false).is_err());
    GpPersistence::ensure_initialized().unwrap();
    let original = snapshot();
    let written = counters();
    assert!(GpPersistence::open(true).is_err());
    assert_eq!(snapshot(), original);
    assert_eq!(counters(), written);
    assert_eq!(VaultEnsureResult::Initialized.code(), "INITIALIZED");
    assert_eq!(VaultEnsureResult::AlreadyReady.code(), "ALREADY_READY");
}
