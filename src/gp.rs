//! GP storage adapter. Construct and use it on the dedicated storage thread.
use crate::store::{Persistence, SNAPSHOT_MAX, validate_snapshot};
use rust_libutee::*;
use sha2::{Digest, Sha256};
use std::{ptr, thread::ThreadId};

const ANCHOR: &[u8] = b"lsp.v1.vault.anchor";
const SLOTS: [&[u8]; 2] = [b"lsp.v1.vault.0", b"lsp.v1.vault.1"];

struct Object {
    raw: usize,
    owner: ThreadId,
}
impl Object {
    fn handle(&self) -> Result<TEE_ObjectHandle, String> {
        if self.owner != std::thread::current().id() {
            return Err("GP object used by another thread".into());
        }
        Ok(self.raw as TEE_ObjectHandle)
    }
}
impl Drop for Object {
    fn drop(&mut self) {
        if self.owner == std::thread::current().id() {
            TEE_CloseObject(self.raw as TEE_ObjectHandle);
        }
    }
}

fn checked_handle(result: u32, handle: TEE_ObjectHandle) -> Result<Object, String> {
    if result != TEE_SUCCESS || handle.is_null() {
        return Err(format!("GP object unavailable ({result:#x})"));
    }
    Ok(Object {
        raw: handle as usize,
        owner: std::thread::current().id(),
    })
}
fn open(id: &[u8], flags: u32) -> Result<Option<Object>, String> {
    let mut handle = ptr::null_mut();
    let result = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        id.as_ptr().cast(),
        id.len(),
        flags,
        &mut handle,
    );
    if result == TEE_ERROR_ITEM_NOT_FOUND {
        return Ok(None);
    }
    checked_handle(result, handle).map(Some)
}
fn create(id: &[u8], flags: u32, bytes: &[u8]) -> Result<Object, String> {
    let mut handle = ptr::null_mut();
    let result = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,
        id.as_ptr().cast(),
        id.len(),
        flags,
        ptr::null_mut(),
        bytes.as_ptr().cast(),
        bytes.len(),
        &mut handle,
    );
    checked_handle(result, handle)
}
fn read(object: &Object, max: usize) -> Result<Vec<u8>, String> {
    let handle = object.handle()?;
    let mut info = TEE_ObjectInfo::default();
    let result = TEE_GetObjectInfo1(handle, &mut info);
    if result != TEE_SUCCESS || info.dataSize > max {
        return Err("GP object size or metadata invalid".into());
    }
    if TEE_SeekObjectData(handle, 0, TEE_Whence::TEE_DATA_SEEK_SET) != TEE_SUCCESS {
        return Err("GP seek failed".into());
    }
    let mut bytes = vec![0; info.dataSize];
    let mut offset = 0;
    while offset < bytes.len() {
        let amount = (bytes.len() - offset).min(32768);
        let mut count = 0;
        let result = TEE_ReadObjectData(
            handle,
            bytes[offset..].as_mut_ptr().cast(),
            amount,
            &mut count,
        );
        if result != TEE_SUCCESS || count == 0 || count > amount {
            return Err("GP object short or failed read".into());
        }
        offset += count;
    }
    let mut extra = 0u8;
    let mut count = 0;
    let result = TEE_ReadObjectData(handle, (&mut extra as *mut u8).cast(), 1, &mut count);
    if result != TEE_SUCCESS || count != 0 {
        return Err("GP object has trailing data or failed EOF read".into());
    }
    Ok(bytes)
}
fn read_slot(id: &[u8]) -> Result<Option<Vec<u8>>, String> {
    open(id, 1)?
        .map(|object| read(&object, SNAPSHOT_MAX))
        .transpose()
}

fn anchor_bytes(id: [u8; 16], ready: bool) -> Vec<u8> {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(b"LSPANC1\0");
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&64u16.to_le_bytes());
    data.extend_from_slice(&u32::from(ready).to_le_bytes());
    data.extend_from_slice(&id);
    let mut hash = Sha256::new();
    hash.update(b"LSP-ANCHOR-v1\0");
    hash.update(&data);
    data.extend_from_slice(&hash.finalize());
    data
}
fn parse_anchor(bytes: &[u8]) -> Result<([u8; 16], bool), String> {
    if bytes.len() != 64 {
        return Err("GP anchor length".into());
    }
    let id: [u8; 16] = bytes[16..32].try_into().map_err(|_| "GP anchor UUID")?;
    let ready = u32::from_le_bytes(bytes[12..16].try_into().map_err(|_| "GP anchor state")?);
    if id == [0; 16] || ready > 1 || bytes != anchor_bytes(id, ready == 1) {
        return Err("GP anchor validation failed".into());
    }
    Ok((id, ready == 1))
}

pub struct GpPersistence {
    anchor: Object,
    vault_id: [u8; 16],
    ready: bool,
}
impl GpPersistence {
    pub fn open(maintenance_initialize: bool) -> Result<Self, String> {
        let anchor = match open(ANCHOR, 7)? {
            Some(value) => value,
            None if maintenance_initialize => {
                if read_slot(SLOTS[0])?.is_some() || read_slot(SLOTS[1])?.is_some() {
                    return Err("Refusing initialization over existing slots".into());
                }
                create(
                    ANCHOR,
                    7,
                    &anchor_bytes(*uuid::Uuid::new_v4().as_bytes(), false),
                )?
            }
            None => return Err("Vault not initialized".into()),
        };
        let (vault_id, ready) = parse_anchor(&read(&anchor, 64)?)?;
        if ready && maintenance_initialize {
            return Err("READY vault cannot be initialized again".into());
        }
        if !ready && !maintenance_initialize {
            return Err("Vault initialization incomplete".into());
        }
        Ok(Self {
            anchor,
            vault_id,
            ready,
        })
    }
    pub fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }
    fn slots(&self) -> Result<[Option<Vec<u8>>; 2], String> {
        Ok([read_slot(SLOTS[0])?, read_slot(SLOTS[1])?])
    }
    fn generations(&self, slots: &[Option<Vec<u8>>; 2]) -> Result<[u64; 2], String> {
        let mut generations = [0; 2];
        for (i, data) in slots.iter().enumerate() {
            let data = data.as_ref().ok_or("READY vault slot missing")?;
            let info = validate_snapshot(data).map_err(|_| "GP snapshot invalid")?;
            if info.vault_id != self.vault_id {
                return Err("GP vault identity mismatch".into());
            }
            generations[i] = info.generation;
        }
        if generations[0].abs_diff(generations[1]) > 1
            || (generations[0] == generations[1] && slots[0] != slots[1])
        {
            return Err("GP snapshot generation mismatch".into());
        }
        Ok(generations)
    }
}
impl Persistence for GpPersistence {
    fn load(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.anchor.handle()?;
        let mut slots = self.slots()?;
        if !self.ready {
            for bytes in slots.iter().flatten() {
                let info = validate_snapshot(bytes).map_err(|_| "Invalid BOOTSTRAP snapshot")?;
                if info.vault_id != self.vault_id
                    || info.generation != 0
                    || u32::from_le_bytes(
                        bytes[24..28]
                            .try_into()
                            .map_err(|_| "snapshot record count")?,
                    ) != 0
                {
                    return Err("Cannot resume nonempty vault initialization".into());
                }
            }
            return Ok(None);
        }
        let generations = self.generations(&slots)?;
        Ok(slots[usize::from(generations[1] > generations[0])].take())
    }
    fn commit(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.anchor.handle()?;
        let info = validate_snapshot(bytes).map_err(|_| "Invalid candidate snapshot")?;
        if info.vault_id != self.vault_id {
            return Err("Candidate vault mismatch".into());
        }
        if !self.ready {
            if info.generation != 0
                || u32::from_le_bytes(bytes[24..28].try_into().map_err(|_| "snapshot count")?) != 0
            {
                return Err("BOOTSTRAP requires empty generation zero".into());
            }
            for id in SLOTS {
                match read_slot(id)? {
                    Some(existing) if existing == bytes => {}
                    Some(_) => return Err("BOOTSTRAP slot differs".into()),
                    None => {
                        drop(create(id, 7, bytes)?);
                    }
                }
            }
            if self.slots()?.iter().any(|s| s.as_deref() != Some(bytes)) {
                return Err("Initialization readback failed".into());
            }
            let anchor = anchor_bytes(self.vault_id, true);
            let handle = self.anchor.handle()?;
            if TEE_SeekObjectData(handle, 0, TEE_Whence::TEE_DATA_SEEK_SET) != TEE_SUCCESS
                || TEE_WriteObjectData(handle, anchor.as_ptr().cast(), anchor.len()) != TEE_SUCCESS
                || read(&self.anchor, 64)? != anchor
            {
                return Err("Anchor publish failed".into());
            }
            self.ready = true;
            return Ok(());
        }
        let slots = self.slots()?;
        let generations = self.generations(&slots)?;
        let newest = generations[0].max(generations[1]);
        if info.generation != newest.checked_add(1).ok_or("Generation overflow")? {
            return Err("Candidate generation not next".into());
        }
        let target = usize::from(generations[1] < generations[0]);
        // Failure may occur after publish. Vault always performs authoritative readback.
        drop(create(SLOTS[target], 0x407, bytes)?);
        Ok(())
    }
}
