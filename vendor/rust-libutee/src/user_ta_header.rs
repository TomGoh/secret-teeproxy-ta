// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.
//
// This file has been modified by KylinSoft on 2025.
//
// Rust translation of OP-TEE `user_ta_header.h` (TA image layout, flags, and
// linker-provided symbols). Property records `ta_props` / `ta_num_props` are
// defined in `api::user_ta_headers`; this module does not re-declare them.

#![allow(non_camel_case_types, non_snake_case)]

use crate::tee_api_types::TEE_UUID;

pub use crate::api::tee_api_property::{
    UserTaPropType as user_ta_prop_type, UserTaProperty as user_ta_property,
};

// --- Bit helpers (C BIT32 / SHIFT_U32 / GENMASK_32) ---

#[inline]
pub const fn bit32(nr: u32) -> u32 {
    1u32 << nr
}

#[inline]
pub const fn bit64(nr: u32) -> u64 {
    1u64 << nr
}

#[inline]
pub const fn shift_u32(v: u32, shift: u32) -> u32 {
    v << shift
}

#[inline]
pub const fn shift_u64(v: u64, shift: u32) -> u64 {
    v << shift
}

#[inline]
pub const fn bit(nr: u32) -> u32 {
    bit32(nr)
}

/// Inclusive bit mask for the low 32 bits: bits `[hi..lo]`.
/// Caller must ensure `lo <= hi < 32` (matches Linux `GENMASK_32`).
#[inline]
pub const fn genmask_32(hi: u32, lo: u32) -> u32 {
    (!0u32 >> (31 - hi)) & (!0u32 << lo)
}

// --- TA flags (OP-TEE) ---

pub const TA_FLAG_USER_MODE: u32 = 0; // Deprecated, was BIT32(0)
pub const TA_FLAG_EXEC_DDR: u32 = 0; // Deprecated, was BIT32(1)
pub const TA_FLAG_SINGLE_INSTANCE: u32 = bit32(2);
pub const TA_FLAG_MULTI_SESSION: u32 = bit32(3);
pub const TA_FLAG_INSTANCE_KEEP_ALIVE: u32 = bit32(4); // remains after last close
pub const TA_FLAG_SECURE_DATA_PATH: u32 = bit32(5); // accesses SDP memory
pub const TA_FLAG_REMAP_SUPPORT: u32 = 0; // Deprecated, was BIT32(6)
pub const TA_FLAG_CACHE_MAINTENANCE: u32 = bit32(7); // use cache flush syscall
/// TA instance can execute multiple sessions concurrently (pseudo-TAs only).
pub const TA_FLAG_CONCURRENT: u32 = bit32(8);
pub const TA_FLAG_DEVICE_ENUM: u32 = bit32(9); // without tee-supplicant
pub const TA_FLAG_DEVICE_ENUM_SUPP: u32 = bit32(10); // with tee-supplicant
/// See also "gpd.ta.doesNotCloseHandleOnCorruptObject"
pub const TA_FLAG_DONT_CLOSE_HANDLE_ON_CORRUPT_OBJECT: u32 = bit32(11);
pub const TA_FLAG_DEVICE_ENUM_TEE_STORAGE_PRIVATE: u32 = bit32(12); // with TEE_STORAGE_PRIVATE
/// Don't restart a TA with TA_FLAG_INSTANCE_KEEP_ALIVE set if it has crashed.
pub const TA_FLAG_INSTANCE_KEEP_CRASHED: u32 = bit32(13);

pub const TA_FLAGS_MASK: u32 = genmask_32(13, 0);

/// Binary layout of the `.ta_head` section (GP / OP-TEE).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ta_head {
    pub uuid: TEE_UUID,
    pub stack_size: u32,
    pub flags: u32,
    pub depr_entry: u64,
}

// --- GP TA property string keys (manifest) ---

pub const TA_PROP_STR_SINGLE_INSTANCE: &[u8] = b"gpd.ta.singleInstance\0";
pub const TA_PROP_STR_MULTI_SESSION: &[u8] = b"gpd.ta.multiSession\0";
pub const TA_PROP_STR_KEEP_ALIVE: &[u8] = b"gpd.ta.instanceKeepAlive\0";
pub const TA_PROP_STR_KEEP_CRASHED: &[u8] = b"optee.ta.instanceKeepCrashed\0";
pub const TA_PROP_STR_DATA_SIZE: &[u8] = b"gpd.ta.dataSize\0";
pub const TA_PROP_STR_STACK_SIZE: &[u8] = b"gpd.ta.stackSize\0";
pub const TA_PROP_STR_VERSION: &[u8] = b"gpd.ta.version\0";
pub const TA_PROP_STR_DESCRIPTION: &[u8] = b"gpd.ta.description\0";
pub const TA_PROP_STR_ENDIAN: &[u8] = b"gpd.ta.endian\0";
pub const TA_PROP_STR_DOES_NOT_CLOSE_HANDLE_ON_CORRUPT_OBJECT: &[u8] =
    b"gpd.ta.doesNotCloseHandleOnCorruptObject\0";
