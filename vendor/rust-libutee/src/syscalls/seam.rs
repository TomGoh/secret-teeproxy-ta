// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Testable wrapper seam over the macro-generated inter-TA syscall entries.
//!
//! `TEE_OpenTASession` and `TEE_InvokeTACommand` build an `utee_params` from
//! the caller's `TEE_Param` array and must hand the kernel the address of
//! that structure, so the kernel's parameter handling and the SDK write-back
//! path (`update_out_param`) stay coupled to the same memory. The
//! macro-generated entries execute raw `svc`/`syscall` instructions, which
//! trap on a host test builder, so those argument words cannot be observed
//! there directly.
//!
//! This module is the single call path for the two arity-5 inter-TA
//! entries. Production builds forward 1:1 to the syscall entry with the
//! same signature and argument words and no extra state. `cargo test`
//! builds instead record the full five-argument invocation into a
//! thread-local and emulate the kernel-side contract (output params,
//! session handle, origin) through the captured addresses.

use core::ffi::c_ulong;

#[cfg(not(test))]
use super::syscall_table::{_utee_invoke_ta_command, _utee_open_ta_session};
#[cfg(test)]
use super::syscall_table::{TEE_SCN_INVOKE_TA_COMMAND, TEE_SCN_OPEN_TA_SESSION};
#[cfg(test)]
use crate::tee_api_defines::{
    TEE_ORIGIN_TEE, TEE_PARAM_TYPE_GET, TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
    TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_SUCCESS,
};
use crate::tee_api_types::TEE_UUID;
use crate::utee_types::utee_params;

#[cfg(test)]
use std::cell::RefCell;

/// One captured inter-TA syscall: the syscall number, the five argument
/// words in syscall positional order, and the `utee_params` snapshot read
/// from the params argument while the emulated syscall was in flight.
#[cfg(test)]
pub struct CapturedSyscall {
    pub nr: usize,
    pub args: [usize; 5],
    pub params_snapshot: utee_params,
}

/// Values the emulated kernel writes into the `utee_params` output slots
/// during `invoke_ta_command`. Tests assert they round-trip into the
/// caller's output parameters, proving the syscall received the address of
/// the very structure the SDK reads back after the call.
#[cfg(test)]
pub const EMULATED_OUTPUT_VALS: [u64; 8] = [
    0x1111_1010,
    0x1111_2020,
    0x1111_3030,
    0x1111_4040,
    0x1111_5050,
    0x1111_6060,
    0x1111_7070,
    0x1111_8080,
];

/// Non-zero session handle the emulated kernel reports for a successful
/// `open_ta_session`, matching the kernel's non-zero handle contract.
#[cfg(test)]
pub const EMULATED_OPEN_SESSION_HANDLE: u32 = 0x5E55_1234;

#[cfg(test)]
thread_local! {
    static LAST_CAPTURED: RefCell<Option<CapturedSyscall>> = RefCell::new(None);
}

#[cfg(test)]
fn record(nr: usize, args: [usize; 5], params: *mut utee_params) {
    // The snapshot must be taken while the caller's stack frame is alive;
    // reading the params address after `TEE_InvokeTACommand` returns would
    // touch dead stack memory.
    let params_snapshot = unsafe { params.read() };
    LAST_CAPTURED.with(|slot| {
        *slot.borrow_mut() = Some(CapturedSyscall {
            nr,
            args,
            params_snapshot,
        });
    });
}

/// Take the most recently captured inter-TA syscall, if any.
#[cfg(test)]
pub fn take_last_captured() -> Option<CapturedSyscall> {
    LAST_CAPTURED.with(|slot| slot.borrow_mut().take())
}

/// Seamed `_utee_open_ta_session`: forwards to the syscall entry unchanged.
#[cfg(not(test))]
#[inline]
pub(crate) unsafe fn open_ta_session(
    dest: *const TEE_UUID,
    cancel_req_to: c_ulong,
    params: *mut utee_params,
    sess: *mut u32,
    ret_orig: *mut u32,
) -> usize {
    unsafe { _utee_open_ta_session(dest, cancel_req_to, params, sess, ret_orig) }
}

/// Seamed `_utee_open_ta_session` for test builds: capture and emulate the
/// kernel-side contract instead of trapping on the host.
#[cfg(test)]
pub(crate) unsafe fn open_ta_session(
    dest: *const TEE_UUID,
    cancel_req_to: c_ulong,
    params: *mut utee_params,
    sess: *mut u32,
    ret_orig: *mut u32,
) -> usize {
    record(
        TEE_SCN_OPEN_TA_SESSION,
        [
            dest as usize,
            cancel_req_to as usize,
            params as usize,
            sess as usize,
            ret_orig as usize,
        ],
        params,
    );
    // Emulate the kernel-side write-backs of a successful open: a fresh
    // non-zero session handle and the origin of the result.
    unsafe {
        *sess = EMULATED_OPEN_SESSION_HANDLE;
        if !ret_orig.is_null() {
            *ret_orig = TEE_ORIGIN_TEE;
        }
    }
    TEE_SUCCESS as usize
}

/// Seamed `_utee_invoke_ta_command`: forwards to the syscall entry
/// unchanged.
#[cfg(not(test))]
#[inline]
pub(crate) unsafe fn invoke_ta_command(
    sess: c_ulong,
    cancel_req_to: c_ulong,
    cmd_id: c_ulong,
    params: *mut utee_params,
    ret_orig: *mut u32,
) -> usize {
    unsafe { _utee_invoke_ta_command(sess, cancel_req_to, cmd_id, params, ret_orig) }
}

/// Seamed `_utee_invoke_ta_command` for test builds: capture and emulate the
/// kernel-side contract instead of trapping on the host.
#[cfg(test)]
pub(crate) unsafe fn invoke_ta_command(
    sess: c_ulong,
    cancel_req_to: c_ulong,
    cmd_id: c_ulong,
    params: *mut utee_params,
    ret_orig: *mut u32,
) -> usize {
    record(
        TEE_SCN_INVOKE_TA_COMMAND,
        [
            sess as usize,
            cancel_req_to as usize,
            cmd_id as usize,
            params as usize,
            ret_orig as usize,
        ],
        params,
    );
    // Emulate the kernel writing output parameter values through the params
    // address received by the syscall. Only output/inout slots are written:
    // the kernel contract never writes back input parameters, and the caller
    // must still see its own input values after the call.
    unsafe {
        let types = (*params).types as u32;
        for i in 0..4u32 {
            if matches!(
                TEE_PARAM_TYPE_GET(types, i),
                TEE_PARAM_TYPE_VALUE_OUTPUT
                    | TEE_PARAM_TYPE_VALUE_INOUT
                    | TEE_PARAM_TYPE_MEMREF_OUTPUT
                    | TEE_PARAM_TYPE_MEMREF_INOUT
            ) {
                (*params).vals[(i * 2) as usize] = EMULATED_OUTPUT_VALS[(i * 2) as usize];
                (*params).vals[(i * 2 + 1) as usize] = EMULATED_OUTPUT_VALS[(i * 2 + 1) as usize];
            }
        }
        if !ret_orig.is_null() {
            *ret_orig = TEE_ORIGIN_TEE;
        }
    }
    TEE_SUCCESS as usize
}
