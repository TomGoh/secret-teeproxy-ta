// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! GP instance panic: notify Main on the in-flight invoke connection (P0-A).

use std::{
    cell::Cell,
    sync::OnceLock,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use crossbeam_channel::Sender;
use rust_utee::tee_api_defines::TEE_ERROR_TARGET_DEAD;

use teec_protocol::{Parameters, TEE_Response};

thread_local! {
    static INVOKE_RESP: Cell<Option<Sender<TEE_Response>>> = const { Cell::new(None) };
    static INVOKE_PARAMS: Cell<Option<Parameters>> = const { Cell::new(None) };
}

/// Set after `TEE_Panic` / `xtee_ta_panic_notify`; Main drains CloseSession then exits.
pub static INSTANCE_PANICKED: AtomicBool = AtomicBool::new(false);

/// Fast-path `CloseSession` completed after panic (CA can finish `TEEC_CloseSession`).
pub static PANIC_CLOSE_DONE: AtomicBool = AtomicBool::new(false);

static PANIC_AT: OnceLock<Instant> = OnceLock::new();

/// After panic, keep the listener open briefly for `CloseSession` if the CA sends it.
const PANIC_LISTENER_GRACE: Duration = Duration::from_secs(2);

pub fn instance_is_panicked() -> bool {
    INSTANCE_PANICKED.load(Ordering::SeqCst)
}

pub fn mark_panic_close_done() {
    PANIC_CLOSE_DONE.store(true, Ordering::SeqCst);
}

/// When `instance_keep_alive` is false: stop listener after Close ack or grace (no CA hang).
/// When true: never exit the listener loop due to panic alone.
pub fn panic_listener_should_exit(active_connections: usize, instance_keep_alive: bool) -> bool {
    if !instance_is_panicked() || active_connections > 0 || instance_keep_alive {
        return false;
    }
    if PANIC_CLOSE_DONE.load(Ordering::SeqCst) {
        return true;
    }
    PANIC_AT
        .get()
        .is_some_and(|t| t.elapsed() > PANIC_LISTENER_GRACE)
}

fn record_panic_time() {
    let _ = PANIC_AT.set(Instant::now());
}

pub fn install_invoke_context(resp_tx: Sender<TEE_Response>, params: Parameters) {
    INVOKE_RESP.set(Some(resp_tx));
    INVOKE_PARAMS.set(Some(params));
}

pub fn clear_invoke_context() {
    INVOKE_RESP.set(None);
    INVOKE_PARAMS.set(None);
}

/// Called from `rust-libutee` `_utee_panic` when built with `xtee-panic-notify`.
#[unsafe(no_mangle)]
pub extern "C" fn xtee_ta_panic_notify(panic_code: u32) {
    INSTANCE_PANICKED.store(true, Ordering::SeqCst);
    record_panic_time();
    let _ = panic_code;
    let resp_tx = INVOKE_RESP.with(|c| c.take());
    let params = INVOKE_PARAMS.with(|c| c.take());
    if let (Some(tx), Some(params)) = (resp_tx, params) {
        let _ = tx.send(TEE_Response::InvokeCommand {
            params,
            result: TEE_ERROR_TARGET_DEAD,
        });
    }
}
