//! In-process APK bridge. Each opaque handle owns one SDK thread and context.
//! Cancel/close are atomic requests. Only that owner can free its SDK objects.
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CString, c_char};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

use super::*;
use zeroize::{Zeroize, Zeroizing};

const HANDLE_LIMIT: usize = 32;
const ENVELOPE_MAX: usize = OUTPUT_FRAME_MAX + 8;
static HANDLES: OnceLock<Mutex<HashMap<u64, Arc<Worker>>>> = OnceLock::new();
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
thread_local! {static LAST_ERROR:RefCell<CString>=RefCell::new(CString::new("native operation failed").unwrap());}

struct State {
    cancel: AtomicBool,
    close: AtomicBool,
    released: AtomicBool,
    inflight: AtomicBool,
}
struct Worker {
    tx: mpsc::SyncSender<Command>,
    state: Arc<State>,
}
enum Command {
    Exchange(Zeroizing<Vec<u8>>, usize, mpsc::Sender<Result<Vec<u8>>>),
    Raw(
        crate::driver::RawConfig,
        Vec<u8>,
        Option<mpsc::SyncSender<StreamEvent>>,
        mpsc::Sender<Result<Vec<u8>>>,
    ),
    Wake,
}
struct StreamEvent {
    kind: u32,
    bytes: Vec<u8>,
    accepted: mpsc::Sender<Result<()>>,
}

struct StreamDelivery {
    events: mpsc::SyncSender<StreamEvent>,
    state: Arc<State>,
    deadline: Option<Instant>,
}
impl crate::driver::HttpSink for StreamDelivery {
    fn event(&mut self, kind: u32, bytes: &[u8]) -> Result<()> {
        let (accepted, response) = mpsc::channel();
        // Exactly one event is in flight. The owner cannot read/STEP again
        // until the caller has consumed it and acknowledged its callback.
        self.events
            .send(StreamEvent {
                kind,
                bytes: bytes.to_vec(),
                accepted,
            })
            .map_err(|_| "stream consumer disconnected")?;
        loop {
            if self.state.cancel.load(Ordering::Acquire) {
                return Err("raw request cancelled".into());
            }
            if self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            {
                return Err("raw request overall deadline".into());
            }
            match response.recv_timeout(Duration::from_millis(50)) {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("stream consumer disconnected".into());
                }
            }
        }
    }
}

#[derive(Default)]
struct Identity {
    epoch: String,
    nonce: String,
    request_id: Option<[u8; 16]>,
    next: u64,
    terminal: bool,
}
impl Identity {
    fn observe(&mut self, reply: &Frame) {
        self.epoch = reply.metadata["ta_epoch"].as_str().unwrap_or("").into();
        self.nonce = reply.metadata["session_nonce"]
            .as_str()
            .unwrap_or("")
            .into();
        self.next = reply.call_seq.saturating_add(1);
        if reply.opcode == REQUEST_OPEN && reply.status == OK {
            self.request_id = Some(reply.request_id);
        }
        self.terminal = matches!(
            reply.metadata["state"].as_str(),
            Some("ENDED" | "CANCELLED" | "EXPIRED" | "FAILED")
        );
    }
    fn cancel(&self, teec: &mut Teec) {
        if let Some(request_id) = self.request_id {
            if self.terminal || self.next == 0 {
                return;
            }
            let frame = Frame {
                opcode: CANCEL,
                request_id,
                call_seq: self.next,
                status: 0,
                metadata: json!({"ta_epoch":self.epoch,"session_nonce":self.nonce,"reason":"user"}),
                payload: Vec::new(),
            };
            if let Ok(bytes) = encode_request(&frame) {
                let _ = teec.invoke(&bytes, OUTPUT_FRAME_MAX);
            }
        }
    }
}
fn handles() -> &'static Mutex<HashMap<u64, Arc<Worker>>> {
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}
fn worker(handle: u64) -> Result<Arc<Worker>> {
    handles()
        .lock()
        .map_err(|_| "handle registry poisoned")?
        .get(&handle)
        .cloned()
        .ok_or("unknown native handle".into())
}

pub fn open(cid: u32, port: u32) -> Result<u64> {
    cc_teec::configure_vsock_endpoint(cid, port).map_err(str::to_owned)?;
    {
        let registry = handles().lock().map_err(|_| "handle registry poisoned")?;
        require(registry.len() < HANDLE_LIMIT, "native handle limit")?;
    }
    let state = Arc::new(State {
        cancel: AtomicBool::new(false),
        close: AtomicBool::new(false),
        released: AtomicBool::new(false),
        inflight: AtomicBool::new(false),
    });
    let owner_state = state.clone();
    let (tx, rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("lsp-sdk-owner".into())
        .spawn(move || {
            let mut teec = match Teec::open() {
                Ok(teec) => teec,
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    owner_state.released.store(true, Ordering::Release);
                    return;
                }
            };
            if ready_tx.send(Ok(())).is_err() {
                drop(teec);
                owner_state.released.store(true, Ordering::Release);
                return;
            }
            let mut identity = Identity::default();
            let mut cancelled_response = None;
            loop {
                if owner_state.cancel.load(Ordering::Acquire)
                    || owner_state.close.load(Ordering::Acquire)
                {
                    identity.cancel(&mut teec);
                    break;
                }
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(Command::Exchange(bytes, capacity, response)) => {
                        let result =
                            teec.invoke(&bytes, capacity)
                                .and_then(|invoked| match invoked {
                                    Invoke::Capacity => {
                                        let mut envelope = E_OUTPUT_CAPACITY.to_le_bytes().to_vec();
                                        envelope.extend_from_slice(
                                            &(OUTPUT_FRAME_MAX as u32).to_le_bytes(),
                                        );
                                        Ok(envelope)
                                    }
                                    Invoke::Reply(reply) => {
                                        identity.observe(&reply);
                                        let encoded = reply
                                            .encode_reply()
                                            .map_err(|_| "reply encoding failed")?;
                                        let mut envelope = reply.status.to_le_bytes().to_vec();
                                        envelope.extend_from_slice(
                                            &(encoded.len() as u32).to_le_bytes(),
                                        );
                                        envelope.extend_from_slice(&encoded);
                                        Ok(envelope)
                                    }
                                });
                        if owner_state.cancel.load(Ordering::Acquire)
                            || owner_state.close.load(Ordering::Acquire)
                        {
                            cancelled_response = Some(response);
                            identity.cancel(&mut teec);
                            break;
                        }
                        owner_state.inflight.store(false, Ordering::Release);
                        let failed = result.is_err();
                        let _ = response.send(result);
                        // A transport/association failure makes this generation uncertain.
                        // It closes the context and cannot accept another invoke.
                        if failed {
                            break;
                        }
                    }
                    Ok(Command::Raw(config, body, events, response)) => {
                        if identity.next != 0 {
                            owner_state.inflight.store(false, Ordering::Release);
                            let _ = response.send(Err("rawCall requires a fresh handle".into()));
                            continue;
                        }
                        match Channel::hello_from(teec, "request", false) {
                            Ok(mut channel) => {
                                let mut delivery = events.map(|events| StreamDelivery {
                                    events,
                                    state: owner_state.clone(),
                                    deadline: Some(
                                        Instant::now()
                                            + Duration::from_millis(
                                                config.overall_timeout_ms as u64,
                                            ),
                                    ),
                                });
                                let sink = delivery
                                    .as_mut()
                                    .map(|sink| sink as &mut dyn crate::driver::HttpSink);
                                let result = crate::driver::request_with_sink(
                                    &mut channel,
                                    &config,
                                    &body,
                                    Some(&owner_state.cancel),
                                    sink,
                                )
                                .and_then(|result| result.encode());
                                drop(channel);
                                owner_state.inflight.store(false, Ordering::Release);
                                owner_state.released.store(true, Ordering::Release);
                                let _ = response.send(result);
                                return;
                            }
                            Err(error) => {
                                owner_state.inflight.store(false, Ordering::Release);
                                owner_state.released.store(true, Ordering::Release);
                                let _ = response.send(Err(error));
                                return;
                            }
                        }
                    }
                    Ok(Command::Wake) => {}
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            drop(teec);
            owner_state.inflight.store(false, Ordering::Release);
            owner_state.released.store(true, Ordering::Release);
            if let Some(response) = cancelled_response {
                let _ = response.send(Err(
                    "cancelled; SDK CloseSession/FinalizeContext returned".into()
                ));
            }
        })
        .map_err(|_| "SDK owner thread creation failed")?;
    match ready_rx.recv_timeout(Duration::from_secs(30)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            state.close.store(true, Ordering::Release);
            return Err("OpenSession outcome unknown; owner retains cleanup responsibility".into());
        }
    }
    let handle = NEXT_HANDLE
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map_err(|_| "handle space exhausted")?;
    let owner = Arc::new(Worker { tx, state });
    let mut registry = handles().lock().map_err(|_| "handle registry poisoned")?;
    if registry.len() >= HANDLE_LIMIT {
        owner.state.close.store(true, Ordering::Release);
        owner.state.cancel.store(true, Ordering::Release);
        let _ = owner.tx.try_send(Command::Wake);
        return Err("native handle limit".into());
    }
    registry.insert(handle, owner);
    Ok(handle)
}

pub fn exchange(handle: u64, request: &[u8], capacity: usize) -> Result<Vec<u8>> {
    require(
        capacity <= OUTPUT_FRAME_MAX,
        "output capacity exceeds LSP limit",
    )?;
    let mut validated = Frame::decode_request(request).map_err(|error| error.to_string())?;
    validated.payload.zeroize();
    let owner = worker(handle)?;
    require(
        !owner.state.close.load(Ordering::Acquire)
            && !owner.state.cancel.load(Ordering::Acquire)
            && !owner.state.released.load(Ordering::Acquire),
        "native handle is closing or released",
    )?;
    require(
        owner
            .state
            .inflight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok(),
        "native handle busy",
    )?;
    let (tx, rx) = mpsc::channel();
    if owner
        .tx
        .try_send(Command::Exchange(
            Zeroizing::new(request.to_vec()),
            capacity,
            tx,
        ))
        .is_err()
    {
        owner.state.inflight.store(false, Ordering::Release);
        return Err("SDK owner queue unavailable".into());
    }
    rx.recv_timeout(Duration::from_secs(65)).map_err(
        |_| "Invoke outcome unknown; command cannot be replayed and SDK owner remains retained",
    )?
}

/// Runs a complete bounded HTTP request on the handle's existing SDK context.
/// The rawCall owns the context through FINISH and SDK close/finalize.
pub fn raw_call(handle: u64, config: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    start_raw(handle, config, body, None)?
        .recv_timeout(Duration::from_secs(665))
        .map_err(|_| "rawCall outcome unknown; owner retains cleanup responsibility")?
}

/// Delivers byte chunks on this calling thread, with one bounded owner event.
/// The final envelope contains metadata and an empty aggregate body.
pub fn stream_call(
    handle: u64,
    config: &[u8],
    body: &[u8],
    mut callback: impl FnMut(u32, &[u8]) -> Result<()>,
) -> Result<Vec<u8>> {
    let (events, incoming) = mpsc::sync_channel(1);
    let result = start_raw(handle, config, body, Some(events))?;
    loop {
        match incoming.recv_timeout(Duration::from_millis(50)) {
            Ok(event) => {
                let accepted = callback(event.kind, &event.bytes);
                let failed = accepted.is_err();
                let _ = event.accepted.send(accepted);
                if failed {
                    // The owner sends business CANCEL and retains SDK cleanup.
                    let _ = cancel(handle);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return result.recv().map_err(|_| "stream owner disconnected")?;
            }
        }
        match result.try_recv() {
            Ok(result) => return result,
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => return Err("stream owner disconnected".into()),
        }
    }
}

fn start_raw(
    handle: u64,
    config: &[u8],
    body: &[u8],
    events: Option<mpsc::SyncSender<StreamEvent>>,
) -> Result<mpsc::Receiver<Result<Vec<u8>>>> {
    require(
        config.len() <= 4096 && body.len() <= crate::driver::MAX_REQUEST_BYTES,
        "rawCall input bounds",
    )?;
    let config: crate::driver::RawConfig =
        serde_json::from_slice(config).map_err(|_| "invalid rawCall configuration")?;
    let owner = worker(handle)?;
    require(
        !owner.state.close.load(Ordering::Acquire)
            && !owner.state.cancel.load(Ordering::Acquire)
            && !owner.state.released.load(Ordering::Acquire),
        "native handle is closing or released",
    )?;
    require(
        owner
            .state
            .inflight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok(),
        "native handle busy",
    )?;
    let (tx, rx) = mpsc::channel();
    if owner
        .tx
        .try_send(Command::Raw(config, body.to_vec(), events, tx))
        .is_err()
    {
        owner.state.inflight.store(false, Ordering::Release);
        return Err("SDK owner queue unavailable".into());
    }
    Ok(rx)
}

/// Acceptance of cancellation is separate from the observed cleanup state.
pub fn cancel(handle: u64) -> Result<()> {
    let owner = worker(handle)?;
    owner.state.cancel.store(true, Ordering::Release);
    let _ = owner.tx.try_send(Command::Wake);
    Ok(())
}

/// Returns true only after the SDK owner has returned from Close/Finalize.
pub fn close(handle: u64) -> Result<bool> {
    let owner = worker(handle)?;
    owner.state.close.store(true, Ordering::Release);
    owner.state.cancel.store(true, Ordering::Release);
    let _ = owner.tx.try_send(Command::Wake);
    if !owner.state.released.load(Ordering::Acquire) {
        return Ok(false);
    }
    handles()
        .lock()
        .map_err(|_| "handle registry poisoned")?
        .remove(&handle);
    Ok(true)
}
pub fn released(handle: u64) -> Result<bool> {
    Ok(worker(handle)?.state.released.load(Ordering::Acquire))
}

fn fail(error: String) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = CString::new(error.replace('\0', " ")).unwrap());
}
#[unsafe(no_mangle)]
pub extern "C" fn lsp_native_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}
#[unsafe(no_mangle)]
pub extern "C" fn lsp_native_open(cid: u32, port: u32) -> u64 {
    match open(cid, port) {
        Ok(handle) => handle,
        Err(error) => {
            fail(error);
            0
        }
    }
}
/// # Safety
/// Input points to `length` readable bytes. Output points to `output_capacity`
/// writable bytes, with capacity at least 32776. Buffers remain valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lsp_native_exchange(
    handle: u64,
    input: *const u8,
    length: usize,
    capacity: usize,
    output: *mut u8,
    output_capacity: usize,
) -> i64 {
    if input.is_null()
        || output.is_null()
        || length > INPUT_FRAME_MAX
        || output_capacity < ENVELOPE_MAX
    {
        fail("invalid native exchange buffers".into());
        return -1;
    }
    let input = unsafe { std::slice::from_raw_parts(input, length) };
    match exchange(handle, input, capacity) {
        Ok(bytes) => {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
            }
            bytes.len() as i64
        }
        Err(error) => {
            fail(error);
            -1
        }
    }
}
fn raw_capacity(config: &[u8]) -> Result<usize> {
    require(config.len() <= 4096, "rawCall configuration bounds")?;
    let config: crate::driver::RawConfig =
        serde_json::from_slice(config).map_err(|_| "invalid rawCall configuration")?;
    let maximum = config.max_response_bytes as usize;
    require(
        maximum > 0 && maximum <= crate::driver::MAX_AGGREGATE_BYTES,
        "raw response bounds",
    )?;
    Ok(maximum + 8192)
}

/// # Safety
/// Config points to `length` readable bytes for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lsp_native_raw_capacity(config: *const u8, length: usize) -> i64 {
    if config.is_null() || length > 4096 {
        fail("invalid rawCall configuration buffer".into());
        return -1;
    }
    match raw_capacity(unsafe { std::slice::from_raw_parts(config, length) }) {
        Ok(capacity) => capacity as i64,
        Err(error) => {
            fail(error);
            -1
        }
    }
}

/// # Safety
/// Inputs and output point to the indicated readable/writable byte ranges.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lsp_native_raw_call(
    handle: u64,
    config: *const u8,
    config_len: usize,
    body: *const u8,
    body_len: usize,
    output: *mut u8,
    capacity: usize,
) -> i64 {
    if config.is_null()
        || body.is_null()
        || output.is_null()
        || config_len > 4096
        || body_len > crate::driver::MAX_REQUEST_BYTES
    {
        fail("invalid rawCall buffers".into());
        return -1;
    }
    let config = unsafe { std::slice::from_raw_parts(config, config_len) };
    let body = unsafe { std::slice::from_raw_parts(body, body_len) };
    match raw_capacity(config) {
        Ok(required) if capacity >= required => {}
        Ok(_) => {
            fail("raw response output capacity too small".into());
            return -1;
        }
        Err(error) => {
            fail(error);
            return -1;
        }
    }
    match raw_call(handle, config, body) {
        Ok(bytes) if bytes.len() <= capacity => {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
            }
            bytes.len() as i64
        }
        Ok(_) => {
            fail("raw response encoding limit".into());
            -1
        }
        Err(error) => {
            fail(error);
            -1
        }
    }
}
/// # Safety
/// Input/output ranges remain valid through the call. `callback` and its user
/// pointer remain valid and callable on this same thread until return. Each
/// byte slice is borrowed only for the callback duration. Return zero to accept.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lsp_native_stream_call(
    handle: u64,
    config: *const u8,
    config_len: usize,
    body: *const u8,
    body_len: usize,
    callback: Option<unsafe extern "C" fn(*mut std::ffi::c_void, u32, *const u8, usize) -> i32>,
    user: *mut std::ffi::c_void,
    output: *mut u8,
    capacity: usize,
) -> i64 {
    if config.is_null()
        || body.is_null()
        || output.is_null()
        || callback.is_none()
        || config_len > 4096
        || body_len > crate::driver::MAX_REQUEST_BYTES
        || capacity < 8192
    {
        fail("invalid streamCall buffers".into());
        return -1;
    }
    let config = unsafe { std::slice::from_raw_parts(config, config_len) };
    let body = unsafe { std::slice::from_raw_parts(body, body_len) };
    let callback = callback.unwrap();
    let result = stream_call(handle, config, body, |kind, bytes| {
        if unsafe { callback(user, kind, bytes.as_ptr(), bytes.len()) } == 0 {
            Ok(())
        } else {
            Err("stream callback rejected delivery".into())
        }
    });
    match result {
        Ok(bytes) if bytes.len() <= capacity => {
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
            bytes.len() as i64
        }
        Ok(_) => {
            fail("stream metadata encoding limit".into());
            -1
        }
        Err(error) => {
            fail(error);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lsp_native_cancel(handle: u64) -> i32 {
    match cancel(handle) {
        Ok(()) => 0,
        Err(error) => {
            fail(error);
            -1
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn lsp_native_close(handle: u64) -> i32 {
    match close(handle) {
        Ok(released) => i32::from(released),
        Err(error) => {
            fail(error);
            -1
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn lsp_native_released(handle: u64) -> i32 {
    match released(handle) {
        Ok(released) => i32::from(released),
        Err(error) => {
            fail(error);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> Arc<State> {
        Arc::new(State {
            cancel: AtomicBool::new(false),
            close: AtomicBool::new(false),
            released: AtomicBool::new(false),
            inflight: AtomicBool::new(true),
        })
    }

    #[test]
    fn streaming_owner_waits_for_callback_ack_before_next_chunk() {
        use crate::driver::HttpSink;
        let (tx, rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let mut sink = StreamDelivery {
                events: tx,
                state: test_state(),
                deadline: None,
            };
            sink.event(2, b"first").unwrap();
            sink.event(2, b"second").unwrap();
            done_tx.send(()).unwrap();
        });
        let first = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(first.bytes, b"first");
        assert!(
            rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "owner emitted next chunk before callback acknowledgement"
        );
        assert!(done_rx.try_recv().is_err());
        first.accepted.send(Ok(())).unwrap();
        let second = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(second.bytes, b"second");
        second.accepted.send(Ok(())).unwrap();
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn cancellation_unblocks_owner_waiting_for_listener_and_is_per_request() {
        use crate::driver::HttpSink;
        let first = test_state();
        let other = test_state();
        let owner = first.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let mut sink = StreamDelivery {
                events: tx,
                state: owner,
                deadline: None,
            };
            done_tx.send(sink.event(2, b"chunk")).unwrap();
        });
        let _unacknowledged = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        first.cancel.store(true, Ordering::Release);
        assert!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap_err()
                .contains("cancelled")
        );
        assert!(!other.cancel.load(Ordering::Acquire));
        thread.join().unwrap();
    }

    #[test]
    fn overall_deadline_unblocks_owner_waiting_for_listener_ack() {
        use crate::driver::HttpSink;
        let (tx, rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::channel();
        let owner = std::thread::spawn(move || {
            let mut sink = StreamDelivery {
                events: tx,
                state: test_state(),
                deadline: Some(Instant::now() + Duration::from_millis(25)),
            };
            done_tx.send(sink.event(2, b"blocked-listener")).unwrap();
        });
        let _event = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap_err()
                .contains("deadline")
        );
        owner.join().unwrap();
    }

    #[test]
    fn configured_aggregate_capacity_is_bounded_and_not_always_maximum() {
        let config = |maximum| {
            serde_json::to_vec(&json!({"namespace":"test","credential_ref":"0".repeat(32),"expected_version":1,"operation":"CHAT","response_mode":"json","overall_timeout_ms":60000,"max_response_bytes":maximum})).unwrap()
        };
        assert_eq!(raw_capacity(&config(1024)).unwrap(), 1024 + 8192);
        assert_eq!(
            raw_capacity(&config(64 * 1024 * 1024)).unwrap(),
            64 * 1024 * 1024 + 8192
        );
        assert!(raw_capacity(&config(0)).is_err());
        assert!(raw_capacity(&config(64 * 1024 * 1024 + 1)).is_err());
    }

    #[test]
    fn cancellation_latches_while_inflight_and_close_waits_for_owner() {
        let id = u64::MAX;
        let (tx, _rx) = mpsc::sync_channel(1);
        let state = Arc::new(State {
            cancel: AtomicBool::new(false),
            close: AtomicBool::new(false),
            released: AtomicBool::new(false),
            inflight: AtomicBool::new(true),
        });
        handles().lock().unwrap().insert(
            id,
            Arc::new(Worker {
                tx,
                state: state.clone(),
            }),
        );
        cancel(id).unwrap();
        assert!(state.cancel.load(Ordering::Acquire));
        assert!(!close(id).unwrap());
        assert!(worker(id).is_ok());
        assert!(!released(id).unwrap());
        state.released.store(true, Ordering::Release);
        assert!(close(id).unwrap());
        assert!(worker(id).is_err());
    }

    #[test]
    fn close_only_signals_the_flag_observed_by_active_raw_pump() {
        let id = u64::MAX - 1;
        let (tx, _rx) = mpsc::sync_channel(1);
        let state = Arc::new(State {
            cancel: AtomicBool::new(false),
            close: AtomicBool::new(false),
            released: AtomicBool::new(false),
            inflight: AtomicBool::new(true),
        });
        handles().lock().unwrap().insert(
            id,
            Arc::new(Worker {
                tx,
                state: state.clone(),
            }),
        );
        assert!(!close(id).unwrap());
        assert!(state.cancel.load(Ordering::Acquire));
        assert!(state.inflight.load(Ordering::Acquire));
        assert!(!state.released.load(Ordering::Acquire));
        state.released.store(true, Ordering::Release);
        assert!(close(id).unwrap());
    }

    #[test]
    fn invalid_handles_and_buffers_are_rejected_before_sdk_calls() {
        assert!(worker(0).is_err());
        assert!(cancel(0).is_err());
        assert!(close(0).is_err());
        assert_eq!(
            unsafe { lsp_native_exchange(0, std::ptr::null(), 0, 32768, std::ptr::null_mut(), 0) },
            -1
        );
    }
}
