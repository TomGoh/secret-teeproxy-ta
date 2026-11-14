//! Session dispatcher and the single storage worker used by the GP adapter.
use crate::{
    relay::{self, Relay},
    store::{CredentialSnapshot, Persistence, StoreError, Vault},
    wire::*,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, AtomicU8, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

fn storage_error(retry: &'static str) -> StoreError {
    StoreError {
        status: E_STORAGE,
        detail: "storage worker unavailable",
        retry,
    }
}

fn invalid_admission() -> WireError {
    WireError { status: E_INTERNAL, detail: "request admission unavailable" }
}

fn operation(metadata: &Value) -> Option<relay::Operation> {
    match metadata["operation"].as_str()? {
        "CHAT" => Some(relay::Operation::Chat),
        "RESPONSES" => Some(relay::Operation::Responses),
        "MESSAGES" => Some(relay::Operation::Messages),
        "GENERATE" => Some(relay::Operation::Generate),
        "OLLAMA_CHAT" => Some(relay::Operation::OllamaChat),
        "MODELS" => Some(relay::Operation::Models),
        _ => None,
    }
}

// Deserialize only the top-level option, skipping other JSON values without
// cloning image payloads or message arrays into a second request-sized tree.
#[derive(serde::Deserialize)]
struct BodyOptions {
    stream: Option<bool>,
}

fn valid_request_body(body: &[u8], op: relay::Operation, mode: &Value) -> bool {
    if matches!(op, relay::Operation::Models) {
        return body.is_empty();
    }
    if body.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return false;
    }
    let Ok(options) = serde_json::from_slice::<BodyOptions>(body) else {
        return false;
    };
    matches!(op, relay::Operation::Generate)
        || options
            .stream
            .unwrap_or(matches!(op, relay::Operation::OllamaChat))
            == (mode == "sse" || mode == "ndjson")
}
enum StoreMessage {
    Put(
        Value,
        Vec<u8>,
        Arc<AtomicU8>,
        mpsc::Sender<Result<Value, StoreError>>,
    ),
    Query(Value, mpsc::Sender<Result<Value, StoreError>>),
    Delete(
        Value,
        Arc<AtomicU8>,
        mpsc::Sender<Result<Value, StoreError>>,
    ),
    Snapshot(Value, mpsc::Sender<Result<CredentialSnapshot, StoreError>>),
}
#[derive(Clone)]
pub struct StoreClient {
    tx: mpsc::SyncSender<StoreMessage>,
    busy: Arc<AtomicBool>,
}
impl StoreClient {
    pub fn start<P, F>(factory: F, initialize: bool) -> Result<Self, String>
    where
        P: Persistence + 'static,
        F: FnOnce() -> Result<(P, [u8; 16]), String> + Send + 'static,
    {
        let (tx, rx) = mpsc::sync_channel(8);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let busy = Arc::new(AtomicBool::new(false));
        let worker_busy = busy.clone();
        std::thread::Builder::new()
            .name("lsp-storage".into())
            .spawn(move || {
                let setup = factory().and_then(|(p, id)| {
                    if initialize {
                        Vault::initialize(p, id)
                    } else {
                        Vault::from_storage(p)
                    }
                    .map_err(|e| e.to_string())
                });
                let mut vault = match setup {
                    Ok(v) => {
                        let _ = ready_tx.send(Ok(()));
                        v
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                loop {
                    match rx.recv_timeout(Duration::from_millis(250)) {
                        Ok(StoreMessage::Put(meta, mut key, state, response)) => {
                            if state
                                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                                .is_err()
                            {
                                use zeroize::Zeroize;
                                key.zeroize();
                                continue;
                            }
                            let result = vault.put(&meta, &key);
                            use zeroize::Zeroize;
                            key.zeroize();
                            worker_busy.store(false, Ordering::Release);
                            let _ = response.send(result);
                        }
                        Ok(StoreMessage::Delete(meta, state, response)) => {
                            if state
                                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                                .is_err()
                            {
                                continue;
                            }
                            let result = vault.delete(&meta);
                            worker_busy.store(false, Ordering::Release);
                            let _ = response.send(result);
                        }
                        Ok(StoreMessage::Query(meta, response)) => {
                            let result = vault.query(&meta);
                            let _ = response.send(result);
                        }
                        Ok(StoreMessage::Snapshot(meta, response)) => {
                            let result = vault.snapshot(
                                meta["namespace"].as_str().unwrap_or(""),
                                meta["credential_ref"].as_str().unwrap_or(""),
                                meta["expected_version"]
                                    .as_str()
                                    .and_then(|s| s.parse().ok())
                                    .unwrap_or(u64::MAX),
                                meta["profile_id"].as_str().unwrap_or(""),
                            );
                            let _ = response.send(result);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if !worker_busy.load(Ordering::Acquire) {
                                let _ = vault.sweep();
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        ready_rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| "storage startup timeout")??;
        Ok(Self { tx, busy })
    }
    fn mutation(&self, opcode: u16, meta: Value, key: Vec<u8>) -> Result<Value, StoreError> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(StoreError {
                status: E_BUSY,
                detail: "vault busy",
                retry: "none",
            });
        }
        let (tx, rx) = mpsc::channel();
        let state = Arc::new(AtomicU8::new(0));
        let message = if opcode == CREDENTIAL_PUT {
            StoreMessage::Put(meta, key, state.clone(), tx)
        } else {
            StoreMessage::Delete(meta, state.clone(), tx)
        };
        if self.tx.try_send(message).is_err() {
            self.busy.store(false, Ordering::Release);
            return Err(StoreError {
                status: E_BUSY,
                detail: "storage queue full",
                retry: "none",
            });
        }
        // A running GP write retains its own inputs and fence after this timeout.
        match rx.recv_timeout(Duration::from_millis(2000)) {
            Ok(result) => result,
            Err(_)
                if state
                    .compare_exchange(0, 3, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok() =>
            {
                self.busy.store(false, Ordering::Release);
                Err(StoreError {
                    status: E_BUSY,
                    detail: "queued management withdrawn",
                    retry: "none",
                })
            }
            Err(_) => rx
                .try_recv()
                .unwrap_or_else(|_| Err(storage_error("reconcile_management"))),
        }
    }
    fn query(&self, meta: Value) -> Result<Value, StoreError> {
        let (tx, rx) = mpsc::channel();
        if self.tx.try_send(StoreMessage::Query(meta, tx)).is_err() {
            return Err(storage_error("none"));
        }
        rx.recv_timeout(Duration::from_millis(2000))
            .map_err(|_| storage_error("none"))?
    }
    fn snapshot(&self, meta: Value) -> Result<CredentialSnapshot, StoreError> {
        let (tx, rx) = mpsc::channel();
        if self.tx.try_send(StoreMessage::Snapshot(meta, tx)).is_err() {
            return Err(storage_error("none"));
        }
        rx.recv_timeout(Duration::from_millis(2000))
            .map_err(|_| storage_error("none"))?
    }
}

pub struct App {
    epoch: String,
    store: StoreClient,
    admission: Arc<Mutex<Admission>>,
    request_limit: usize,
    body_limit: usize,
    sessions: Mutex<Vec<Weak<Mutex<Session>>>>,
}

pub const MAX_CONCURRENT_REQUESTS: usize = 4;
pub const MAX_BODY_RESERVATION: usize = 64 * 1024 * 1024;
const MAX_SESSIONS: usize = 8;

#[derive(Default)]
struct Admission {
    requests: usize,
    body_bytes: usize,
}

struct AdmissionPermit {
    state: Arc<Mutex<Admission>>,
    body_bytes: usize,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.requests -= 1;
        state.body_bytes -= self.body_bytes;
    }
}
pub struct Session {
    nonce: String,
    next_seq: u64,
    role: Option<String>,
    request_id: Option<[u8; 16]>,
    state: &'static str,
    open: Option<Value>,
    body: Vec<u8>,
    uploaded: u64,
    key: Option<CredentialSnapshot>,
    relay: Option<Relay>,
    permit: Option<AdmissionPermit>,
    deadline: Option<Instant>,
    last_progress: Instant,
    terminal: Option<Value>,
    terminal_event_sent: bool,
    event_seq: u64,
}
impl Session {
    fn empty_progress(&self) -> Value {
        json!({"accepted_input_bytes":0,"uploaded_body":self.uploaded.to_string(),"accepted_tls_rx":"0","emitted_tls_tx":"0",
            "emitted_http_body":"0","rx_credit":0,"net_tx_pending":false,"http_body_pending":false,"need_step":false,
            "poll_after_ms":1000,"events":[],"terminal":self.terminal,"connect_target":null})
    }
}
impl App {
    pub fn new(store: StoreClient) -> Arc<Self> {
        Self::with_capacity(store, MAX_CONCURRENT_REQUESTS, MAX_BODY_RESERVATION)
    }
    fn with_capacity(store: StoreClient, request_limit: usize, body_limit: usize) -> Arc<Self> {
        let app = Arc::new(Self {
            epoch: uuid::Uuid::new_v4().simple().to_string(),
            store,
            admission: Arc::new(Mutex::new(Admission::default())),
            request_limit,
            body_limit,
            sessions: Mutex::new(Vec::new()),
        });
        let weak = Arc::downgrade(&app);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(250));
                let Some(app) = weak.upgrade() else { break };
                if let Ok(mut sessions) = app.sessions.lock() {
                    sessions.retain(|weak| {
                        let Some(ctx) = weak.upgrade() else {
                            return false;
                        };
                        if let Ok(mut session) = ctx.try_lock() {
                            app.check_time(&mut session);
                        }
                        true
                    });
                }
            }
        });
        app
    }
    pub fn open_session(&self) -> Result<Arc<Mutex<Session>>, &'static str> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| "session registry poisoned")?;
        sessions.retain(|s| s.strong_count() > 0);
        if sessions.len() >= MAX_SESSIONS {
            return Err("session capacity exhausted");
        }
        let session = Arc::new(Mutex::new(Session {
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            next_seq: 1,
            role: None,
            request_id: None,
            state: "NEW",
            open: None,
            body: Vec::new(),
            uploaded: 0,
            key: None,
            relay: None,
            permit: None,
            deadline: None,
            last_progress: Instant::now(),
            terminal: None,
            terminal_event_sent: false,
            event_seq: 1,
        }));
        sessions.push(Arc::downgrade(&session));
        Ok(session)
    }
    pub fn close_session(&self, session: &mut Session) {
        if let Some(relay) = session.relay.as_mut() {
            let _ = relay.cancel(relay::CancelReason::CallerGone);
        }
        session.body = Vec::new();
        session.key = None;
        session.relay = None;
        self.release(session);
    }
    fn release(&self, s: &mut Session) {
        s.permit = None;
    }
    fn check_time(&self, s: &mut Session) {
        if s.permit.is_none() {
            return;
        }
        let now = Instant::now();
        let expired = s.deadline.is_some_and(|d| now >= d)
            || now.duration_since(s.last_progress)
                > Duration::from_secs(if s.state == "UPLOADING" { 10 } else { 30 });
        let revoked = s.key.as_ref().is_some_and(CredentialSnapshot::revoked);
        if expired || revoked {
            if let Some(relay) = s.relay.as_mut() {
                if revoked {
                    relay.latch_revoked();
                } else {
                    relay.latch_expired();
                }
                let output = relay.status();
                s.state = output.state;
                s.terminal = output.progress["terminal"]
                    .as_object()
                    .map(|_| output.progress["terminal"].clone());
            } else {
                s.state = if revoked { "FAILED" } else { "EXPIRED" };
                s.terminal = Some(
                    json!({"end_reason":if revoked {"revoked"}else{"deadline"},"http_framing":"not_started","tls_phase":"not_started",
                    "close_notify_received":false,"request_application_bytes_generated":"0","emitted_http_body":"0","app_resources":"released","manager_cleanup":"not_asserted"}),
                );
                s.body = Vec::new();
            }
            s.key = None;
            self.release(s);
        }
    }
    pub fn exchange(&self, bytes: &[u8], session: &mut Session) -> Result<Vec<u8>, WireError> {
        let frame = Frame::decode_request(bytes)?;
        let validation = validate_request_metadata(&frame);
        if let Err(e) = validation {
            return self.reply(
                &frame,
                session,
                e.status,
                "wire",
                "none",
                None,
                None,
                Vec::new(),
            );
        }
        if frame.call_seq != session.next_seq || frame.call_seq == u64::MAX {
            return self.reply(
                &frame,
                session,
                E_SEQUENCE,
                "wire",
                "none",
                None,
                None,
                Vec::new(),
            );
        }
        if frame.opcode != HELLO
            && (frame.metadata["ta_epoch"] != self.epoch
                || frame.metadata["session_nonce"] != session.nonce)
        {
            return self.reply(
                &frame,
                session,
                E_STALE_EPOCH,
                "wire",
                "none",
                None,
                None,
                Vec::new(),
            );
        }
        if let Some(id) = session.request_id {
            if frame.request_id != id {
                return self.reply(
                    &frame,
                    session,
                    E_REQUEST_ID,
                    "wire",
                    "none",
                    None,
                    None,
                    Vec::new(),
                );
            }
        }
        session.next_seq += 1;
        self.check_time(session);
        if frame.opcode == HELLO {
            if session.state != "NEW" {
                return self.reply(
                    &frame,
                    session,
                    E_STATE,
                    "hello",
                    "none",
                    None,
                    None,
                    Vec::new(),
                );
            }
            let compatible = frame.metadata["supported_versions"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v["major"] == 1 && v["minor"] == 0));
            if !compatible {
                session.next_seq -= 1;
                return self.reply(
                    &frame,
                    session,
                    E_VERSION,
                    "hello",
                    "none",
                    None,
                    None,
                    Vec::new(),
                );
            }
            session.role = frame.metadata["role"].as_str().map(str::to_owned);
            session.state = "HELLO_READY";
            return self.reply(
                &frame,
                session,
                OK,
                "hello",
                "none",
                Some(self.hello_result(session)),
                None,
                Vec::new(),
            );
        }
        let management = matches!(
            frame.opcode,
            CREDENTIAL_PUT | CREDENTIAL_QUERY | CREDENTIAL_DELETE
        );
        let expected_role = if management { "management" } else { "request" };
        if session.role.as_deref() != Some(expected_role) {
            return self.reply(
                &frame,
                session,
                E_ROLE,
                "credential",
                "none",
                None,
                None,
                Vec::new(),
            );
        }
        if management {
            if frame
                .metadata
                .get("ttl_ms")
                .and_then(Value::as_u64)
                .is_some_and(|ttl| ttl > 300000)
            {
                return self.reply(
                    &frame,
                    session,
                    E_LIMIT,
                    "credential",
                    "none",
                    None,
                    None,
                    Vec::new(),
                );
            }
            let result = if frame.opcode == CREDENTIAL_QUERY {
                self.store.query(frame.metadata.clone())
            } else {
                self.store
                    .mutation(frame.opcode, frame.metadata.clone(), frame.payload.clone())
            };
            return match result {
                Ok(value) => self.reply(
                    &frame,
                    session,
                    OK,
                    "credential",
                    "none",
                    Some(value),
                    None,
                    Vec::new(),
                ),
                Err(error) => self.reply(
                    &frame,
                    session,
                    error.status,
                    "credential",
                    error.retry,
                    None,
                    None,
                    Vec::new(),
                ),
            };
        }
        if frame.opcode == REQUEST_OPEN {
            return self.request_open(&frame, session);
        }
        if session.request_id.is_none() {
            return self.reply(
                &frame,
                session,
                E_STATE,
                "open",
                "none",
                None,
                None,
                Vec::new(),
            );
        }
        if let Some(remaining) = frame.metadata.get("remaining_ms").and_then(Value::as_u64) {
            let d = Instant::now() + Duration::from_millis(remaining);
            session.deadline = Some(session.deadline.map_or(d, |old| old.min(d)));
            if let Some(relay) = session.relay.as_mut() {
                relay.shorten_deadline(Duration::from_millis(remaining));
            }
            self.check_time(session);
        }
        if frame.opcode == STATUS {
            let p = session
                .relay
                .as_ref()
                .map(|r| r.status().progress)
                .unwrap_or_else(|| session.empty_progress());
            return self.reply(
                &frame,
                session,
                OK,
                "open",
                "none",
                None,
                Some(p),
                Vec::new(),
            );
        }
        if session.terminal.is_some() && session.relay.is_none() {
            let status = if matches!(frame.opcode, FINISH | CANCEL) {
                OK
            } else if session.state == "EXPIRED" {
                E_DEADLINE
            } else if session
                .terminal
                .as_ref()
                .is_some_and(|t| t["end_reason"] == "revoked")
            {
                E_CREDENTIAL_REVOKED
            } else {
                E_STATE
            };
            return self.fail_upload(&frame, session, status, "deadline", "deadline");
        }
        if frame.opcode == BODY_CHUNK {
            if session.state != "UPLOADING" {
                return self.request_error(&frame, session, E_STATE, "upload");
            }
            let offset = u64_string(&frame.metadata, "body_offset")?;
            if offset != session.body.len() as u64 {
                return self.request_error(&frame, session, E_BODY_OFFSET, "upload");
            }
            let expected = u64_string(session.open.as_ref().unwrap(), "body_length")?;
            if session.body.len() as u64 + frame.payload.len() as u64 > expected {
                return self.request_error(&frame, session, E_BODY_LENGTH, "upload");
            }
            session.body.extend_from_slice(&frame.payload);
            session.uploaded = session.body.len() as u64;
            session.last_progress = Instant::now();
            let mut p = session.empty_progress();
            p["accepted_input_bytes"] = json!(frame.payload.len());
            return self.reply(
                &frame,
                session,
                OK,
                "upload",
                "none",
                None,
                Some(p),
                Vec::new(),
            );
        }
        if frame.opcode == BODY_COMMIT {
            if session.state != "UPLOADING" {
                return self.request_error(&frame, session, E_STATE, "upload");
            }
            let meta = session.open.as_ref().unwrap();
            if session.body.len() as u64 != u64_string(meta, "body_length")? {
                return self.request_error(&frame, session, E_BODY_LENGTH, "upload");
            }
            let digest: String = Sha256::digest(&session.body)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if frame.metadata["body_sha256"] != digest {
                return self.fail_upload(
                    &frame,
                    session,
                    E_BODY_DIGEST,
                    "upload",
                    "internal_error",
                );
            }
            let operation = operation(meta).expect("validated request operation");
            if !valid_request_body(&session.body, operation, &meta["response_mode"]) {
                session.next_seq -= 1;
                return self.reply(
                    &frame,
                    session,
                    E_WIRE_FORMAT,
                    "wire",
                    "none",
                    None,
                    None,
                    Vec::new(),
                );
            }
            let headers: Vec<relay::Header> =
                serde_json::from_value(meta.get("headers").cloned().unwrap_or(json!([])))
                    .unwrap_or_default();
            let key = session.key.as_ref().unwrap();
            let timeout = session
                .deadline
                .unwrap()
                .saturating_duration_since(Instant::now());
            let relay = Relay::for_provider(
                &key.provider,
                operation,
                meta.get("model_id").and_then(Value::as_str),
                meta["response_mode"] != "json",
                std::mem::take(&mut session.body),
                key.key.as_bytes(),
                &headers,
                timeout,
            );
            match relay {
                Ok(mut relay) => {
                    let output = relay.commit(
                        frame.metadata["net_tx_credit"].as_u64().unwrap() as u32,
                        frame.metadata["app_rx_credit"].as_u64().unwrap() as u32,
                    );
                    session.relay = Some(relay);
                    return self.relay_reply(&frame, session, output);
                }
                Err(e) => {
                    return self.fail_upload(&frame, session, e.status, e.stage, "transport_error");
                }
            }
        }
        if let Some(relay) = session.relay.as_mut() {
            let output = match frame.opcode {
                STEP => {
                    let offset = u64_string(&frame.metadata, "tls_rx_offset")?;
                    let input = match frame.metadata["input_kind"].as_str().unwrap() {
                        "none" => relay::Input::None,
                        "tls_rx" => relay::Input::Tls {
                            offset,
                            bytes: &frame.payload,
                        },
                        "tcp_eof" => relay::Input::Eof { offset },
                        _ => relay::Input::NetworkError,
                    };
                    let output = relay.step(
                        input,
                        frame.metadata["net_tx_credit"].as_u64().unwrap() as u32,
                        frame.metadata["app_rx_credit"].as_u64().unwrap() as u32,
                    );
                    if output.error.is_none() {
                        session.last_progress = Instant::now();
                    }
                    output
                }
                FINISH => {
                    let reason = if frame.metadata["reason"] == "consumer_complete" {
                        relay::FinishReason::ConsumerComplete
                    } else {
                        relay::FinishReason::ResponseConsumed
                    };
                    relay.finish(
                        reason,
                        session.open.as_ref().unwrap()["completion_policy"] == "MODEL_TERMINAL",
                    )
                }
                CANCEL => {
                    let reason = match frame.metadata["reason"].as_str().unwrap() {
                        "timeout" => relay::CancelReason::Timeout,
                        "caller_gone" => relay::CancelReason::CallerGone,
                        "shutdown" => relay::CancelReason::Shutdown,
                        _ => relay::CancelReason::User,
                    };
                    relay.cancel(reason)
                }
                _ => return self.request_error(&frame, session, E_STATE, "open"),
            };
            return self.relay_reply(&frame, session, output);
        }
        if frame.opcode == CANCEL {
            return self.fail_upload(
                &frame,
                session,
                OK,
                "cancel",
                if frame.metadata["reason"] == "timeout" {
                    "deadline"
                } else {
                    "cancelled"
                },
            );
        }
        self.request_error(&frame, session, E_STATE, "open")
    }
    fn request_open(&self, f: &Frame, s: &mut Session) -> Result<Vec<u8>, WireError> {
        if s.state != "HELLO_READY" {
            return self.request_error(f, s, E_STATE, "open");
        }
        if operation(&f.metadata).is_none() {
            return self.reply(
                f,
                s,
                E_PROFILE_DENIED,
                "open",
                "none",
                None,
                None,
                Vec::new(),
            );
        }
        let body_len = u64_string(&f.metadata, "body_length")?;
        let configured_budget = f.metadata["overall_timeout_ms"].as_u64().unwrap();
        let budget = configured_budget.min(
            f.metadata
                .get("remaining_ms")
                .and_then(Value::as_u64)
                .unwrap_or(configured_budget),
        );
        if budget == 0 {
            return self.reply(f, s, E_DEADLINE, "deadline", "none", None, None, Vec::new());
        }
        if body_len > 32 * 1024 * 1024 || budget > 600000 {
            return self.reply(f, s, E_LIMIT, "open", "none", None, None, Vec::new());
        }
        let deadline = Instant::now() + Duration::from_millis(budget);
        {
            let mut admission = self.admission.lock().map_err(|_| invalid_admission())?;
            if admission.requests >= self.request_limit {
                return self.reply(f, s, E_BUSY, "open", "none", None, None, Vec::new());
            }
            let total = admission.body_bytes.checked_add(body_len as usize);
            if total.is_none_or(|total| total > self.body_limit) {
                return self.reply(f, s, E_LIMIT, "open", "none", None, None, Vec::new());
            }
            admission.requests += 1;
            admission.body_bytes = total.unwrap();
            s.permit = Some(AdmissionPermit {
                state: self.admission.clone(),
                body_bytes: body_len as usize,
            });
        }
        let snapshot = self.store.snapshot(f.metadata.clone());
        if Instant::now() >= deadline {
            self.release(s);
            return self.reply(f, s, E_DEADLINE, "deadline", "none", None, None, Vec::new());
        }
        match snapshot {
            Ok(key) => {
                if !key.provider.supports(operation(&f.metadata).unwrap()) {
                    self.release(s);
                    return self.reply(
                        f,
                        s,
                        E_PROFILE_DENIED,
                        "open",
                        "none",
                        None,
                        None,
                        Vec::new(),
                    );
                }
                s.key = Some(key);
            }
            Err(error) => {
                self.release(s);
                return self.reply(
                    f,
                    s,
                    error.status,
                    "open",
                    error.retry,
                    None,
                    None,
                    Vec::new(),
                );
            }
        }
        let mut body = Vec::new();
        if body.try_reserve_exact(body_len as usize).is_err() {
            self.release(s);
            s.key = None;
            return self.reply(f, s, E_LIMIT, "open", "none", None, None, Vec::new());
        }
        if Instant::now() >= deadline {
            drop(body);
            self.release(s);
            s.key = None;
            return self.reply(f, s, E_DEADLINE, "deadline", "none", None, None, Vec::new());
        }
        s.body = body;
        s.open = Some(f.metadata.clone());
        s.request_id = Some(f.request_id);
        s.state = "UPLOADING";
        s.deadline = Some(deadline);
        s.last_progress = Instant::now();
        self.reply(
            f,
            s,
            OK,
            "open",
            "none",
            None,
            Some(s.empty_progress()),
            Vec::new(),
        )
    }
    fn relay_reply(
        &self,
        f: &Frame,
        s: &mut Session,
        output: relay::RelayOutput,
    ) -> Result<Vec<u8>, WireError> {
        s.state = output.state;
        if !output.progress["terminal"].is_null() {
            s.terminal = Some(output.progress["terminal"].clone());
            s.key = None;
            self.release(s);
        }
        let (status, stage) = output.error.map_or((OK, "tls_io"), |e| (e.status, e.stage));
        self.reply(
            f,
            s,
            status,
            stage,
            "none",
            None,
            Some(output.progress),
            output.payload,
        )
    }
    fn request_error(
        &self,
        f: &Frame,
        s: &Session,
        status: u32,
        stage: &str,
    ) -> Result<Vec<u8>, WireError> {
        let progress = if s.request_id.is_some() {
            Some(
                s.relay
                    .as_ref()
                    .map(|r| r.status().progress)
                    .unwrap_or_else(|| s.empty_progress()),
            )
        } else {
            None
        };
        self.reply(f, s, status, stage, "none", None, progress, Vec::new())
    }
    fn fail_upload(
        &self,
        f: &Frame,
        s: &mut Session,
        status: u32,
        stage: &str,
        reason: &str,
    ) -> Result<Vec<u8>, WireError> {
        if s.terminal.is_some() {
            let mut p = s.empty_progress();
            if !s.terminal_event_sent {
                p["events"] = json!([{"event_seq":s.event_seq.to_string(),"kind":"REQUEST_END","offset":0,"length":0,"details":s.terminal}]);
                s.terminal_event_sent = true;
                s.event_seq += 1;
            }
            return self.reply(f, s, status, stage, "none", None, Some(p), Vec::new());
        }
        s.state = if reason == "cancelled" {
            "CANCELLED"
        } else if reason == "deadline" {
            "EXPIRED"
        } else {
            "FAILED"
        };
        s.terminal = Some(
            json!({"end_reason":reason,"http_framing":"not_started","tls_phase":"not_started","close_notify_received":false,
            "request_application_bytes_generated":"0","emitted_http_body":"0","app_resources":"released","manager_cleanup":"not_asserted"}),
        );
        let uploaded = s.uploaded;
        s.body = Vec::new();
        s.key = None;
        self.release(s);
        let mut p = s.empty_progress();
        p["uploaded_body"] = json!(uploaded.to_string());
        p["events"] = json!([{"event_seq":s.event_seq.to_string(),"kind":"REQUEST_END","offset":0,"length":0,"details":s.terminal}]);
        s.event_seq += 1;
        s.terminal_event_sent = true;
        self.reply(f, s, status, stage, "none", None, Some(p), Vec::new())
    }
    fn reply(
        &self,
        f: &Frame,
        s: &Session,
        status: u32,
        stage: &str,
        retry: &str,
        result: Option<Value>,
        progress: Option<Value>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, WireError> {
        let name = status_name(status);
        Frame{opcode:f.opcode,request_id:f.request_id,call_seq:f.call_seq,status,
            metadata:json!({"ta_epoch":self.epoch,"session_nonce":s.nonce,"next_call_seq":s.next_seq.to_string(),"state":s.state,
                "error":if status==OK{Value::Null}else{json!({"code":name,"stage":stage,"retry":retry})},"result":result,"progress":progress}),payload}.encode_reply()
    }
    fn hello_result(&self, s: &Session) -> Value {
        json!({"selected_version":{"major":1,"minor":0},"role":s.role,"capabilities":{"operations":["CHAT","RESPONSES","MESSAGES","GENERATE","OLLAMA_CHAT","MODELS"],
            "profiles":[{"id":"deepseek-prod-v1","auth_by_operation":{"CHAT":"bearer","RESPONSES":"bearer","MESSAGES":"x_api_key","MODELS":"bearer"}},
                {"id":"custom-provider-v1","provider_types":["openai_compatible","openai_responses","anthropic_messages","google_gemini","ollama_native"]}],
            "backend_contract_id":"lsp-provider-dev-v2",
            "features":["bounded_pump","business_cancel","epoch_bound_sessions","temporary_credentials","provider_configuration","concurrent_requests","credential_rebind","bulk_input_frames"]},
            "limits":{"frame_input_max":INPUT_FRAME_MAX,"frame_output_max":OUTPUT_FRAME_MAX,"json_max":METADATA_MAX,"max_request_body":33554432,"max_concurrent_requests":self.request_limit,"max_sessions":MAX_SESSIONS,
                "max_body_reservation_bytes":self.body_limit,
                "max_pending_net_rx":65536,"max_pending_net_tx":65536,"max_pending_http_body":65536,"upload_idle_ms":10000,"lease_ms":30000,"heartbeat_max_ms":2000,
                "max_overall_ms":600000,"max_header_bytes":4096,"max_credential_bytes":4096,"max_temporary_ttl_ms":300000}})
    }
}

fn status_name(code: u32) -> &'static str {
    match code {
        OK => "OK",
        E_OUTPUT_CAPACITY => "E_OUTPUT_CAPACITY",
        E_WIRE_FORMAT => "E_WIRE_FORMAT",
        E_VERSION => "E_VERSION",
        E_ROLE => "E_ROLE",
        E_STATE => "E_STATE",
        E_STALE_EPOCH => "E_STALE_EPOCH",
        E_SEQUENCE => "E_SEQUENCE",
        E_REQUEST_ID => "E_REQUEST_ID",
        E_CREDENTIAL_NOT_FOUND => "E_CREDENTIAL_NOT_FOUND",
        E_VERSION_CONFLICT => "E_VERSION_CONFLICT",
        E_OPERATION_CONFLICT => "E_OPERATION_CONFLICT",
        E_PROFILE_DENIED => "E_PROFILE_DENIED",
        E_STORAGE => "E_STORAGE",
        E_CREDENTIAL_REVOKED => "E_CREDENTIAL_REVOKED",
        E_STORAGE_NOT_COMMITTED => "E_STORAGE_NOT_COMMITTED",
        E_BUSY => "E_BUSY",
        E_LIMIT => "E_LIMIT",
        E_BODY_LENGTH => "E_BODY_LENGTH",
        E_BODY_OFFSET => "E_BODY_OFFSET",
        E_BODY_DIGEST => "E_BODY_DIGEST",
        E_TLS => "E_TLS",
        E_HTTP_PARSE => "E_HTTP_PARSE",
        E_NETWORK => "E_NETWORK",
        E_DEADLINE => "E_DEADLINE",
        E_HTTP_LIMIT => "E_HTTP_LIMIT",
        _ => "E_INTERNAL",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone, Default)]
    struct Memory(Arc<Mutex<Option<Vec<u8>>>>);
    impl Persistence for Memory {
        fn load(&mut self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn commit(&mut self, b: &[u8]) -> Result<(), String> {
            *self.0.lock().unwrap() = Some(b.to_vec());
            Ok(())
        }
    }
    fn app() -> Arc<App> {
        App::with_capacity(
            StoreClient::start(|| Ok((Memory::default(), [7; 16])), true).unwrap(),
            1,
            MAX_BODY_RESERVATION,
        )
    }
    #[test]
    fn parallel_opens_cancel_and_replacement_keep_other_requests_independent() {
        let app = App::new(StoreClient::start(|| Ok((Memory::default(), [7; 16])), true).unwrap());
        provision(&app);
        let sessions: Vec<_> = (0..5).map(|_| app.open_session().unwrap()).collect();
        let start = Arc::new(std::sync::Barrier::new(5));
        let workers: Vec<_> = sessions[..4].iter().map(|session| {
            let app = app.clone();
            let session = session.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                let mut state = session.lock().unwrap();
                hello(&app, &mut state, "request");
                start.wait();
                open(&app, &mut state, 2, 60000)
            })
        }).collect();
        start.wait();
        for worker in workers {
            assert!(worker.join().unwrap()["error"].is_null());
        }
        assert_eq!(app.admission.lock().unwrap().requests, 4);
        let mut fifth = sessions[4].lock().unwrap();
        hello(&app, &mut fifth, "request");
        assert_eq!(open(&app, &mut fifth, 2, 60000)["error"]["code"], "E_BUSY");
        {
            let mut first = sessions[0].lock().unwrap();
            let cancelled = exchange(&app, &mut first, CANCEL, [3;16], 3, json!({"reason":"user"}), b"");
            assert_eq!(cancelled["state"], "CANCELLED");
        }
        for session in &sessions[1..4] {
            assert_eq!(session.lock().unwrap().state, "UPLOADING");
        }
        assert!(open(&app, &mut fifth, 3, 60000)["error"].is_null());
        app.close_session(&mut fifth);
        drop(fifth);
        drop(sessions);
        let admission = app.admission.lock().unwrap();
        assert_eq!(admission.requests, 0);
        assert_eq!(admission.body_bytes, 0);
    }

    #[test]
    fn total_body_reservation_rejects_before_allocation_and_recovers_on_drop() {
        let app = App::with_capacity(StoreClient::start(|| Ok((Memory::default(), [7;16])), true).unwrap(), 4, 7);
        provision(&app);
        let first = app.open_session().unwrap();
        {
            let mut state = first.lock().unwrap();
            hello(&app, &mut state, "request");
            assert!(open(&app, &mut state, 2, 60000)["error"].is_null());
        }
        let second = app.open_session().unwrap();
        let mut state = second.lock().unwrap();
        hello(&app, &mut state, "request");
        assert_eq!(open(&app, &mut state, 2, 60000)["error"]["code"], "E_LIMIT");
        assert!(state.body.is_empty());
        assert!(state.permit.is_none());
        drop(first);
        assert!(open(&app, &mut state, 3, 60000)["error"].is_null());
        app.close_session(&mut state);
        assert_eq!(app.admission.lock().unwrap().body_bytes, 0);
    }

    #[test]
    fn read_operations_preserve_an_independent_pending_mutation_fence() {
        let app = app();
        provision(&app);
        app.store.busy.store(true, Ordering::Release);
        let metadata = json!({"namespace":"test","credential_ref":"11111111111111111111111111111111","profile_id":"deepseek-prod-v1","expected_version":"1"});
        assert_eq!(app.store.query(metadata.clone()).unwrap()["state"], "live");
        assert_eq!(app.store.snapshot(metadata).unwrap().version, 1);
        assert!(app.store.busy.load(Ordering::Acquire));
        app.store.busy.store(false, Ordering::Release);
    }

    #[test]
    fn keyless_rebind_frame_preserves_key_and_business_guards() {
        let app = app();
        let context = app.open_session().unwrap();
        let mut session = context.lock().unwrap();
        let hello = exchange(&app, &mut session, HELLO, [0; 16], 1,
            json!({"role":"management","supported_versions":[{"major":1,"minor":0}]}), &[]);
        assert!(hello["result"]["capabilities"]["features"].as_array().unwrap()
            .iter().any(|feature| feature == "credential_rebind"));
        let put = json!({"namespace":"test","credential_ref":"1".repeat(32),
            "operation_id":"2".repeat(32),"profile_id":"custom-provider-v1","expected_version":"0",
            "provider_config":{"provider_type":"openai_compatible","base_url":"https://first.example/v1/"}});
        let created = exchange(&app, &mut session, CREDENTIAL_PUT, [0; 16], 2,
            put.clone(), b"fake-preserved-key");
        assert!(created["error"].is_null(), "{created}");
        let snapshot_meta = json!({"namespace":"test","credential_ref":"1".repeat(32),
            "profile_id":"custom-provider-v1","expected_version":"1"});
        let before = app.store.snapshot(snapshot_meta.clone()).unwrap();
        let mut rebind = put;
        rebind["operation_id"] = json!("3".repeat(32));
        rebind["expected_version"] = json!("1");
        rebind["reuse_existing_key"] = json!(true);
        rebind["provider_config"]["base_url"] = json!("https://second.example/v2/");
        let rebound = exchange(&app, &mut session, CREDENTIAL_PUT, [0; 16], 3,
            rebind.clone(), &[]);
        assert!(rebound["error"].is_null(), "{rebound}");
        assert_eq!(rebound["result"]["version"], "2");
        let mut snapshot_meta = snapshot_meta;
        snapshot_meta["expected_version"] = json!("2");
        let after = app.store.snapshot(snapshot_meta).unwrap();
        assert!(Arc::ptr_eq(&before.key, &after.key));
        assert_eq!(after.key.as_bytes(), b"fake-preserved-key");
        assert_eq!(before.provider.host(), "first.example");
        assert_eq!(after.provider.host(), "second.example");
        let replayed = exchange(&app, &mut session, CREDENTIAL_PUT, [0; 16], 4,
            rebind.clone(), &[]);
        assert_eq!(replayed["result"]["replayed"], true);
        let mut missing = rebind.clone();
        missing["credential_ref"] = json!("4".repeat(32));
        missing["operation_id"] = json!("5".repeat(32));
        missing["expected_version"] = json!("0");
        let rejected = exchange(&app, &mut session, CREDENTIAL_PUT, [0; 16], 5, missing, &[]);
        assert_eq!(rejected["error"]["code"], "E_CREDENTIAL_NOT_FOUND");
        rebind["operation_id"] = json!("6".repeat(32));
        let stale = exchange(&app, &mut session, CREDENTIAL_PUT, [0; 16], 6,
            rebind.clone(), &[]);
        assert_eq!(stale["error"]["code"], "E_VERSION_CONFLICT");
        let deleted = exchange(&app, &mut session, CREDENTIAL_DELETE, [0; 16], 7,
            json!({"namespace":"test","credential_ref":"1".repeat(32),
                "operation_id":"7".repeat(32),"expected_version":"2"}), &[]);
        assert!(deleted["error"].is_null(), "{deleted}");
        rebind["operation_id"] = json!("8".repeat(32));
        rebind["expected_version"] = json!("3");
        let revoked = exchange(&app, &mut session, CREDENTIAL_PUT, [0; 16], 8, rebind, &[]);
        assert_eq!(revoked["error"]["code"], "E_CREDENTIAL_REVOKED");
        app.close_session(&mut session);
    }

    #[test]
    fn provider_body_stream_defaults_preserve_nested_payload_options() {
        assert!(valid_request_body(br#"{"messages":[{"content":"opaque"}],"temperature":0.2,"stream":true}"#, relay::Operation::Responses, &json!("sse")));
        assert!(!valid_request_body(br#"{"stream":false}"#, relay::Operation::Messages, &json!("sse")));
        assert!(valid_request_body(br#"{"contents":[]}"#, relay::Operation::Generate, &json!("sse")));
        assert!(valid_request_body(br#"{"messages":[]}"#, relay::Operation::OllamaChat, &json!("ndjson")));
        assert!(!valid_request_body(br#"{"messages":[]}"#, relay::Operation::Chat, &json!("sse")));
        assert!(!valid_request_body(br#"[true]"#, relay::Operation::Chat, &json!("sse")));
        assert!(!valid_request_body(br#"{"stream":true,"stream":false}"#, relay::Operation::Chat, &json!("sse")));
    }

    #[test]
    fn open_deadline_includes_waiting_for_credential_snapshot() {
        #[derive(Clone)]
        struct Delayed {
            memory: Memory,
            hold: Arc<AtomicBool>,
            entered: Arc<AtomicBool>,
        }
        impl Persistence for Delayed {
            fn load(&mut self) -> Result<Option<Vec<u8>>, String> { self.memory.load() }
            fn commit(&mut self, bytes: &[u8]) -> Result<(), String> {
                if self.hold.load(Ordering::Acquire) {
                    self.entered.store(true, Ordering::Release);
                    while self.hold.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                self.memory.commit(bytes)
            }
        }
        let hold = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicBool::new(false));
        let persistence = Delayed { memory: Memory::default(), hold: hold.clone(), entered: entered.clone() };
        let app = App::new(StoreClient::start(move || Ok((persistence, [7;16])), true).unwrap());
        provision(&app);
        hold.store(true, Ordering::Release);
        let writer = app.store.clone();
        let write = std::thread::spawn(move || writer.mutation(CREDENTIAL_PUT,
            json!({"namespace":"test","credential_ref":"4".repeat(32),"operation_id":"5".repeat(32),"profile_id":"deepseek-prod-v1","expected_version":"0"}), b"fake-other-key".to_vec()));
        let setup_deadline = Instant::now() + Duration::from_secs(2);
        while !entered.load(Ordering::Acquire) {
            assert!(Instant::now() < setup_deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let unblock = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            hold.store(false, Ordering::Release);
        });
        let session = app.open_session().unwrap();
        let mut state = session.lock().unwrap();
        hello(&app, &mut state, "request");
        let reply = open(&app, &mut state, 2, 20);
        unblock.join().unwrap();
        assert!(write.join().unwrap().is_ok());
        assert_eq!(reply["error"]["code"], "E_DEADLINE");
        assert!(state.permit.is_none());
        assert_eq!(state.body.capacity(), 0);
        assert_eq!(app.admission.lock().unwrap().requests, 0);
    }

    fn exchange(
        app: &App,
        s: &mut Session,
        op: u16,
        id: [u8; 16],
        seq: u64,
        mut meta: Value,
        body: &[u8],
    ) -> Value {
        if op != HELLO {
            meta["ta_epoch"] = json!(app.epoch);
            meta["session_nonce"] = json!(s.nonce);
        }
        let input = Frame {
            opcode: op,
            request_id: id,
            call_seq: seq,
            status: 0,
            metadata: meta,
            payload: body.to_vec(),
        }
        .encode_request()
        .unwrap();
        let out = app.exchange(&input, s).unwrap();
        let n = u32::from_le_bytes(out[20..24].try_into().unwrap()) as usize;
        serde_json::from_slice(&out[64..64 + n]).unwrap()
    }
    fn hello(app: &App, s: &mut Session, role: &str) {
        let r = exchange(
            app,
            s,
            HELLO,
            [0; 16],
            1,
            json!({"role":role,"supported_versions":[{"major":1,"minor":0}]}),
            b"",
        );
        assert!(r["error"].is_null());
    }

    #[test]
    fn bulk_hello_and_legacy_uploads_preserve_exact_body_and_digest() {
        let body = serde_json::to_vec(&json!({"model":"test-model","messages":[
            {"role":"user","content":"x".repeat(120001)}]})).unwrap();
        for chunk_size in [15000, INPUT_FRAME_MAX - HEADER_BYTES - METADATA_MAX] {
            let app = app();
            provision(&app);
            let context = app.open_session().unwrap();
            let mut session = context.lock().unwrap();
            let hello = exchange(&app, &mut session, HELLO, [0; 16], 1,
                json!({"role":"request","supported_versions":[{"major":1,"minor":0}]}), &[]);
            assert_eq!(hello["result"]["limits"]["frame_input_max"], INPUT_FRAME_MAX);
            assert_eq!(hello["result"]["limits"]["frame_output_max"], 32768);
            assert!(hello["result"]["capabilities"]["features"].as_array().unwrap()
                .iter().any(|feature| feature == "bulk_input_frames"));
            let opened = exchange(&app, &mut session, REQUEST_OPEN, [3; 16], 2,
                json!({"namespace":"test","credential_ref":"1".repeat(32),"profile_id":"deepseek-prod-v1",
                    "expected_version":"1","operation":"CHAT","body_length":body.len().to_string(),
                    "overall_timeout_ms":60000,"response_mode":"json","completion_policy":"HTTP_COMPLETE"}), &[]);
            assert!(opened["error"].is_null());
            let mut sequence = 3;
            for (index, chunk) in body.chunks(chunk_size).enumerate() {
                let uploaded = exchange(&app, &mut session, BODY_CHUNK, [3; 16], sequence,
                    json!({"body_offset":(index * chunk_size).to_string()}), chunk);
                assert!(uploaded["error"].is_null());
                assert_eq!(uploaded["progress"]["accepted_input_bytes"], chunk.len());
                sequence += 1;
            }
            assert_eq!(session.body, body);
            let committed = exchange(&app, &mut session, BODY_COMMIT, [3; 16], sequence,
                json!({"body_sha256":format!("{:x}",Sha256::digest(&body)),
                    "net_tx_credit":65536,"app_rx_credit":65536}), &[]);
            assert!(committed["error"].is_null(), "{committed}");
            assert!(session.relay.is_some());
        }
    }
    fn provision(app: &App) {
        let c = app.open_session().unwrap();
        let mut s = c.lock().unwrap();
        hello(app, &mut s, "management");
        let r = exchange(
            app,
            &mut s,
            CREDENTIAL_PUT,
            [0; 16],
            2,
            json!({"namespace":"test","credential_ref":"11111111111111111111111111111111","operation_id":"22222222222222222222222222222222","profile_id":"deepseek-prod-v1","expected_version":"0"}),
            b"FAKE-TEST-KEY",
        );
        assert!(r["error"].is_null());
    }
    fn open(app: &App, s: &mut Session, seq: u64, budget: u32) -> Value {
        exchange(
            app,
            s,
            REQUEST_OPEN,
            [3; 16],
            seq,
            json!({"namespace":"test","credential_ref":"11111111111111111111111111111111","profile_id":"deepseek-prod-v1","expected_version":"1","operation":"CHAT","body_length":"4","overall_timeout_ms":budget,"response_mode":"json","completion_policy":"HTTP_COMPLETE"}),
            b"",
        )
    }
    #[test]
    fn single_slot_rejects_other_session_without_resetting_first() {
        let app = app();
        provision(&app);
        let c1 = app.open_session().unwrap();
        let c2 = app.open_session().unwrap();
        let mut a = c1.lock().unwrap();
        let mut b = c2.lock().unwrap();
        hello(&app, &mut a, "request");
        hello(&app, &mut b, "request");
        assert!(open(&app, &mut a, 2, 60000)["error"].is_null());
        assert_eq!(open(&app, &mut b, 2, 60000)["error"]["code"], "E_BUSY");
        app.close_session(&mut b);
        assert_eq!(a.state, "UPLOADING");
        assert_eq!(app.admission.lock().unwrap().requests, 1);
        app.close_session(&mut a);
        assert_eq!(app.admission.lock().unwrap().requests, 0);
        assert!(open(&app, &mut b, 3, 60000)["error"].is_null());
        app.close_session(&mut b);
    }
    #[test]
    fn offset_rejection_consumes_sequence_but_preserves_upload() {
        let app = app();
        provision(&app);
        let c = app.open_session().unwrap();
        let mut s = c.lock().unwrap();
        hello(&app, &mut s, "request");
        open(&app, &mut s, 2, 60000);
        let r = exchange(
            &app,
            &mut s,
            BODY_CHUNK,
            [3; 16],
            3,
            json!({"body_offset":"1"}),
            b"{}  ",
        );
        assert_eq!(r["error"]["code"], "E_BODY_OFFSET");
        assert!(s.body.is_empty());
        assert_eq!(s.next_seq, 4);
        let r = exchange(
            &app,
            &mut s,
            BODY_CHUNK,
            [3; 16],
            4,
            json!({"body_offset":"0"}),
            b"{}  ",
        );
        assert_eq!(r["progress"]["accepted_input_bytes"], 4);
        app.close_session(&mut s);
    }
    #[test]
    fn cancel_upload_has_one_terminal_and_allows_fresh_request() {
        let app = app();
        provision(&app);
        let c = app.open_session().unwrap();
        let mut s = c.lock().unwrap();
        hello(&app, &mut s, "request");
        open(&app, &mut s, 2, 60000);
        let r = exchange(
            &app,
            &mut s,
            CANCEL,
            [3; 16],
            3,
            json!({"reason":"user"}),
            b"",
        );
        assert_eq!(r["state"], "CANCELLED");
        assert_eq!(s.body.capacity(), 0);
        assert_eq!(r["progress"]["events"].as_array().unwrap().len(), 1);
        assert_eq!(app.admission.lock().unwrap().requests, 0);
        let r = exchange(
            &app,
            &mut s,
            CANCEL,
            [3; 16],
            4,
            json!({"reason":"user"}),
            b"",
        );
        assert!(r["progress"]["events"].as_array().unwrap().is_empty());
        assert_eq!(r["progress"]["terminal"]["end_reason"], "cancelled");
    }
    #[test]
    fn independent_deadline_keeps_counters_and_status_does_not_consume_end() {
        let app = app();
        provision(&app);
        let c = app.open_session().unwrap();
        let mut s = c.lock().unwrap();
        hello(&app, &mut s, "request");
        open(&app, &mut s, 2, 100);
        exchange(
            &app,
            &mut s,
            BODY_CHUNK,
            [3; 16],
            3,
            json!({"body_offset":"0"}),
            b"{}  ",
        );
        s.deadline = Some(Instant::now() - Duration::from_millis(1));
        app.check_time(&mut s);
        let r = exchange(&app, &mut s, STATUS, [3; 16], 4, json!({}), b"");
        assert_eq!(r["state"], "EXPIRED");
        assert_eq!(r["progress"]["uploaded_body"], "4");
        assert!(r["progress"]["events"].as_array().unwrap().is_empty());
        let r = exchange(
            &app,
            &mut s,
            CANCEL,
            [3; 16],
            5,
            json!({"reason":"timeout"}),
            b"",
        );
        assert_eq!(r["progress"]["events"].as_array().unwrap().len(), 1);
        assert_eq!(r["progress"]["terminal"]["end_reason"], "deadline");
    }
    #[test]
    fn digest_failure_is_fatal_before_network() {
        let app = app();
        provision(&app);
        let c = app.open_session().unwrap();
        let mut s = c.lock().unwrap();
        hello(&app, &mut s, "request");
        open(&app, &mut s, 2, 60000);
        exchange(
            &app,
            &mut s,
            BODY_CHUNK,
            [3; 16],
            3,
            json!({"body_offset":"0"}),
            b"{}  ",
        );
        let r = exchange(
            &app,
            &mut s,
            BODY_COMMIT,
            [3; 16],
            4,
            json!({"body_sha256":"00".repeat(32),"net_tx_credit":65536,"app_rx_credit":65536}),
            b"",
        );
        assert_eq!(r["error"]["code"], "E_BODY_DIGEST");
        assert!(s.relay.is_none());
        assert_eq!(app.admission.lock().unwrap().requests, 0);
    }
    #[test]
    fn unsupported_operation_and_excess_ttl_reject_without_side_effects() {
        let app = app();
        let c = app.open_session().unwrap();
        let mut s = c.lock().unwrap();
        hello(&app, &mut s, "management");
        let r = exchange(
            &app,
            &mut s,
            CREDENTIAL_PUT,
            [0; 16],
            2,
            json!({"namespace":"test","credential_ref":"11111111111111111111111111111111","operation_id":"22222222222222222222222222222222","profile_id":"deepseek-prod-v1","expected_version":"0","temporary":true,"ttl_ms":300001}),
            b"FAKE",
        );
        assert_eq!(r["error"]["code"], "E_LIMIT");
        let r = exchange(
            &app,
            &mut s,
            CREDENTIAL_QUERY,
            [0; 16],
            3,
            json!({"namespace":"test","credential_ref":"11111111111111111111111111111111"}),
            b"",
        );
        assert_eq!(r["result"]["state"], "absent");
    }
    #[test]
    fn session_capacity_is_bounded_and_dropped_slots_recover() {
        let app = app();
        let mut sessions = Vec::new();
        for _ in 0..8 {
            sessions.push(app.open_session().unwrap());
        }
        assert!(app.open_session().is_err());
        sessions.pop();
        assert!(app.open_session().is_ok());
    }
    #[test]
    fn management_query_and_delete_work_without_overwriting_active_upload() {
        let app = app();
        provision(&app);
        let c = app.open_session().unwrap();
        let mut request = c.lock().unwrap();
        hello(&app, &mut request, "request");
        open(&app, &mut request, 2, 60000);
        let a = app.open_session().unwrap();
        let mut admin = a.lock().unwrap();
        hello(&app, &mut admin, "management");
        let r = exchange(
            &app,
            &mut admin,
            CREDENTIAL_QUERY,
            [0; 16],
            2,
            json!({"namespace":"test","credential_ref":"11111111111111111111111111111111"}),
            b"",
        );
        assert_eq!(r["result"]["state"], "live");
        assert_eq!(request.state, "UPLOADING");
        let r = exchange(
            &app,
            &mut admin,
            CREDENTIAL_DELETE,
            [0; 16],
            3,
            json!({"namespace":"test","credential_ref":"11111111111111111111111111111111","expected_version":"1","operation_id":"33333333333333333333333333333333"}),
            b"",
        );
        assert!(r["error"].is_null());
        app.check_time(&mut request);
        assert_eq!(request.state, "FAILED");
        assert_eq!(request.body.capacity(), 0);
        assert_eq!(request.terminal.as_ref().unwrap()["end_reason"], "revoked");
    }
    #[test]
    fn remaining_zero_on_status_shortens_deadline_without_consuming_event() {
        let app = app();
        provision(&app);
        let c = app.open_session().unwrap();
        let mut s = c.lock().unwrap();
        hello(&app, &mut s, "request");
        open(&app, &mut s, 2, 60000);
        let r = exchange(
            &app,
            &mut s,
            STATUS,
            [3; 16],
            3,
            json!({"remaining_ms":0}),
            b"",
        );
        assert_eq!(r["state"], "EXPIRED");
        assert!(r["progress"]["events"].as_array().unwrap().is_empty());
        assert_eq!(app.admission.lock().unwrap().requests, 0);
    }
}
