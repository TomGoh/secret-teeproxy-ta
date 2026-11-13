//! Per-request TLS byte relay. The untrusted CA owns TCP, while certificate
//! verification, authentication headers and HTTP framing remain inside the TA.
use std::collections::VecDeque;
use std::io::{self, Cursor, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroize;

use crate::http::{ResponseParser, token};
use crate::provider::ProviderProfile;

pub const MAX_PENDING: usize = 64 * 1024;
// Reserve the complete 4 KiB metadata budget and fixed 64-byte LSP header.
const FRAME_PAYLOAD: usize = 32768 - 64 - 4096;
const WORK_ROUNDS: usize = 32;
const IO_CHUNK: usize = 4096;
#[cfg(test)]
const HOST: &str = "api.deepseek.com";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Chat,
    Responses,
    Messages,
    Models,
    Generate,
    OllamaChat,
}

pub enum Input<'a> {
    None,
    Tls { offset: u64, bytes: &'a [u8] },
    Eof { offset: u64 },
    NetworkError,
}

#[derive(Clone, Copy)]
pub enum FinishReason {
    ConsumerComplete,
    ResponseConsumed,
}
#[derive(Clone, Copy)]
pub enum CancelReason {
    User,
    CallerGone,
    Timeout,
    Shutdown,
}

#[derive(Debug, Clone, Copy)]
pub struct RelayError {
    pub code: &'static str,
    pub status: u32,
    pub stage: &'static str,
}

impl RelayError {
    pub fn json(self) -> Value {
        json!({"code":self.code,"stage":self.stage,"retry":"none"})
    }
    pub(crate) fn http() -> Self {
        Self {
            code: "E_HTTP_PARSE",
            status: 0x1402,
            stage: "http",
        }
    }
    pub(crate) fn http_limit() -> Self {
        Self {
            code: "E_HTTP_LIMIT",
            status: 0x1405,
            stage: "http",
        }
    }
    pub(crate) fn content_encoding() -> Self {
        Self {
            code: "E_HTTP_PARSE",
            status: 0x1402,
            stage: "content_encoding",
        }
    }
    pub(crate) fn internal() -> Self {
        Self {
            code: "E_INTERNAL",
            status: 0x1fff,
            stage: "internal",
        }
    }
    fn tls(handshaking: bool) -> Self {
        Self {
            code: "E_TLS",
            status: 0x1401,
            stage: if handshaking {
                "tls_handshake"
            } else {
                "tls_io"
            },
        }
    }
    fn state(stage: &'static str) -> Self {
        Self {
            code: "E_STATE",
            status: 0x1101,
            stage,
        }
    }
    fn wire() -> Self {
        Self {
            code: "E_WIRE_FORMAT",
            status: 0x1002,
            stage: "wire",
        }
    }
}

pub struct RelayOutput {
    pub state: &'static str,
    pub error: Option<RelayError>,
    pub progress: Value,
    pub payload: Vec<u8>,
}

pub struct Relay {
    tls: Option<ClientConnection>,
    provider: ProviderProfile,
    request_head: Vec<u8>,
    request_head_offset: usize,
    request_body: Vec<u8>,
    request_body_offset: usize,
    uploaded_body: u64,
    tls_rx: VecDeque<u8>,
    tls_tx: VecDeque<u8>,
    parser: ResponseParser,
    accepted_tls_rx: u64,
    emitted_tls_tx: u64,
    emitted_http_body: u64,
    generated: u64,
    event_seq: u64,
    head_emitted: bool,
    end_emitted: bool,
    committed: bool,
    eof_queued: bool,
    eof_processed: bool,
    plaintext_eof: bool,
    plaintext_pending: usize,
    close_notify: bool,
    tls_phase: &'static str,
    deadline: Instant,
    terminal: Option<Value>,
    terminal_state: &'static str,
    terminal_error: Option<RelayError>,
    terminal_event_emitted: bool,
}

impl Relay {
    pub fn new(
        operation: Operation,
        body: Vec<u8>,
        key: &[u8],
        headers: &[Header],
        timeout: Duration,
    ) -> Result<Self, RelayError> {
        Self::for_provider(
            &ProviderProfile::deepseek(),
            operation,
            None,
            false,
            body,
            key,
            headers,
            timeout,
        )
    }

    pub fn for_provider(
        provider: &ProviderProfile,
        operation: Operation,
        model_id: Option<&str>,
        stream: bool,
        body: Vec<u8>,
        key: &[u8],
        headers: &[Header],
        timeout: Duration,
    ) -> Result<Self, RelayError> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::for_provider_with_roots(
            provider, operation, model_id, stream, body, key, headers, timeout, roots,
        )
    }

    fn for_provider_with_roots(
        provider_profile: &ProviderProfile,
        operation: Operation,
        model_id: Option<&str>,
        stream: bool,
        body: Vec<u8>,
        key: &[u8],
        headers: &[Header],
        timeout: Duration,
        roots: RootCertStore,
    ) -> Result<Self, RelayError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| RelayError::internal())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.enable_early_data = false;
        let name = ServerName::try_from(provider_profile.host().to_owned())
            .map_err(|_| RelayError::wire())?;
        let mut tls =
            ClientConnection::new(Arc::new(config), name).map_err(|_| RelayError::tls(true))?;
        tls.set_buffer_limit(Some(16 * 1024));
        let uploaded_body = body.len() as u64;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(RelayError::wire)?;
        let request_head = build_provider_request_head(
            provider_profile,
            operation,
            model_id,
            stream,
            body.len(),
            key,
            headers,
        )?;
        Ok(Self {
            tls: Some(tls),
            provider: provider_profile.clone(),
            request_head,
            request_head_offset: 0,
            request_body: body,
            request_body_offset: 0,
            uploaded_body,
            tls_rx: VecDeque::new(),
            tls_tx: VecDeque::new(),
            parser: ResponseParser::new(),
            accepted_tls_rx: 0,
            emitted_tls_tx: 0,
            emitted_http_body: 0,
            generated: 0,
            event_seq: 0,
            head_emitted: false,
            end_emitted: false,
            committed: false,
            eof_queued: false,
            eof_processed: false,
            plaintext_eof: false,
            plaintext_pending: 0,
            close_notify: false,
            tls_phase: "not_started",
            deadline,
            terminal: None,
            terminal_state: "FAILED",
            terminal_error: None,
            terminal_event_emitted: false,
        })
    }

    /// Only shortens the request-local monotonic deadline.
    pub fn shorten_deadline(&mut self, remaining: Duration) {
        if let Some(candidate) = Instant::now().checked_add(remaining) {
            self.deadline = self.deadline.min(candidate);
        }
    }

    pub fn commit(&mut self, net_tx_credit: u32, app_rx_credit: u32) -> RelayOutput {
        if self.terminal.is_some() {
            return self.output(0, None, false, 0, 0);
        }
        if self.committed {
            return self.rejected(RelayError::state("upload"));
        }
        if self.check_deadline() {
            return self.output(0, None, false, 0, 0);
        }
        self.committed = true;
        self.tls_phase = "handshake";
        if let Err(error) = self.pump() {
            self.fail(error);
        }
        self.output(0, None, true, net_tx_credit, app_rx_credit)
    }

    pub fn step(
        &mut self,
        input: Input<'_>,
        net_tx_credit: u32,
        app_rx_credit: u32,
    ) -> RelayOutput {
        if self.terminal.is_some() {
            return self.output(0, None, false, 0, 0);
        }
        if !self.committed {
            return self.rejected(RelayError::state("tls_io"));
        }
        if self.check_deadline() {
            return self.output(0, None, false, 0, 0);
        }
        let mut accepted = 0;
        match input {
            Input::None => {}
            Input::NetworkError => {
                self.fail(RelayError {
                    code: "E_NETWORK",
                    status: 0x1403,
                    stage: "network",
                });
                return self.output(0, None, false, 0, 0);
            }
            Input::Tls { offset, bytes } => {
                if offset != self.accepted_tls_rx || bytes.is_empty() || self.eof_queued {
                    return self.rejected(RelayError::wire());
                }
                if bytes.len() <= MAX_PENDING - self.tls_rx.len() {
                    let Some(next) = self.accepted_tls_rx.checked_add(bytes.len() as u64) else {
                        return self.rejected(RelayError::wire());
                    };
                    self.tls_rx.extend(bytes);
                    self.accepted_tls_rx = next;
                    accepted = bytes.len() as u32;
                }
            }
            Input::Eof { offset } => {
                if offset != self.accepted_tls_rx || self.eof_queued {
                    return self.rejected(RelayError::wire());
                }
                self.eof_queued = true;
            }
        }
        if let Err(error) = self.pump() {
            self.fail(error);
        }
        self.output(accepted, None, false, net_tx_credit, app_rx_credit)
    }

    /// Snapshot only. It neither pumps TLS nor consumes the terminal event.
    pub fn status(&self) -> RelayOutput {
        RelayOutput {
            state: self.state(),
            error: None,
            progress: self.progress(0, Vec::new(), false),
            payload: Vec::new(),
        }
    }

    pub fn finish(&mut self, reason: FinishReason, model_terminal: bool) -> RelayOutput {
        if self.terminal.is_some() {
            return self.output(0, None, false, 0, 0);
        }
        if self.check_deadline() {
            return self.output(0, None, false, 0, 0);
        }
        let end_reason = match reason {
            FinishReason::ConsumerComplete
                if model_terminal && self.head_emitted && self.emitted_http_body > 0 =>
            {
                "consumer_complete"
            }
            FinishReason::ResponseConsumed
                if self.end_emitted
                    && self.parser.body.is_empty()
                    && self.parser.head.is_none() =>
            {
                "response_consumed"
            }
            _ => return self.rejected(RelayError::state("finish")),
        };
        self.terminate("ENDED", end_reason, None);
        self.output(0, None, false, 0, 0)
    }

    pub fn cancel(&mut self, reason: CancelReason) -> RelayOutput {
        self.check_deadline();
        if self.terminal.is_none() {
            match reason {
                CancelReason::Timeout => self.terminate("EXPIRED", "deadline", None),
                _ => self.terminate("CANCELLED", "cancelled", None),
            }
        }
        self.output(0, None, false, 0, 0)
    }

    pub fn revoke(&mut self) -> RelayOutput {
        self.latch_revoked();
        self.output(0, None, false, 0, 0)
    }

    /// Latches a sweeper observation without consuming REQUEST_END.
    pub fn latch_revoked(&mut self) {
        if self.terminal.is_none() {
            self.terminate(
                "FAILED",
                "revoked",
                Some(RelayError {
                    code: "E_CREDENTIAL_REVOKED",
                    status: 0x1206,
                    stage: "credential",
                }),
            );
        }
    }

    pub fn expire(&mut self) -> RelayOutput {
        self.latch_expired();
        self.output(0, None, false, 0, 0)
    }

    /// Latches a sweeper observation without consuming REQUEST_END.
    pub fn latch_expired(&mut self) {
        if self.terminal.is_none() {
            self.terminate(
                "EXPIRED",
                "deadline",
                Some(RelayError {
                    code: "E_DEADLINE",
                    status: 0x1404,
                    stage: "deadline",
                }),
            );
        }
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }

    fn state(&self) -> &'static str {
        if self.terminal.is_some() {
            self.terminal_state
        } else if !self.committed {
            "UPLOADING"
        } else if self.parser.complete() {
            "HTTP_COMPLETE"
        } else if self.tls.as_ref().is_some_and(|tls| tls.is_handshaking()) {
            "HANDSHAKING"
        } else {
            "EXCHANGING"
        }
    }

    fn check_deadline(&mut self) -> bool {
        if self.terminal.is_some() {
            return true;
        }
        if Instant::now() >= self.deadline {
            self.terminate(
                "EXPIRED",
                "deadline",
                Some(RelayError {
                    code: "E_DEADLINE",
                    status: 0x1404,
                    stage: "deadline",
                }),
            );
            return true;
        }
        false
    }

    fn fail(&mut self, error: RelayError) {
        let reason = match error.code {
            "E_TLS" | "E_NETWORK" | "E_HTTP_PARSE" | "E_HTTP_LIMIT" => "transport_error",
            _ => "internal_error",
        };
        if error.code == "E_TLS" {
            self.tls_phase = "failed";
        }
        self.terminate("FAILED", reason, Some(error));
    }

    fn terminate(&mut self, state: &'static str, reason: &'static str, error: Option<RelayError>) {
        if self.terminal.is_some() {
            return;
        }
        self.terminal = Some(json!({
            "end_reason":reason,"http_framing":self.parser.framing(),"tls_phase":self.tls_phase,
            "close_notify_received":self.close_notify,
            "request_application_bytes_generated":self.generated.to_string(),
            "emitted_http_body":self.emitted_http_body.to_string(),
            "app_resources":"released","manager_cleanup":"not_asserted"
        }));
        self.terminal_state = state;
        self.terminal_error = error;
        self.request_head.zeroize();
        self.request_head = Vec::new();
        self.request_body.zeroize();
        self.request_body = Vec::new();
        self.tls_rx = VecDeque::new();
        self.tls_tx = VecDeque::new();
        self.parser.clear();
        self.tls = None;
    }

    fn rejected(&self, error: RelayError) -> RelayOutput {
        RelayOutput {
            state: self.state(),
            error: Some(error),
            progress: self.progress(0, Vec::new(), false),
            payload: Vec::new(),
        }
    }

    fn pump(&mut self) -> Result<(), RelayError> {
        for _ in 0..WORK_ROUNDS {
            if self.check_deadline() {
                return Ok(());
            }
            let mut made_progress = false;
            let tls = self.tls.as_mut().ok_or_else(RelayError::internal)?;
            // Stop decryption while plaintext delivery is backpressured.
            if !self.tls_rx.is_empty() && self.parser.capacity() >= IO_CHUNK {
                let contiguous = self.tls_rx.make_contiguous();
                let count = tls
                    .read_tls(&mut Cursor::new(
                        &contiguous[..contiguous.len().min(IO_CHUNK)],
                    ))
                    .map_err(|_| RelayError::tls(tls.is_handshaking()))?;
                self.tls_rx.drain(..count);
                made_progress |= count > 0;
                let state = tls
                    .process_new_packets()
                    .map_err(|_| RelayError::tls(tls.is_handshaking()))?;
                self.close_notify |= state.peer_has_closed();
                self.plaintext_pending = state.plaintext_bytes_to_read();
            }
            if self.eof_queued && self.tls_rx.is_empty() && !self.eof_processed {
                tls.read_tls(&mut Cursor::new(&[]))
                    .map_err(|_| RelayError::tls(tls.is_handshaking()))?;
                self.eof_processed = true;
                made_progress = true;
            }
            if !tls.is_handshaking() {
                self.tls_phase = if self.close_notify {
                    "closed"
                } else {
                    "application"
                };
                let remaining_head = &self.request_head[self.request_head_offset..];
                let source = if !remaining_head.is_empty() {
                    remaining_head
                } else {
                    &self.request_body[self.request_body_offset..]
                };
                if !source.is_empty() && self.tls_tx.len() + IO_CHUNK + 1024 <= MAX_PENDING {
                    let count = tls
                        .writer()
                        .write(&source[..source.len().min(IO_CHUNK)])
                        .map_err(|_| RelayError::tls(false))?;
                    if !remaining_head.is_empty() {
                        self.request_head_offset += count;
                    } else {
                        self.request_body_offset += count;
                    }
                    self.generated += count as u64;
                    made_progress |= count > 0;
                    if self.request_head_offset == self.request_head.len() {
                        self.request_head.zeroize();
                        self.request_head = Vec::new();
                        self.request_head_offset = 0;
                    }
                    if self.request_body_offset == self.request_body.len() {
                        self.request_body.zeroize();
                        self.request_body = Vec::new();
                        self.request_body_offset = 0;
                    }
                }
            }
            if tls.wants_write() && self.tls_tx.len() < MAX_PENDING {
                let mut writer = QueueWriter {
                    queue: &mut self.tls_tx,
                };
                let count = tls
                    .write_tls(&mut writer)
                    .map_err(|_| RelayError::tls(tls.is_handshaking()))?;
                made_progress |= count > 0;
            }
            let capacity = self.parser.capacity().min(IO_CHUNK);
            if capacity > 0 && !self.plaintext_eof {
                let mut plain = [0u8; IO_CHUNK];
                match tls.reader().read(&mut plain[..capacity]) {
                    Ok(0) => {
                        self.plaintext_eof = true;
                        made_progress = true;
                    }
                    Ok(count) => {
                        self.plaintext_pending = self.plaintext_pending.saturating_sub(count);
                        self.parser.feed(&plain[..count])?;
                        made_progress = true;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error)
                        if error.kind() == io::ErrorKind::UnexpectedEof
                            && self.parser.complete() =>
                    {
                        self.plaintext_eof = true;
                    }
                    Err(_) => return Err(RelayError::tls(tls.is_handshaking())),
                }
            }
            self.parser.feed(&[])?;
            if self.plaintext_eof {
                self.parser.eof()?;
            }
            if !made_progress {
                break;
            }
        }
        Ok(())
    }

    fn output(
        &mut self,
        accepted: u32,
        error: Option<RelayError>,
        connect_target: bool,
        net_credit: u32,
        app_credit: u32,
    ) -> RelayOutput {
        let mut events = Vec::new();
        let mut payload = Vec::new();
        if let Some(terminal) = self.terminal.clone() {
            if !self.terminal_event_emitted {
                self.push_event(&mut events, "REQUEST_END", 0, 0, None, None, Some(terminal));
                self.terminal_event_emitted = true;
            }
            let error = error.or_else(|| {
                if events.is_empty() {
                    None
                } else {
                    self.terminal_error
                }
            });
            return RelayOutput {
                state: self.state(),
                error,
                progress: self.progress(accepted, events, false),
                payload,
            };
        }
        let count = self
            .tls_tx
            .len()
            .min(net_credit as usize)
            .min(FRAME_PAYLOAD);
        if count > 0 {
            payload.extend(self.tls_tx.drain(..count));
            self.push_event(
                &mut events,
                "NET_TX",
                0,
                count,
                Some(self.emitted_tls_tx),
                Some(self.generated > 0),
                None,
            );
            self.emitted_tls_tx += count as u64;
        }
        if let Some(head) = self.parser.head.as_ref() {
            if payload.len() + head.len() <= FRAME_PAYLOAD {
                let head = self.parser.head.take().unwrap();
                let offset = payload.len();
                payload.extend_from_slice(&head);
                self.push_event(
                    &mut events,
                    "HTTP_HEAD",
                    offset,
                    head.len(),
                    None,
                    None,
                    None,
                );
                self.head_emitted = true;
            }
        }
        if self.head_emitted {
            let count = self
                .parser
                .body
                .len()
                .min(app_credit as usize)
                .min(FRAME_PAYLOAD - payload.len());
            if count > 0 {
                let offset = payload.len();
                payload.extend(self.parser.body.drain(..count));
                self.push_event(
                    &mut events,
                    "HTTP_BODY",
                    offset,
                    count,
                    Some(self.emitted_http_body),
                    None,
                    None,
                );
                self.emitted_http_body += count as u64;
            }
            if self.parser.complete() && self.parser.body.is_empty() && !self.end_emitted {
                self.push_event(&mut events,"HTTP_END",payload.len(),0,None,None,
                    Some(json!({"framing":"complete","body_bytes":self.parser.received_body.to_string()})));
                self.end_emitted = true;
            }
        }
        RelayOutput {
            state: self.state(),
            error,
            progress: self.progress(accepted, events, connect_target),
            payload,
        }
    }

    fn push_event(
        &mut self,
        events: &mut Vec<Value>,
        kind: &str,
        offset: usize,
        length: usize,
        stream: Option<u64>,
        contains_request: Option<bool>,
        details: Option<Value>,
    ) {
        self.event_seq += 1;
        let mut event = json!({"event_seq":self.event_seq.to_string(),"kind":kind,"offset":offset,"length":length});
        if let Some(stream) = stream {
            event["stream_offset"] = json!(stream.to_string());
        }
        if let Some(contains_request) = contains_request {
            event["may_contain_request"] = json!(contains_request);
        }
        if let Some(details) = details {
            event["details"] = details;
        }
        events.push(event);
    }

    fn progress(&self, accepted: u32, events: Vec<Value>, connect: bool) -> Value {
        let active = self.terminal.is_none() && self.committed;
        let net_pending = active
            && (!self.tls_tx.is_empty() || self.tls.as_ref().is_some_and(|tls| tls.wants_write()));
        let body_pending = active && (!self.parser.body.is_empty() || self.parser.head.is_some());
        let unsent_request = self.request_head_offset < self.request_head.len()
            || self.request_body_offset < self.request_body.len();
        let need_step = active
            && (net_pending
                || body_pending
                || !self.tls_rx.is_empty()
                || (self.tls.as_ref().is_some_and(|tls| !tls.is_handshaking()) && unsent_request)
                || self.plaintext_pending > 0
                || (self.eof_queued && !self.eof_processed)
                || (self.parser.complete() && !self.end_emitted));
        json!({
            "accepted_input_bytes":accepted,"uploaded_body":self.uploaded_body.to_string(),
            "accepted_tls_rx":self.accepted_tls_rx.to_string(),"emitted_tls_tx":self.emitted_tls_tx.to_string(),
            "emitted_http_body":self.emitted_http_body.to_string(),
            "rx_credit":if active && !self.eof_queued {MAX_PENDING-self.tls_rx.len()} else {0},
            "net_tx_pending":net_pending,"http_body_pending":body_pending,"need_step":need_step,
            "poll_after_ms":if need_step {0} else {1000},"events":events,"terminal":self.terminal,
            "connect_target":if connect && self.terminal.is_none() {self.provider.connect_target()} else {Value::Null}
        })
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.request_head.zeroize();
        self.request_body.zeroize();
    }
}

struct QueueWriter<'a> {
    queue: &'a mut VecDeque<u8>,
}
impl Write for QueueWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(MAX_PENDING - self.queue.len());
        if count == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.queue.extend(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
fn build_request_head(
    operation: Operation,
    body_length: usize,
    key: &[u8],
    headers: &[Header],
) -> Result<Vec<u8>, RelayError> {
    build_provider_request_head(
        &ProviderProfile::deepseek(),
        operation,
        None,
        false,
        body_length,
        key,
        headers,
    )
}

fn build_provider_request_head(
    provider: &ProviderProfile,
    operation: Operation,
    model_id: Option<&str>,
    stream: bool,
    body_length: usize,
    key: &[u8],
    headers: &[Header],
) -> Result<Vec<u8>, RelayError> {
    if key.is_empty()
        || key.len() > 4096
        || std::str::from_utf8(key).is_err()
        || key.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err(RelayError::wire());
    }
    if headers.len() > 32 || matches!(operation, Operation::Models) && body_length != 0 {
        return Err(RelayError::wire());
    }
    let target = provider
        .request_target(operation, model_id, stream)
        .map_err(|_| RelayError::wire())?;
    let method = if operation == Operation::Models {
        "GET"
    } else {
        "POST"
    };
    let mut request = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\n",
        provider.authority()
    )
    .into_bytes();
    let auth = provider.auth_header(operation);
    request.extend_from_slice(auth.as_bytes());
    request.extend_from_slice(b": ");
    if auth == "Authorization" {
        request.extend_from_slice(b"Bearer ");
    }
    request.extend_from_slice(key);
    request.extend_from_slice(b"\r\nConnection: close\r\nAccept-Encoding: identity\r\n");
    if let Some(version) = provider.anthropic_version() {
        request.extend_from_slice(b"anthropic-version: ");
        request.extend_from_slice(version.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    let mut has_content_type = false;
    for header in headers {
        let name = header.name.to_ascii_lowercase();
        if name.is_empty()
            || name.len() > 256
            || header.value.len() > 4096
            || !name.bytes().all(token)
            || matches!(
                name.as_str(),
                "host"
                    | "authorization"
                    | "x-api-key"
                    | "x-goog-api-key"
                    | "anthropic-version"
                    | "content-length"
                    | "transfer-encoding"
                    | "connection"
                    | "accept-encoding"
                    | "te"
                    | "trailer"
                    | "upgrade"
            )
            || name.starts_with("proxy-")
            || header
                .value
                .bytes()
                .any(|byte| byte < 32 && byte != b'\t' || byte == 127)
        {
            request.zeroize();
            return Err(RelayError::wire());
        }
        has_content_type |= name == "content-type";
        request.extend_from_slice(header.name.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(header.value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    if !has_content_type && operation != Operation::Models {
        request.extend_from_slice(b"Content-Type: application/json\r\n");
    }
    request.extend_from_slice(format!("Content-Length: {body_length}\r\n\r\n").as_bytes());
    if request.len() > 16 * 1024 {
        request.zeroize();
        return Err(RelayError::http_limit());
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::{ServerConfig, ServerConnection};

    const TEST_KEY: &[u8] = b"fake-key-only-for-local-tests-8a913a5c";

    fn connections(body: Vec<u8>, hostname: &str, trusted: bool) -> (Relay, ServerConnection) {
        provider_connections(
            &ProviderProfile::deepseek(),
            Operation::Chat,
            None,
            false,
            body,
            hostname,
            trusted,
        )
    }

    fn provider_connections(
        profile: &ProviderProfile,
        operation: Operation,
        model_id: Option<&str>,
        stream: bool,
        body: Vec<u8>,
        hostname: &str,
        trusted: bool,
    ) -> (Relay, ServerConnection) {
        let identity = rcgen::generate_simple_self_signed(vec![hostname.into()]).unwrap();
        let mut roots = RootCertStore::empty();
        if trusted {
            roots.add(identity.cert.der().clone()).unwrap();
        }
        let relay = Relay::for_provider_with_roots(
            profile,
            operation,
            model_id,
            stream,
            body,
            TEST_KEY,
            &[],
            Duration::from_secs(60),
            roots,
        )
        .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.cert.der().clone()],
                PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
            )
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut server = ServerConnection::new(Arc::new(config)).unwrap();
        server.set_buffer_limit(None);
        (relay, server)
    }

    struct Transcript {
        body: Vec<u8>,
        request: Vec<u8>,
        heads: Vec<Value>,
        end_count: usize,
        event_seq: u64,
        net_offset: u64,
        body_offset: u64,
    }

    impl Transcript {
        fn new() -> Self {
            Self {
                body: Vec::new(),
                request: Vec::new(),
                heads: Vec::new(),
                end_count: 0,
                event_seq: 0,
                net_offset: 0,
                body_offset: 0,
            }
        }

        fn consume(&mut self, output: &RelayOutput, server: &mut ServerConnection) {
            assert!(output.payload.len() <= FRAME_PAYLOAD);
            assert!(serde_json::to_vec(&output.progress).unwrap().len() < 3500);
            let mut cursor = 0;
            for event in output.progress["events"].as_array().unwrap() {
                let seq = event["event_seq"].as_str().unwrap().parse::<u64>().unwrap();
                assert_eq!(seq, self.event_seq + 1);
                self.event_seq = seq;
                let offset = event["offset"].as_u64().unwrap() as usize;
                let length = event["length"].as_u64().unwrap() as usize;
                assert_eq!(offset, cursor);
                let bytes = &output.payload[offset..offset + length];
                cursor += length;
                match event["kind"].as_str().unwrap() {
                    "NET_TX" => {
                        assert_eq!(event["stream_offset"], self.net_offset.to_string());
                        self.net_offset += length as u64;
                        assert!(!bytes.windows(TEST_KEY.len()).any(|part| part == TEST_KEY));
                        let mut input = Cursor::new(bytes);
                        while input.position() < bytes.len() as u64 {
                            server.read_tls(&mut input).unwrap();
                            server.process_new_packets().unwrap();
                        }
                    }
                    "HTTP_HEAD" => self.heads.push(serde_json::from_slice(bytes).unwrap()),
                    "HTTP_BODY" => {
                        assert!(!self.heads.is_empty());
                        assert_eq!(self.end_count, 0);
                        assert_eq!(event["stream_offset"], self.body_offset.to_string());
                        self.body_offset += length as u64;
                        self.body.extend_from_slice(bytes);
                    }
                    "HTTP_END" => {
                        self.end_count += 1;
                        assert_eq!(event["details"]["body_bytes"], self.body_offset.to_string());
                    }
                    "REQUEST_END" => {}
                    other => panic!("unexpected event {other}"),
                }
            }
            assert_eq!(cursor, output.payload.len());
            let mut plain = [0u8; 4096];
            loop {
                match server.reader().read(&mut plain) {
                    Ok(0) => break,
                    Ok(count) => self.request.extend_from_slice(&plain[..count]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("server read {error:?}"),
                }
            }
        }
    }

    /// Runs a complete local verified TLS peer without opening any TCP socket.
    fn drive(response: &[u8], body: Vec<u8>, app_credit: u32, close: bool) -> (Relay, Transcript) {
        let request_length = body.len();
        let (relay, server) = connections(body, HOST, true);
        drive_peer(relay, server, response, request_length, app_credit, close)
    }

    fn drive_peer(
        mut relay: Relay,
        mut server: ServerConnection,
        response: &[u8],
        request_length: usize,
        app_credit: u32,
        close: bool,
    ) -> (Relay, Transcript) {
        let mut output = relay.commit(4000, app_credit);
        assert_eq!(
            output.progress["connect_target"],
            relay.provider.connect_target()
        );
        let mut transcript = Transcript::new();
        let mut server_out = VecDeque::new();
        let mut response_sent = false;
        for _ in 0..2000 {
            assert!(output.error.is_none(), "{:?}", output.error);
            transcript.consume(&output, &mut server);
            let header_end = transcript
                .request
                .windows(4)
                .position(|part| part == b"\r\n\r\n");
            let request_done =
                header_end.is_some_and(|end| transcript.request.len() == end + 4 + request_length);
            if request_done && !response_sent {
                server.writer().write_all(response).unwrap();
                if close {
                    server.send_close_notify();
                }
                response_sent = true;
            }
            if server.wants_write() {
                let mut bytes = Vec::new();
                server.write_tls(&mut bytes).unwrap();
                server_out.extend(bytes);
            }
            if transcript.end_count == 1 {
                return (relay, transcript);
            }
            let count = server_out
                .len()
                .min(14000)
                .min(relay.status().progress["rx_credit"].as_u64().unwrap() as usize);
            let input = server_out.drain(..count).collect::<Vec<_>>();
            output = if input.is_empty() {
                relay.step(Input::None, 4000, app_credit)
            } else {
                relay.step(
                    Input::Tls {
                        offset: relay.accepted_tls_rx,
                        bytes: &input,
                    },
                    4000,
                    app_credit,
                )
            };
        }
        panic!("local TLS peer did not finish");
    }

    #[test]
    fn verified_tls_authentication_and_long_stream_are_bounded() {
        let body = vec![b'q'; 200_000];
        let response_body = (0..200_000)
            .map(|index| (index % 253) as u8)
            .collect::<Vec<_>>();
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
            response_body.len()
        )
        .into_bytes();
        response.extend_from_slice(&response_body);
        let (mut relay, transcript) = drive(&response, body.clone(), 217, true);
        assert_eq!(transcript.body, response_body);
        assert_eq!(transcript.heads.len(), 1);
        assert_eq!(transcript.heads[0]["status"], 200);
        let header_end = transcript
            .request
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap();
        assert_eq!(&transcript.request[header_end + 4..], body);
        assert!(
            transcript
                .request
                .windows(TEST_KEY.len())
                .any(|part| part == TEST_KEY)
        );
        assert!(
            transcript
                .request
                .starts_with(b"POST /chat/completions HTTP/1.1\r\n")
        );
        assert!(
            transcript
                .request
                .windows(b"Accept-Encoding: identity\r\n".len())
                .any(|part| part == b"Accept-Encoding: identity\r\n")
        );
        let finish = relay.finish(FinishReason::ResponseConsumed, false);
        assert_eq!(finish.state, "ENDED");
        assert!(finish.payload.is_empty());
        assert_eq!(finish.progress["events"][0]["kind"], "REQUEST_END");
        assert_eq!(finish.progress["terminal"]["http_framing"], "complete");
        assert_eq!(
            finish.progress["terminal"]["emitted_http_body"],
            response_body.len().to_string()
        );
        assert!(
            relay.cancel(CancelReason::User).progress["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_untrusted_chain_and_wrong_hostname() {
        for (hostname, trusted) in [(HOST, false), ("wrong.example", true)] {
            let (mut relay, mut server) = connections(Vec::new(), hostname, trusted);
            let output = relay.commit(32768, 32768);
            let bytes = &output.payload;
            server.read_tls(&mut Cursor::new(bytes)).unwrap();
            server.process_new_packets().unwrap();
            let mut server_bytes = Vec::new();
            server.write_tls(&mut server_bytes).unwrap();
            let result = relay.step(
                Input::Tls {
                    offset: 0,
                    bytes: &server_bytes,
                },
                32768,
                32768,
            );
            assert_eq!(result.error.unwrap().code, "E_TLS");
            assert_eq!(result.state, "FAILED");
            assert_eq!(result.progress["accepted_input_bytes"], server_bytes.len());
            assert!(result.payload.is_empty());
            assert_eq!(result.progress["events"].as_array().unwrap().len(), 1);
            assert_eq!(result.progress["events"][0]["kind"], "REQUEST_END");
        }
    }

    #[test]
    fn chunked_non_success_and_eof_framing_preserve_body() {
        let (relay, transcript) = drive(
            b"HTTP/1.1 429 Busy\r\nTransfer-Encoding: chunked\r\n\r\n3\r\na\nb\r\n0\r\n\r\n",
            Vec::new(),
            1,
            true,
        );
        assert_eq!(transcript.body, b"a\nb");
        assert_eq!(transcript.heads[0]["status"], 429);
        assert_eq!(relay.state(), "HTTP_COMPLETE");
        let (_, transcript) = drive(b"HTTP/1.1 200 OK\r\n\r\nEOF body", Vec::new(), 2, true);
        assert_eq!(transcript.body, b"EOF body");
    }

    #[test]
    fn cancel_zero_credit_and_status_are_control_only() {
        let (mut relay, _) = connections(vec![b'x'; 200000], HOST, true);
        let committed = relay.commit(0, 0);
        assert!(committed.payload.is_empty());
        assert!(committed.progress["net_tx_pending"].as_bool().unwrap());
        let before = relay.status();
        let again = relay.status();
        assert_eq!(before.progress, again.progress);
        let cancelled = relay.cancel(CancelReason::User);
        assert_eq!(cancelled.state, "CANCELLED");
        assert!(cancelled.payload.is_empty());
        assert_eq!(cancelled.progress["emitted_tls_tx"], "0");
        assert_eq!(
            cancelled.progress["terminal"]["request_application_bytes_generated"],
            "0"
        );
        assert_eq!(cancelled.progress["events"].as_array().unwrap().len(), 1);
        assert!(relay.tls.is_none());
        assert!(relay.request_head.is_empty());
        assert!(relay.request_body.is_empty());
        assert!(
            relay.status().progress["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            relay.finish(FinishReason::ResponseConsumed, false).progress["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn input_acceptance_is_whole_or_zero_with_stable_offsets() {
        let (mut relay, _) = connections(Vec::new(), HOST, true);
        relay.commit(0, 0);
        // Prevent decryption by filling the bounded plaintext queue.
        relay
            .parser
            .body
            .extend(std::iter::repeat_n(0, MAX_PENDING));
        relay
            .tls_rx
            .extend(std::iter::repeat_n(0, MAX_PENDING - 10));
        let refused = relay.step(
            Input::Tls {
                offset: 0,
                bytes: &[0; 11],
            },
            0,
            0,
        );
        assert_eq!(refused.progress["accepted_input_bytes"], 0);
        assert_eq!(refused.progress["accepted_tls_rx"], "0");
        let accepted = relay.step(
            Input::Tls {
                offset: 0,
                bytes: &[0; 10],
            },
            0,
            0,
        );
        assert_eq!(accepted.progress["accepted_input_bytes"], 10);
        assert_eq!(accepted.progress["accepted_tls_rx"], "10");
        assert_eq!(accepted.progress["rx_credit"], 0);
        let mismatch = relay.step(
            Input::Tls {
                offset: 0,
                bytes: &[0],
            },
            0,
            0,
        );
        assert_eq!(mismatch.error.unwrap().code, "E_WIRE_FORMAT");
        assert_eq!(mismatch.progress["accepted_input_bytes"], 0);
    }

    fn paused_response(response: &[u8], app_credit: u32) -> (Relay, Transcript) {
        let (mut relay, mut server) = connections(Vec::new(), HOST, true);
        let mut transcript = Transcript::new();
        let mut output = relay.commit(32768, app_credit);
        let mut sent = false;
        for _ in 0..100 {
            assert!(output.error.is_none(), "{:?}", output.error);
            transcript.consume(&output, &mut server);
            if !sent
                && transcript
                    .request
                    .windows(4)
                    .any(|part| part == b"\r\n\r\n")
            {
                server.writer().write_all(response).unwrap();
                sent = true;
            }
            let mut bytes = Vec::new();
            if server.wants_write() {
                server.write_tls(&mut bytes).unwrap();
            }
            if sent && bytes.is_empty() && relay.tls_rx.is_empty() && relay.plaintext_pending == 0 {
                return (relay, transcript);
            }
            output = if bytes.is_empty() {
                relay.step(Input::None, 32768, app_credit)
            } else {
                relay.step(
                    Input::Tls {
                        offset: relay.accepted_tls_rx,
                        bytes: &bytes,
                    },
                    32768,
                    app_credit,
                )
            };
        }
        panic!("TLS peer did not reach pause");
    }

    #[test]
    fn finish_preserves_incomplete_framing_and_drops_pending_without_delivery() {
        let (mut relay, transcript) = paused_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: [DONE]\n\n",
            3,
        );
        assert_eq!(transcript.body.len(), 3);
        assert_eq!(transcript.end_count, 0);
        assert!(relay.parser.body.len() > 0);
        assert_eq!(
            relay
                .finish(FinishReason::ResponseConsumed, false)
                .error
                .unwrap()
                .code,
            "E_STATE"
        );
        assert_eq!(
            relay
                .finish(FinishReason::ConsumerComplete, false)
                .error
                .unwrap()
                .code,
            "E_STATE"
        );
        let ended = relay.finish(FinishReason::ConsumerComplete, true);
        assert_eq!(ended.state, "ENDED");
        assert!(ended.payload.is_empty());
        assert_eq!(ended.progress["events"].as_array().unwrap().len(), 1);
        assert_eq!(ended.progress["events"][0]["kind"], "REQUEST_END");
        assert_eq!(ended.progress["terminal"]["http_framing"], "in_progress");
        assert_eq!(ended.progress["terminal"]["emitted_http_body"], "3");
    }

    #[test]
    fn known_network_failure_discards_pending_success_body() {
        let (mut relay, transcript) =
            paused_response(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n[DONE]", 0);
        assert_eq!(transcript.body.len(), 0);
        assert_eq!(transcript.end_count, 0);
        let failed = relay.step(Input::NetworkError, 32768, 32768);
        assert_eq!(failed.error.unwrap().code, "E_NETWORK");
        assert_eq!(failed.state, "FAILED");
        assert!(failed.payload.is_empty());
        assert_eq!(failed.progress["events"].as_array().unwrap().len(), 1);
        assert_eq!(failed.progress["terminal"]["emitted_http_body"], "0");
        assert_eq!(failed.progress["terminal"]["http_framing"], "complete");
        assert_eq!(
            relay.finish(FinishReason::ConsumerComplete, true).state,
            "FAILED"
        );
    }

    #[test]
    fn partial_http_head_requests_more_network_without_busy_pumping() {
        let (mut relay, transcript) = paused_response(b"HTTP/1.1 200 OK\r\nContent-Len", 8192);
        assert!(transcript.heads.is_empty());
        let output = relay.step(Input::None, 8192, 8192);
        assert!(output.error.is_none());
        assert_eq!(output.progress["need_step"], false);
        assert!(output.progress["rx_credit"].as_u64().unwrap() > 0);
    }

    #[test]
    fn empty_pump_is_not_eof_and_unclosed_eof_body_fails_tls() {
        let (mut relay, transcript) = paused_response(b"HTTP/1.1 200 OK\r\n\r\nincomplete", 32768);
        assert_eq!(transcript.body, b"incomplete");
        let empty = relay.step(Input::None, 32768, 32768);
        assert!(empty.error.is_none());
        assert_eq!(empty.state, "EXCHANGING");
        assert!(empty.progress["events"].as_array().unwrap().is_empty());
        let offset = relay.accepted_tls_rx;
        let failed = relay.step(Input::Eof { offset }, 32768, 32768);
        assert_eq!(failed.error.unwrap().code, "E_TLS");
        assert_eq!(failed.state, "FAILED");
        assert!(failed.payload.is_empty());
        assert_eq!(failed.progress["terminal"]["http_framing"], "in_progress");
    }

    #[test]
    fn elapsed_deadline_terminates_before_commit_and_before_cancel() {
        let (mut relay, _) = connections(Vec::new(), HOST, true);
        relay.shorten_deadline(Duration::ZERO);
        let expired = relay.commit(32768, 32768);
        assert_eq!(expired.state, "EXPIRED");
        assert_eq!(expired.error.unwrap().code, "E_DEADLINE");
        assert!(expired.payload.is_empty());
        assert!(expired.progress["connect_target"].is_null());
        assert_eq!(expired.progress["terminal"]["tls_phase"], "not_started");
        let (mut relay, _) = connections(Vec::new(), HOST, true);
        relay.shorten_deadline(Duration::ZERO);
        let expired = relay.cancel(CancelReason::User);
        assert_eq!(expired.progress["terminal"]["end_reason"], "deadline");
    }

    #[test]
    fn deadline_and_revocation_latching_preserve_one_terminal_event() {
        for revoked in [false, true] {
            let (mut relay, _) = connections(Vec::new(), HOST, true);
            relay.commit(0, 0);
            if revoked {
                relay.latch_revoked();
            } else {
                relay.latch_expired();
            }
            assert!(
                relay.status().progress["events"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            let terminal = relay.step(Input::None, 0, 0);
            assert_eq!(terminal.progress["events"].as_array().unwrap().len(), 1);
            assert_eq!(
                terminal.error.unwrap().code,
                if revoked {
                    "E_CREDENTIAL_REVOKED"
                } else {
                    "E_DEADLINE"
                }
            );
            let repeat = relay.cancel(CancelReason::User);
            assert_eq!(repeat.progress["terminal"], terminal.progress["terminal"]);
            assert!(repeat.progress["events"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn fixed_target_reserved_headers_and_models_body_are_enforced() {
        for name in [
            "Authorization",
            "HOST",
            "Proxy-Authorization",
            "Content-Length",
            "Transfer-Encoding",
            "Accept-Encoding",
            "x-API-key",
            "X-Goog-Api-Key",
            "Anthropic-Version",
        ] {
            let error = build_request_head(
                Operation::Chat,
                0,
                TEST_KEY,
                &[Header {
                    name: name.into(),
                    value: "x".into(),
                }],
            )
            .unwrap_err();
            assert_eq!(error.code, "E_WIRE_FORMAT");
        }
        assert!(build_request_head(Operation::Models, 1, TEST_KEY, &[]).is_err());
        assert!(build_request_head(Operation::Chat, 0, b"bad\r\nkey", &[]).is_err());
        let models = build_request_head(Operation::Models, 0, TEST_KEY, &[]).unwrap();
        assert!(models.starts_with(b"GET /models HTTP/1.1\r\n"));
    }

    #[test]
    fn custom_providers_verify_tls_and_preserve_request_and_response_bytes() {
        let response_body = b" {\"raw\":\"provider bytes\",\"value\":0.125}\n";
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            response_body.len()
        )
        .into_bytes();
        response.extend_from_slice(response_body);
        for (provider_type, operation, model_id, endpoint, auth, extra) in [
            (
                "openai_compatible",
                Operation::Chat,
                None,
                "chat/completions",
                "Authorization: Bearer ",
                "",
            ),
            (
                "openai_responses",
                Operation::Responses,
                None,
                "responses",
                "Authorization: Bearer ",
                "",
            ),
            (
                "anthropic_messages",
                Operation::Messages,
                None,
                "messages",
                "x-api-key: ",
                "anthropic-version: 2023-06-01\r\n",
            ),
            (
                "google_gemini",
                Operation::Generate,
                Some("models/gemini-fixture"),
                "models/gemini-fixture:streamGenerateContent?alt=sse",
                "x-goog-api-key: ",
                "",
            ),
            (
                "ollama_native",
                Operation::OllamaChat,
                None,
                "chat",
                "Authorization: Bearer ",
                "",
            ),
        ] {
            let profile = ProviderProfile::from_metadata(
                crate::provider::CUSTOM_PROFILE_ID,
                Some(&json!({"provider_type":provider_type,"base_url":"https://provider-fixture.test:18443/prefix/"})),
            ).unwrap();
            let body = b" { \"temperature\":0.125, \"messages\":[], \"stream\":true }\n".to_vec();
            let (relay, server) = provider_connections(
                &profile,
                operation,
                model_id,
                true,
                body.clone(),
                "provider-fixture.test",
                true,
            );
            let (mut relay, transcript) =
                drive_peer(relay, server, &response, body.len(), 32768, true);
            assert_eq!(transcript.body, response_body);
            let head_end = transcript
                .request
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap();
            assert_eq!(&transcript.request[head_end + 4..], body);
            let head = std::str::from_utf8(&transcript.request[..head_end + 4]).unwrap();
            assert!(head.starts_with(&format!("POST /prefix/{endpoint} HTTP/1.1\r\n")));
            assert!(head.contains("Host: provider-fixture.test:18443\r\n"));
            assert!(head.contains(&format!(
                "{auth}{}\r\n",
                std::str::from_utf8(TEST_KEY).unwrap()
            )));
            assert!(head.contains(extra));
            assert_eq!(
                relay.finish(FinishReason::ResponseConsumed, false).state,
                "ENDED"
            );
        }
    }
}
