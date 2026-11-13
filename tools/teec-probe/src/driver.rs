use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::*;

const NAMESPACE: &str = "lsp-probe";
const PROFILE: &str = "deepseek-prod-v1";
const FAKE_KEY: &[u8] = b"lsp-probe-intentionally-invalid-key-not-a-user-credential";
// Credits bound TA-owned queues. The reply remains capped by OUTPUT_FRAME_MAX.
const CREDIT: u32 = 65536;
// Fixed BODY_CHUNK/STEP metadata, including epoch, nonce and u64 offsets,
// fits comfortably in the remaining 1320 bytes of a 16 KiB input frame.
const INPUT_CHUNK: usize = 15000;

fn random_id() -> String {
    Uuid::new_v4().simple().to_string()
}
fn expect(reply: &Frame, status: u32, check: &str) -> Result<()> {
    emit(
        json!({"check":check,"ok":reply.status==status,"status":reply.status,
        "expected_status":status,"state":reply.metadata["state"],"call_seq":reply.call_seq.to_string()}),
    );
    require(
        reply.status == status,
        &format!("{check}: unexpected business status {}", reply.status),
    )
}
fn put_metadata(reference: &str, operation: &str, expected: u64, temporary: bool) -> Value {
    let mut metadata = json!({"operation_id":operation,"credential_ref":reference,"namespace":NAMESPACE,
        "profile_id":PROFILE,"expected_version":expected.to_string(),"temporary":temporary});
    if temporary {
        metadata["ttl_ms"] = json!(120000);
    }
    metadata
}
fn query_metadata(reference: &str) -> Value {
    json!({"credential_ref":reference,"namespace":NAMESPACE})
}
fn delete_metadata(reference: &str, operation: &str, expected: u64) -> Value {
    json!({"credential_ref":reference,"namespace":NAMESPACE,"operation_id":operation,"expected_version":expected.to_string()})
}
fn open_metadata(reference: &str, version: u64, models: bool) -> Value {
    json!({"namespace":NAMESPACE,"profile_id":PROFILE,"credential_ref":reference,"expected_version":version.to_string(),
        "operation":if models {"MODELS"} else {"CHAT"},"body_length":if models {"0"} else {"2"},
        "overall_timeout_ms":60000,"response_mode":"json","completion_policy":"HTTP_COMPLETE","headers":[]})
}
fn open_request(
    channel: &mut Channel,
    reference: &str,
    version: u64,
    models: bool,
) -> Result<Frame> {
    if channel.request_id == [0; 16] {
        channel.request_id = *Uuid::new_v4().as_bytes();
    }
    channel.call(REQUEST_OPEN, open_metadata(reference, version, models), &[])
}
fn no_data(reply: &Frame) -> Result<()> {
    require(
        reply.payload.is_empty(),
        "control response unexpectedly contained payload",
    )?;
    for event in reply.metadata["progress"]["events"]
        .as_array()
        .ok_or("events absent")?
    {
        require(
            event["kind"] == "REQUEST_END",
            "control response contained business event",
        )?;
    }
    Ok(())
}

pub fn test_suite() -> Result<()> {
    let reference = random_id();
    let operation = random_id();
    let mut management = Channel::hello("management", true)?;
    let metadata = put_metadata(&reference, &operation, 0, false);
    let reply = management.call(CREDENTIAL_PUT, metadata.clone(), FAKE_KEY)?;
    expect(&reply, OK, "credential_put_fake")?;
    require(reply.metadata["result"]["version"] == "1", "PUT version")?;
    let reply = management.call(CREDENTIAL_QUERY, query_metadata(&reference), &[])?;
    expect(&reply, OK, "credential_query_live")?;
    require(
        reply.metadata["result"]["state"] == "live"
            && reply.metadata["result"]["receipt"]["operation_id"] == operation,
        "QUERY receipt",
    )?;
    let reply = management.call(CREDENTIAL_PUT, metadata.clone(), FAKE_KEY)?;
    expect(&reply, OK, "credential_receipt_replay_before_cas")?;
    require(
        reply.metadata["result"]["replayed"] == true && reply.metadata["result"]["version"] == "1",
        "PUT replay changed version",
    )?;
    let mut conflict = metadata;
    conflict["expected_version"] = json!("1");
    let reply = management.call(CREDENTIAL_PUT, conflict, FAKE_KEY)?;
    expect(
        &reply,
        E_OPERATION_CONFLICT,
        "same_operation_changed_fingerprint",
    )?;
    let reply = management.call(
        CREDENTIAL_PUT,
        put_metadata(&reference, &random_id(), 0, false),
        FAKE_KEY,
    )?;
    expect(&reply, E_VERSION_CONFLICT, "credential_put_stale_cas")?;

    let mut first = Channel::hello("request", false)?;
    expect(
        &open_request(&mut first, &reference, 1, false)?,
        OK,
        "first_request_open",
    )?;
    let mut second = Channel::hello("request", false)?;
    let second_open = open_request(&mut second, &reference, 1, false)?;
    if management.generation_limit == 1 {
        expect(&second_open, E_BUSY, "second_request_busy")?;
    } else {
        expect(&second_open, OK, "second_request_admitted")?;
        expect(
            &second.call(CANCEL, json!({"reason":"user"}), &[])?,
            OK,
            "second_request_cancel_independently",
        )?;
        drop(second);
        second = Channel::hello("request", false)?;
    }
    let reply = first.call(BODY_CHUNK, json!({"body_offset":"1"}), b"{}")?;
    expect(&reply, E_BODY_OFFSET, "body_offset_rejected")?;
    require(
        reply.metadata["progress"]["uploaded_body"] == "0",
        "bad offset consumed upload",
    )?;
    let reply = first.call(BODY_CHUNK, json!({"body_offset":"0"}), b"{}")?;
    expect(&reply, OK, "body_offset_retry_new_sequence")?;
    require(
        reply.metadata["progress"]["accepted_input_bytes"] == 2
            && reply.metadata["progress"]["uploaded_body"] == "2",
        "upload ownership counters",
    )?;
    let reply = first.call(FINISH, json!({"reason":"response_consumed"}), &[])?;
    expect(&reply, E_STATE, "finish_before_http_end_rejected")?;
    no_data(&reply)?;
    let reply=first.call(BODY_COMMIT,json!({"body_sha256":format!("{:x}",Sha256::digest(b"{}")),"net_tx_credit":0,"app_rx_credit":0}),&[])?;
    expect(&reply, OK, "body_commit_zero_credit")?;
    require(
        reply.payload.is_empty()
            && reply.metadata["progress"]["connect_target"]["host"] == "api.deepseek.com",
        "COMMIT target/credit",
    )?;
    let reply = first.call(CANCEL, json!({"reason":"user"}), &[])?;
    expect(&reply, OK, "cancel_zero_credit")?;
    no_data(&reply)?;
    require(
        reply.metadata["state"] == "CANCELLED"
            && reply.metadata["progress"]["events"]
                .as_array()
                .unwrap()
                .len()
                == 1,
        "CANCEL terminal",
    )?;
    let terminal = reply.metadata["progress"]["terminal"].clone();
    let reply = first.call(STATUS, json!({}), &[])?;
    expect(&reply, OK, "status_terminal_pure_snapshot")?;
    require(
        reply.metadata["progress"]["events"] == json!([])
            && reply.metadata["progress"]["terminal"] == terminal,
        "STATUS consumed terminal",
    )?;
    let reply = first.call(CANCEL, json!({"reason":"user"}), &[])?;
    expect(&reply, OK, "cancel_terminal_idempotent")?;
    require(
        reply.metadata["progress"]["events"] == json!([])
            && reply.metadata["progress"]["terminal"] == terminal,
        "CANCEL repeated event",
    )?;
    drop(first);
    expect(
        &open_request(&mut second, &reference, 1, false)?,
        OK,
        "busy_request_can_open_after_release",
    )?;
    expect(
        &second.call(CANCEL, json!({"reason":"user"}), &[])?,
        OK,
        "second_request_cancel",
    )?;
    drop(second);

    let reply = management.call(
        CREDENTIAL_PUT,
        put_metadata(&reference, &random_id(), 1, false),
        FAKE_KEY,
    )?;
    expect(&reply, OK, "credential_update_cas")?;
    require(reply.metadata["result"]["version"] == "2", "UPDATE version")?;
    let delete = delete_metadata(&reference, &random_id(), 2);
    let reply = management.call(CREDENTIAL_DELETE, delete.clone(), &[])?;
    expect(&reply, OK, "credential_delete_cas")?;
    require(reply.metadata["result"]["version"] == "3", "DELETE version")?;
    let reply = management.call(CREDENTIAL_QUERY, query_metadata(&reference), &[])?;
    expect(&reply, OK, "credential_query_deleted")?;
    require(
        reply.metadata["result"]["state"] == "deleted",
        "QUERY deleted state",
    )?;
    let reply = management.call(CREDENTIAL_DELETE, delete, &[])?;
    expect(&reply, OK, "delete_receipt_replay")?;
    require(
        reply.metadata["result"]["replayed"] == true && reply.metadata["result"]["version"] == "3",
        "DELETE receipt",
    )?;
    expect(
        &management.call(
            CREDENTIAL_DELETE,
            delete_metadata(&reference, &random_id(), 3),
            &[],
        )?,
        E_CREDENTIAL_REVOKED,
        "retired_ref_rejected",
    )?;
    drop(management);
    emit(
        json!({"check":"test_suite_complete","ok":true,"fake_credential_ref":reference,"namespace":NAMESPACE}),
    );
    Ok(())
}

fn verify_revoked_snapshot(reply: &Frame) -> Result<()> {
    require(
        reply.status == OK
            && reply.metadata["state"] == "FAILED"
            && reply.metadata["progress"]["terminal"]["end_reason"] == "revoked",
        "parallel delete did not revoke snapshot",
    )
}

pub fn hold_request(mid_tls: bool) -> Result<()> {
    let reference = random_id();
    let mut management = Channel::hello("management", false)?;
    expect(
        &management.call(
            CREDENTIAL_PUT,
            put_metadata(&reference, &random_id(), 0, true),
            FAKE_KEY,
        )?,
        OK,
        "hold_fake_put",
    )?;
    let result = (|| {
        let mut channel = Channel::hello("request", false)?;
        expect(
            &open_request(&mut channel, &reference, 1, false)?,
            OK,
            "hold_request_open",
        )?;
        if mid_tls {
            expect(
                &channel.call(BODY_CHUNK, json!({"body_offset":"0"}), b"{}")?,
                OK,
                "hold_upload",
            )?;
            expect(&channel.call(BODY_COMMIT,json!({"body_sha256":format!("{:x}",Sha256::digest(b"{}")),"net_tx_credit":CREDIT,"app_rx_credit":CREDIT}),&[])?,OK,"hold_commit")?;
        }
        emit(
            json!({"check":"hold_ready","ok":true,"phase":if mid_tls {"tls"} else {"upload"},"hold_ms":60000,"credential_is_fake":true}),
        );
        std::thread::sleep(Duration::from_secs(60));
        expect(
            &channel.call(CANCEL, json!({"reason":"shutdown"}), &[])?,
            OK,
            "hold_cancel",
        )?;
        Ok(())
    })();
    expect(
        &management.call(
            CREDENTIAL_DELETE,
            delete_metadata(&reference, &random_id(), 1),
            &[],
        )?,
        OK,
        "hold_cleanup_fake",
    )?;
    result
}

pub fn fault_suite() -> Result<()> {
    let reference = random_id();
    let mut management = Channel::hello("management", true)?;
    expect(
        &management.call(
            CREDENTIAL_PUT,
            put_metadata(&reference, &random_id(), 0, true),
            FAKE_KEY,
        )?,
        OK,
        "fault_fake_put",
    )?;
    let result = (|| {
        for mid_tls in [false, true] {
            let mut channel = Channel::hello("request", false)?;
            expect(
                &open_request(&mut channel, &reference, 1, false)?,
                OK,
                "fault_request_open",
            )?;
            expect(
                &channel.call(BODY_CHUNK, json!({"body_offset":"0"}), b"{}")?,
                OK,
                "fault_upload",
            )?;
            if mid_tls {
                let commit = channel.call(BODY_COMMIT,json!({"body_sha256":format!("{:x}",Sha256::digest(b"{}")),"net_tx_credit":CREDIT,"app_rx_credit":CREDIT}),&[])?;
                expect(&commit, OK, "fault_commit")?;
                require(
                    !commit.payload.is_empty(),
                    "TLS fault did not reach first flight",
                )?;
                expect(
                    &channel.call(FINISH, json!({"reason":"response_consumed"}), &[])?,
                    E_STATE,
                    "fault_finish_before_http_end",
                )?;
                let failed = step(&mut channel, "network_error", 0, &[], Some("read_failed"))?;
                require(
                    failed.status != OK
                        && failed.metadata["state"] == "FAILED"
                        && failed.metadata["error"]["code"] == "E_NETWORK",
                    "network error did not terminate TLS request",
                )?;
                emit(
                    json!({"check":"fault_injected_network_failure","ok":true,"terminal":failed.metadata["progress"]["terminal"]}),
                );
            }
            // Closing GP context without business CANCEL exercises manager's
            // session-close path during upload or the failed TLS generation.
            drop(channel);
            let mut recovery = Channel::hello("request", false)?;
            expect(
                &open_request(&mut recovery, &reference, 1, false)?,
                OK,
                "fault_fresh_request_after_session_close",
            )?;
            expect(
                &recovery.call(CANCEL, json!({"reason":"user"}), &[])?,
                OK,
                "fault_recovery_cancel",
            )?;
        }
        emit(json!({"check":"fault_suite_complete","ok":true,"real_credentials":false}));
        Ok(())
    })();
    expect(
        &management.call(
            CREDENTIAL_DELETE,
            delete_metadata(&reference, &random_id(), 1),
            &[],
        )?,
        OK,
        "fault_cleanup_fake",
    )?;
    result
}

enum ParallelCommand {
    Open(u64),
    Status,
    Upload,
    Cancel,
    Stop,
}
struct ParallelOwners {
    controls: Vec<std::sync::mpsc::Sender<ParallelCommand>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}
impl Drop for ParallelOwners {
    fn drop(&mut self) {
        for control in &self.controls {
            let _ = control.send(ParallelCommand::Stop);
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Fake-credential concurrency test. Every request has its own SDK context and
/// OS thread. A barrier makes the initial REQUEST_OPEN calls race genuinely.
pub fn parallel_suite() -> Result<()> {
    use std::sync::{Arc, Barrier, mpsc};
    let mut management = Channel::hello("management", false)?;
    let count = management.generation_limit;
    require(
        count > 0 && count <= 6 && count + 2 <= management.session_limit,
        "unsupported concurrency/session limits",
    )?;
    let reference = random_id();
    expect(
        &management.call(
            CREDENTIAL_PUT,
            put_metadata(&reference, &random_id(), 0, true),
            FAKE_KEY,
        )?,
        OK,
        "parallel_fake_put",
    )?;
    let run = (|| {
        let start = Arc::new(Barrier::new(count + 1));
        let (ready_tx, ready_rx) = mpsc::channel();
        let (reply_tx, reply_rx) = mpsc::channel();
        let mut owners = ParallelOwners {
            controls: Vec::new(),
            threads: Vec::new(),
        };
        for index in 0..count {
            let (control, commands) = mpsc::channel();
            owners.controls.push(control);
            let ready = ready_tx.clone();
            let replies = reply_tx.clone();
            let reference = reference.clone();
            let start = start.clone();
            owners.threads.push(std::thread::spawn(move || {
                let mut channel = match Channel::hello("request", false) {
                    Ok(channel) => {
                        let _ = ready.send(Ok(()));
                        channel
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let mut first = true;
                while let Ok(command) = commands.recv() {
                    let result = match command {
                        ParallelCommand::Open(version) => {
                            if first {
                                first = false;
                                start.wait();
                            }
                            open_request(&mut channel, &reference, version, false)
                        }
                        ParallelCommand::Status => channel.call(STATUS, json!({}), &[]),
                        ParallelCommand::Upload => {
                            channel.call(BODY_CHUNK, json!({"body_offset":"0"}), b"{}")
                        }
                        ParallelCommand::Cancel => {
                            channel.call(CANCEL, json!({"reason":"user"}), &[])
                        }
                        ParallelCommand::Stop => break,
                    };
                    if replies.send((index, result)).is_err() {
                        break;
                    }
                }
            }));
        }
        drop(ready_tx);
        drop(reply_tx);
        for _ in 0..count {
            ready_rx
                .recv_timeout(Duration::from_secs(35))
                .map_err(|_| "parallel owner startup timeout")??;
        }
        for control in &owners.controls {
            control
                .send(ParallelCommand::Open(1))
                .map_err(|_| "parallel owner disconnected")?;
        }
        start.wait();
        for _ in 0..count {
            let (_, reply) = reply_rx
                .recv_timeout(Duration::from_secs(65))
                .map_err(|_| "parallel open timeout")?;
            expect(&reply?, OK, "parallel_request_admitted")?;
        }
        let mut extra = Channel::hello("request", false)?;
        expect(
            &open_request(&mut extra, &reference, 1, false)?,
            E_BUSY,
            "parallel_over_limit_busy",
        )?;
        expect(
            &management.call(
                CREDENTIAL_PUT,
                put_metadata(&reference, &random_id(), 1, true),
                FAKE_KEY,
            )?,
            OK,
            "parallel_update_keeps_old_snapshots",
        )?;
        for control in &owners.controls {
            control
                .send(ParallelCommand::Upload)
                .map_err(|_| "parallel owner disconnected")?;
        }
        for _ in 0..count {
            let (_, reply) = reply_rx
                .recv_timeout(Duration::from_secs(65))
                .map_err(|_| "parallel upload timeout")?;
            expect(&reply?, OK, "parallel_old_snapshot_upload_after_update")?;
        }
        owners.controls[0]
            .send(ParallelCommand::Cancel)
            .map_err(|_| "parallel owner disconnected")?;
        expect(
            &reply_rx
                .recv_timeout(Duration::from_secs(65))
                .map_err(|_| "parallel cancel timeout")?
                .1?,
            OK,
            "parallel_cancel_one",
        )?;
        for control in owners.controls.iter().skip(1) {
            control
                .send(ParallelCommand::Status)
                .map_err(|_| "parallel owner disconnected")?;
        }
        for _ in 1..count {
            let (_, reply) = reply_rx
                .recv_timeout(Duration::from_secs(65))
                .map_err(|_| "parallel status timeout")?;
            let reply = reply?;
            expect(&reply, OK, "parallel_other_request_survives_cancel")?;
            require(
                reply.metadata["state"] == "UPLOADING"
                    && reply.metadata["progress"]["uploaded_body"] == "2",
                "parallel cancellation affected another request",
            )?;
        }
        expect(
            &open_request(&mut extra, &reference, 2, false)?,
            OK,
            "parallel_reuse_cancelled_slot_v2",
        )?;
        let deleted = management.call(
            CREDENTIAL_DELETE,
            delete_metadata(&reference, &random_id(), 2),
            &[],
        )?;
        expect(&deleted, OK, "parallel_delete_revokes_all_snapshots")?;
        let deleted_version = parse_counter(&deleted.metadata["result"]["version"])?;
        for control in owners.controls.iter().skip(1) {
            control
                .send(ParallelCommand::Status)
                .map_err(|_| "parallel owner disconnected")?;
        }
        for _ in 1..count {
            let (_, reply) = reply_rx
                .recv_timeout(Duration::from_secs(65))
                .map_err(|_| "parallel revoked status timeout")?;
            let reply = reply?;
            expect(&reply, OK, "parallel_old_snapshot_revocation_status")?;
            verify_revoked_snapshot(&reply)?;
        }
        let revoked = extra.call(STATUS, json!({}), &[])?;
        verify_revoked_snapshot(&revoked)?;
        drop(extra);
        drop(owners);
        let mut after = Channel::hello("request", false)?;
        expect(
            &open_request(&mut after, &reference, 2, false)?,
            E_VERSION_CONFLICT,
            "parallel_deleted_stale_version_conflict",
        )?;
        expect(
            &open_request(&mut after, &reference, deleted_version, false)?,
            E_CREDENTIAL_REVOKED,
            "parallel_deleted_future_open_rejected",
        )?;
        emit(
            json!({"check":"parallel_suite_complete","ok":true,"isolated_sdk_contexts":count,"simultaneous_open_barrier":true,"max_concurrent_requests":count,"real_credentials":false}),
        );
        Ok(())
    })();
    // Cleanup fake credentials after any failure, using QUERY to reconcile CAS.
    let query = management.call(CREDENTIAL_QUERY, query_metadata(&reference), &[])?;
    if query.metadata["result"]["state"] == "live" {
        let version = parse_counter(&query.metadata["result"]["version"])?;
        expect(
            &management.call(
                CREDENTIAL_DELETE,
                delete_metadata(&reference, &random_id(), version),
                &[],
            )?,
            OK,
            "parallel_cleanup_fake_credential",
        )?;
    }
    run
}

#[derive(Default)]
struct RelayChecks {
    next_event: u64,
    net: u64,
    body: u64,
    accepted: u64,
    head: Option<u64>,
    end: bool,
    hash: Sha256,
    collected: Vec<u8>,
    content_type: Option<String>,
    max_body: usize,
    streaming: bool,
    started: Option<Instant>,
    head_us: Option<u64>,
    body_us: Option<u64>,
}
impl RelayChecks {
    #[cfg(test)]
    fn consume(&mut self, reply: &Frame, socket: &mut impl Write) -> Result<()> {
        self.consume_with_sink(reply, socket, &mut None)
    }

    fn consume_with_sink(
        &mut self,
        reply: &Frame,
        socket: &mut impl Write,
        sink: &mut Option<&mut dyn HttpSink>,
    ) -> Result<()> {
        require(reply.status == OK, "relay business failure")?;
        let progress = &reply.metadata["progress"];
        let events = progress["events"]
            .as_array()
            .ok_or("relay events missing")?;
        require(events.len() <= 8, "too many events")?;
        let mut cursor = 0;
        for event in events {
            let sequence = parse_counter(&event["event_seq"])?;
            require(
                sequence == self.next_event + 1,
                "event sequence discontinuity",
            )?;
            self.next_event = sequence;
            let offset = event["offset"].as_u64().ok_or("event offset")? as usize;
            let length = event["length"].as_u64().ok_or("event length")? as usize;
            require(
                offset == cursor && length <= reply.payload.len().saturating_sub(offset),
                "event slice coverage",
            )?;
            let bytes = &reply.payload[offset..offset + length];
            cursor += length;
            match event["kind"].as_str().ok_or("event kind")? {
                "NET_TX" => {
                    require(
                        length > 0
                            && parse_counter(&event["stream_offset"])? == self.net
                            && event["may_contain_request"].is_boolean(),
                        "NET_TX descriptor",
                    )?;
                    socket
                        .write_all(bytes)
                        .map_err(|_| "upstream write_failed")?;
                    self.net += length as u64;
                }
                "HTTP_HEAD" => {
                    require(
                        self.head.is_none() && self.body == 0 && !self.end,
                        "HTTP_HEAD ordering",
                    )?;
                    let head: Value =
                        serde_json::from_slice(bytes).map_err(|_| "HTTP_HEAD JSON")?;
                    let status = head["status"].as_u64().ok_or("HTTP status")?;
                    require(
                        (100..=599).contains(&status) && head["headers"].is_array(),
                        "HTTP_HEAD fields",
                    )?;
                    self.content_type = head["headers"]
                        .as_array()
                        .and_then(|headers| {
                            headers.iter().find(|header| {
                                header["name"]
                                    .as_str()
                                    .is_some_and(|name| name.eq_ignore_ascii_case("content-type"))
                            })
                        })
                        .and_then(|header| header["value"].as_str())
                        .map(str::to_owned);
                    self.head = Some(status);
                    self.head_us = self.started.map(elapsed_us);
                    if let Some(sink) = sink.as_deref_mut() {
                        sink.event(HTTP_HEAD_EVENT, bytes)?;
                    }
                    emit(json!({"check":"models_http_head","http_status":status,"ok":true}));
                }
                "HTTP_BODY" => {
                    require(
                        length > 0
                            && self.head.is_some()
                            && !self.end
                            && parse_counter(&event["stream_offset"])? == self.body,
                        "HTTP_BODY ordering/offset",
                    )?;
                    require(
                        self.body as usize + bytes.len()
                            <= if self.max_body == 0 {
                                1024 * 1024
                            } else {
                                self.max_body
                            },
                        "bounded response body limit",
                    )?;
                    if self.body_us.is_none() {
                        self.body_us = self.started.map(elapsed_us);
                    }
                    if let Some(sink) = sink.as_deref_mut() {
                        sink.event(HTTP_BODY_EVENT, bytes)?;
                    }
                    if !self.streaming {
                        self.collected.extend_from_slice(bytes);
                    }
                    self.hash.update(bytes);
                    self.body += length as u64;
                }
                "HTTP_END" => {
                    require(
                        length == 0
                            && self.head.is_some()
                            && !self.end
                            && event["details"]["framing"] == "complete"
                            && parse_counter(&event["details"]["body_bytes"])? == self.body,
                        "HTTP_END ordering/framing",
                    )?;
                    self.end = true;
                }
                "REQUEST_END" => return Err("request terminated before HTTP delivery".into()),
                _ => return Err("unknown relay event".into()),
            }
        }
        require(
            cursor == reply.payload.len(),
            "event payload not completely covered",
        )?;
        require(
            parse_counter(&progress["emitted_tls_tx"])? == self.net
                && parse_counter(&progress["emitted_http_body"])? == self.body
                && parse_counter(&progress["accepted_tls_rx"])? == self.accepted,
            "relay cumulative counter association",
        )?;
        Ok(())
    }
}
fn parse_counter(value: &Value) -> Result<u64> {
    let text = value.as_str().ok_or("counter must be decimal string")?;
    require(
        !text.is_empty()
            && text.bytes().all(|byte| byte.is_ascii_digit())
            && (text == "0" || !text.starts_with('0')),
        "noncanonical counter",
    )?;
    text.parse().map_err(|_| "counter overflow".into())
}
fn step(
    channel: &mut Channel,
    kind: &str,
    offset: u64,
    input: &[u8],
    network_code: Option<&str>,
) -> Result<Frame> {
    let mut metadata = json!({"input_kind":kind,"tls_rx_offset":offset.to_string(),"net_tx_credit":CREDIT,"app_rx_credit":CREDIT});
    if let Some(code) = network_code {
        metadata["network_error_code"] = json!(code);
    }
    channel.call(STEP, metadata, input)
}
fn budget_remaining(
    deadline: Instant,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Duration> {
    if cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire)) {
        return Err("raw request cancelled".into());
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or("raw request overall deadline".into())
}

fn enforce_budget(
    channel: &mut Channel,
    deadline: Instant,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Duration> {
    match budget_remaining(deadline, cancel) {
        Ok(remaining) => Ok(remaining),
        Err(error) => {
            let reason = if error.contains("cancelled") {
                "user"
            } else {
                "timeout"
            };
            let _ = channel.call(CANCEL, json!({"reason":reason}), &[]);
            Err(error)
        }
    }
}

fn upstream(
    host: &str,
    port: u16,
    ip: Option<IpAddr>,
    deadline: Instant,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<TcpStream> {
    budget_remaining(deadline, cancel)?;
    let addresses = if let Some(ip) = ip {
        vec![SocketAddr::new(ip, port)]
    } else {
        // libc DNS can block beyond the logical budget. No additional network
        // action or successful completion is admitted after it returns late.
        (host, port)
            .to_socket_addrs()
            .map_err(|_| "upstream dns_failed")?
            .collect::<Vec<_>>()
    };
    for address in addresses.into_iter().take(4) {
        let timeout = budget_remaining(deadline, cancel)?.min(Duration::from_secs(5));
        if let Ok(socket) = TcpStream::connect_timeout(&address, timeout) {
            socket.set_nodelay(true).map_err(|_| "set TCP_NODELAY")?;
            let remaining = budget_remaining(deadline, cancel)?;
            socket
                .set_read_timeout(Some(remaining.min(Duration::from_millis(200))))
                .map_err(|_| "set read timeout")?;
            socket
                .set_write_timeout(Some(remaining.min(Duration::from_secs(2))))
                .map_err(|_| "set write timeout")?;
            return Ok(socket);
        }
    }
    budget_remaining(deadline, cancel)?;
    Err("upstream connect_failed".into())
}

fn connect_target(target: &Value) -> Result<(String, u16)> {
    let host = target["host"]
        .as_str()
        .ok_or("upstream target host missing")?;
    let port = target["port"]
        .as_u64()
        .filter(|port| (1..=65535).contains(port))
        .ok_or("upstream target port invalid")? as u16;
    let dns_host = host.strip_suffix('.').unwrap_or(host);
    let valid_host = host.parse::<IpAddr>().is_ok()
        || !dns_host.is_empty()
            && host.len() <= 253
            && dns_host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            });
    require(
        valid_host && target["sni"] == host && target["alpn"] == "http/1.1",
        "upstream target mismatch",
    )?;
    Ok((host.to_owned(), port))
}

pub fn models(upstream_ip: Option<IpAddr>) -> Result<()> {
    let reference = random_id();
    let mut management = Channel::hello("management", false)?;
    let reply = management.call(
        CREDENTIAL_PUT,
        put_metadata(&reference, &random_id(), 0, true),
        FAKE_KEY,
    )?;
    expect(&reply, OK, "models_temporary_fake_credential")?;
    let result = models_request(&reference, upstream_ip);
    let deleted = management.call(
        CREDENTIAL_DELETE,
        delete_metadata(&reference, &random_id(), 1),
        &[],
    )?;
    expect(&deleted, OK, "models_delete_fake_credential")?;
    result
}
fn models_request(reference: &str, upstream_ip: Option<IpAddr>) -> Result<()> {
    let config = RawConfig {
        namespace: NAMESPACE.into(),
        profile_id: default_profile(),
        model_id: None,
        credential_ref: reference.into(),
        expected_version: 1,
        operation: "MODELS".into(),
        response_mode: "json".into(),
        overall_timeout_ms: 60000,
        max_response_bytes: 1024 * 1024,
        network_chunk_size: INPUT_CHUNK,
        upstream_ip: upstream_ip.map(|ip| ip.to_string()),
        headers: Vec::new(),
    };
    let mut channel = Channel::hello("request", false)?;
    let response = request(&mut channel, &config, &[], None)?;
    require(
        response.status == 401,
        "fake credential did not return expected HTTP 401",
    )?;
    emit(
        json!({"check":"models_expected_authentication_rejection","ok":true,"http_status":401,
        "emitted_http_body":response.body.len().to_string(),"body_sha256":format!("{:x}",Sha256::digest(&response.body)),
        "transport":response.transport,"generation_success":false}),
    );
    Ok(())
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    pub namespace: String,
    #[serde(default = "default_profile")]
    pub profile_id: String,
    #[serde(default)]
    pub model_id: Option<String>,
    pub credential_ref: String,
    pub expected_version: u64,
    pub operation: String,
    pub response_mode: String,
    pub overall_timeout_ms: u32,
    pub max_response_bytes: u32,
    #[serde(default = "default_network_chunk")]
    pub network_chunk_size: usize,
    pub upstream_ip: Option<String>,
    #[serde(default)]
    pub headers: Vec<secret_teeproxy_ta::relay::Header>,
}
fn default_network_chunk() -> usize {
    INPUT_CHUNK
}

fn default_profile() -> String {
    PROFILE.into()
}

pub const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;

pub struct RawResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub body_length: u64,
    pub transport: Value,
    pub ca_metrics: Value,
}
impl RawResponse {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let metadata=serde_json::to_vec(&json!({"status":self.status,"content_type":self.content_type,"transport":self.transport,"body_length":self.body_length,"ca_metrics":self.ca_metrics})).map_err(|_|"raw response encoding")?;
        let mut output = (metadata.len() as u32).to_le_bytes().to_vec();
        output.extend_from_slice(&metadata);
        output.extend_from_slice(&self.body);
        Ok(output)
    }
}

pub const HTTP_HEAD_EVENT: u32 = 1;
pub const HTTP_BODY_EVENT: u32 = 2;

/// Synchronous delivery applies backpressure before the next TA STEP/read.
/// Returning an error cancels the request and prevents successful completion.
pub trait HttpSink {
    fn event(&mut self, kind: u32, bytes: &[u8]) -> Result<()>;
}

#[derive(Default, serde::Serialize)]
struct CallTiming {
    count: u64,
    total_us: u64,
    max_us: u64,
}

type CallTimings = std::collections::BTreeMap<String, CallTiming>;

fn measured_call(
    channel: &mut Channel,
    timings: &mut CallTimings,
    opcode: u16,
    metadata: Value,
    payload: &[u8],
) -> Result<Frame> {
    let started = Instant::now();
    let result = channel.call(opcode, metadata, payload);
    let timing = timings.entry(format!("{opcode:04x}")).or_default();
    let duration = elapsed_us(started);
    timing.count += 1;
    timing.total_us += duration;
    timing.max_us = timing.max_us.max(duration);
    result
}

fn measured_step(
    channel: &mut Channel,
    timings: &mut CallTimings,
    kind: &str,
    offset: u64,
    payload: &[u8],
) -> Result<Frame> {
    measured_call(
        channel,
        timings,
        STEP,
        json!({"input_kind":kind,"tls_rx_offset":offset.to_string(),"net_tx_credit":CREDIT,"app_rx_credit":CREDIT}),
        payload,
    )
}

/// Shared complete GP/TLS/TCP pump used by the CLI and in-process APK owner.
pub fn request(
    channel: &mut Channel,
    config: &RawConfig,
    body: &[u8],
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<RawResponse> {
    request_with_sink(channel, config, body, cancel, None)
}

/// Incremental HTTP delivery. Only aggregate mode retains the response body.
pub fn request_with_sink(
    channel: &mut Channel,
    config: &RawConfig,
    body: &[u8],
    cancel: Option<&std::sync::atomic::AtomicBool>,
    sink: Option<&mut dyn HttpSink>,
) -> Result<RawResponse> {
    request_with_hooks(channel, config, body, cancel, sink, None)
}

pub fn request_with_hooks(
    channel: &mut Channel,
    config: &RawConfig,
    body: &[u8],
    cancel: Option<&std::sync::atomic::AtomicBool>,
    mut sink: Option<&mut dyn HttpSink>,
    mut opened_hook: Option<&mut dyn FnMut() -> Result<()>>,
) -> Result<RawResponse> {
    let streaming = sink.is_some();
    let mut phase_calls = std::collections::BTreeMap::new();
    let started = Instant::now();
    require(
        (1..=16384).contains(&config.network_chunk_size),
        "network chunk size bounds",
    )?;
    require(
        body.len() <= MAX_REQUEST_BYTES
            && config.max_response_bytes > 0
            && config.max_response_bytes as usize <= MAX_AGGREGATE_BYTES,
        "raw request/response bounds",
    )?;
    require(
        matches!(
            config.operation.as_str(),
            "CHAT" | "RESPONSES" | "MESSAGES" | "GENERATE" | "OLLAMA_CHAT" | "MODELS"
        ) && (config.operation != "MODELS" || body.is_empty()),
        "raw operation/body",
    )?;
    let upstream_ip = config
        .upstream_ip
        .as_deref()
        .map(str::parse::<IpAddr>)
        .transpose()
        .map_err(|_| "invalid upstream IP")?;
    channel.request_id = *Uuid::new_v4().as_bytes();
    require(
        (1..=600000).contains(&config.overall_timeout_ms),
        "raw request timeout bounds",
    )?;
    let deadline = started + Duration::from_millis(config.overall_timeout_ms as u64);
    budget_remaining(deadline, cancel)?;
    let mut metadata = json!({"namespace":config.namespace,"profile_id":config.profile_id,"credential_ref":config.credential_ref,
        "expected_version":config.expected_version.to_string(),"operation":config.operation,"body_length":body.len().to_string(),
        "overall_timeout_ms":config.overall_timeout_ms,"response_mode":config.response_mode,"completion_policy":"HTTP_COMPLETE","headers":config.headers});
    if let Some(model) = &config.model_id {
        metadata["model_id"] = json!(model);
    }
    let opened = measured_call(channel, &mut phase_calls, REQUEST_OPEN, metadata, &[])?;
    expect(&opened, OK, "raw_request_open")?;
    enforce_budget(channel, deadline, cancel)?;
    if let Some(hook) = opened_hook.as_mut() {
        if let Err(error) = hook() {
            let _ = channel.call(CANCEL, json!({"reason":"shutdown"}), &[]);
            return Err(error);
        }
    }
    let upload_chunk_size = channel.upload_chunk_size;
    for (offset, chunk) in upload_chunks(body, upload_chunk_size) {
        enforce_budget(channel, deadline, cancel)?;
        let uploaded = measured_call(
            channel,
            &mut phase_calls,
            BODY_CHUNK,
            json!({"body_offset":offset.to_string()}),
            chunk,
        )?;
        expect(&uploaded, OK, "raw_body_chunk")?;
        require(
            uploaded.metadata["progress"]["accepted_input_bytes"] == chunk.len(),
            "raw upload ownership",
        )?;
    }
    enforce_budget(channel, deadline, cancel)?;
    let mut reply=measured_call(channel, &mut phase_calls, BODY_COMMIT,json!({"body_sha256":format!("{:x}",Sha256::digest(body)),"net_tx_credit":CREDIT,"app_rx_credit":CREDIT}),&[])?;
    expect(&reply, OK, "raw_commit")?;
    let target = &reply.metadata["progress"]["connect_target"];
    let (host, port) = connect_target(target)?;
    enforce_budget(channel, deadline, cancel)?;
    let mut socket = match upstream(&host, port, upstream_ip, deadline, cancel) {
        Ok(socket) => socket,
        Err(error) => {
            enforce_budget(channel, deadline, cancel)?;
            let code = if error.contains("dns_failed") {
                "dns_failed"
            } else {
                "connect_failed"
            };
            let terminal = step(channel, "network_error", 0, &[], Some(code))?;
            emit(
                json!({"check":"models_network_failure","status":terminal.status,"error":code,"terminal":terminal.metadata["progress"]["terminal"]}),
            );
            return Err(error);
        }
    };
    let mut checks = RelayChecks {
        max_body: config.max_response_bytes as usize,
        streaming,
        started: Some(started),
        ..Default::default()
    };
    let mut pending = Vec::new();
    let mut eof = false;
    let mut stalls = 0;
    loop {
        let remaining = enforce_budget(channel, deadline, cancel)?;
        socket
            .set_write_timeout(Some(remaining.min(Duration::from_secs(2))))
            .map_err(|_| "set write timeout")?;
        if reply.status != OK {
            emit(
                json!({"check":"models_ta_failure","status":reply.status,"error":reply.metadata["error"],"terminal":reply.metadata["progress"]["terminal"]}),
            );
            return Err("models relay failed".into());
        }
        let previous_event = checks.next_event;
        if let Err(error) = checks.consume_with_sink(&reply, &mut socket, &mut sink) {
            if error == "upstream write_failed" {
                let _terminal = step(
                    channel,
                    "network_error",
                    checks.accepted,
                    &[],
                    Some("write_failed"),
                )?;
            } else {
                let reason = if error.contains("deadline") {
                    "timeout"
                } else if error.contains("cancelled") {
                    "user"
                } else {
                    "shutdown"
                };
                let _terminal = channel.call(CANCEL, json!({"reason":reason}), &[])?;
            }
            return Err(error);
        }
        // Draining real output is progress, including multi-MiB request uploads.
        if checks.next_event != previous_event {
            stalls = 0;
        }
        enforce_budget(channel, deadline, cancel)?;
        if checks.end {
            let finish = measured_call(channel, &mut phase_calls, FINISH, json!({"reason":"response_consumed"}), &[])?;
            expect(&finish, OK, "models_finish_response_consumed")?;
            no_data(&finish)?;
            require(
                finish.metadata["state"] == "ENDED"
                    && finish.metadata["progress"]["terminal"]["http_framing"] == "complete",
                "models terminal snapshot",
            )?;
            budget_remaining(deadline, cancel)?;
            return Ok(RawResponse {
                status: checks.head.ok_or("HTTP status missing")? as u16,
                content_type: checks.content_type,
                body: checks.collected,
                body_length: checks.body,
                transport: finish.metadata["progress"]["terminal"].clone(),
                ca_metrics: json!({"sdk":channel.teec.metrics,"calls_by_opcode":phase_calls,"request_total_us":elapsed_us(started),"http_head_us":checks.head_us,
                    "first_body_us":checks.body_us,"http_body_bytes":checks.body,"tls_tx_bytes":checks.net,"tls_rx_bytes":checks.accepted}),
            });
        }
        let progress = &reply.metadata["progress"];
        if progress["net_tx_pending"] == true
            || progress["http_body_pending"] == true
            || progress["need_step"] == true && pending.is_empty()
        {
            reply = measured_step(channel, &mut phase_calls, "none", checks.accepted, &[])?;
            stalls += 1;
            if stalls > 1000 {
                let _ = channel.call(CANCEL, json!({"reason":"shutdown"}), &[]);
                return Err("relay pump stalled".into());
            }
            continue;
        }
        if pending.is_empty() && !eof {
            let credit = progress["rx_credit"]
                .as_u64()
                .ok_or("rx_credit missing")?
                .min(INPUT_CHUNK as u64)
                .min(config.network_chunk_size as u64) as usize;
            if credit > 0 {
                let remaining = enforce_budget(channel, deadline, cancel)?;
                socket
                    .set_read_timeout(Some(remaining.min(Duration::from_millis(200))))
                    .map_err(|_| "set read timeout")?;
                let mut buffer = vec![0; credit];
                match socket.read(&mut buffer) {
                    Ok(0) => {
                        eof = true;
                        reply = measured_step(channel, &mut phase_calls, "tcp_eof", checks.accepted, &[])?;
                        continue;
                    }
                    Ok(count) => {
                        buffer.truncate(count);
                        pending = buffer;
                        stalls = 0;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => {
                        let _ = step(
                            channel,
                            "network_error",
                            checks.accepted,
                            &[],
                            Some("read_failed"),
                        )?;
                        return Err("upstream read_failed".into());
                    }
                }
            }
        }
        if pending.is_empty() {
            reply = measured_step(channel, &mut phase_calls, "none", checks.accepted, &[])?;
        } else {
            reply = measured_step(channel, &mut phase_calls, "tls_rx", checks.accepted, &pending)?;
            let accepted = reply.metadata["progress"]["accepted_input_bytes"]
                .as_u64()
                .ok_or("accepted_input_bytes missing")? as usize;
            require(
                accepted == 0 || accepted == pending.len(),
                "partial TLS input acceptance",
            )?;
            if accepted == pending.len() {
                checks.accepted += accepted as u64;
                pending.clear();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_input_frames_preserve_negotiated_bounds() {
        let payload = vec![0x5a; INPUT_CHUNK];
        for (opcode, mut metadata) in [
            (BODY_CHUNK, json!({"body_offset":u64::MAX.to_string()})),
            (STEP, json!({"input_kind":"tls_rx","tls_rx_offset":u64::MAX.to_string(),"net_tx_credit":CREDIT,"app_rx_credit":CREDIT})),
        ] {
            metadata["ta_epoch"] = json!("f".repeat(32));
            metadata["session_nonce"] = json!("e".repeat(32));
            let frame = Frame {
                opcode,
                request_id: [1; 16],
                call_seq: 1,
                status: 0,
                metadata,
                payload: payload.clone(),
            };
            let encoded = encode_request(&frame).unwrap();
            assert!(encoded.len() <= INPUT_FRAME_MAX);
            assert_eq!(Frame::decode_request(&encoded).unwrap().payload, payload);
        }
        let config: RawConfig = serde_json::from_value(json!({
            "namespace":"public-test","credential_ref":"f".repeat(32),
            "expected_version":1,"operation":"CHAT","response_mode":"sse",
            "overall_timeout_ms":60000,"max_response_bytes":1048576,
            "upstream_ip":null
        })).unwrap();
        assert_eq!(config.network_chunk_size, INPUT_CHUNK);
        assert!((1..=16384).contains(&config.network_chunk_size));
        assert!(CREDIT <= 65536);
    }

    fn delivery_frame(sequence: u64, kind: &str, bytes: &[u8], offset: u64) -> Frame {
        let body = if kind == "HTTP_BODY" {
            offset + bytes.len() as u64
        } else {
            offset
        };
        Frame {
            opcode: STEP,
            request_id: [1; 16],
            call_seq: sequence,
            status: OK,
            payload: bytes.to_vec(),
            metadata: json!({"progress":{
                "emitted_tls_tx":"0", "accepted_tls_rx":"0", "emitted_http_body":body.to_string(),
                "events":[{"event_seq":sequence.to_string(),"kind":kind,"offset":0,"length":bytes.len(),
                    "stream_offset":offset.to_string(),"details":{"framing":"complete","body_bytes":body.to_string()}}]}}),
        }
    }
    struct RecordingSink {
        bytes: usize,
        hash: Sha256,
        heads: usize,
        reject: bool,
    }
    impl HttpSink for RecordingSink {
        fn event(&mut self, kind: u32, bytes: &[u8]) -> Result<()> {
            if self.reject {
                return Err("listener failed".into());
            }
            match kind {
                HTTP_HEAD_EVENT => self.heads += 1,
                HTTP_BODY_EVENT => {
                    self.bytes += bytes.len();
                    self.hash.update(bytes);
                }
                _ => panic!("unknown callback kind"),
            }
            Ok(())
        }
    }
    fn recording_sink() -> RecordingSink {
        RecordingSink {
            bytes: 0,
            hash: Sha256::new(),
            heads: 0,
            reject: false,
        }
    }

    #[test]
    fn incremental_large_sse_is_byte_exact_without_body_retention() {
        let mut checks = RelayChecks {
            streaming: true,
            max_body: 64 * 1024 * 1024,
            ..Default::default()
        };
        let mut recorder = recording_sink();
        let mut sink: Option<&mut dyn HttpSink> = Some(&mut recorder);
        let head = serde_json::to_vec(
            &json!({"status":200,"headers":[{"name":"Content-Type","value":"text/event-stream"}]}),
        )
        .unwrap();
        checks
            .consume_with_sink(
                &delivery_frame(1, "HTTP_HEAD", &head, 0),
                &mut Vec::new(),
                &mut sink,
            )
            .unwrap();
        // Deliberately splits UTF-8 and SSE events across callback boundaries.
        let source = "data: {\"delta\":\"你好\"}\n\ndata: [DONE]\n\n"
            .as_bytes()
            .repeat(100_000);
        let mut sequence = 2;
        for chunk in source.chunks(8191) {
            let frame = delivery_frame(sequence, "HTTP_BODY", chunk, checks.body);
            checks
                .consume_with_sink(&frame, &mut Vec::new(), &mut sink)
                .unwrap();
            assert!(
                checks.collected.is_empty(),
                "streaming retained response body"
            );
            sequence += 1;
        }
        checks
            .consume_with_sink(
                &delivery_frame(sequence, "HTTP_END", &[], checks.body),
                &mut Vec::new(),
                &mut sink,
            )
            .unwrap();
        assert!(checks.end);
        assert_eq!(checks.body, source.len() as u64);
        assert_eq!(checks.content_type.as_deref(), Some("text/event-stream"));
        assert_eq!(recorder.bytes, source.len());
        assert_eq!(recorder.heads, 1);
        assert_eq!(recorder.hash.finalize(), Sha256::digest(&source));
    }

    #[test]
    fn stream_total_limit_and_listener_failure_prevent_completion() {
        for reject in [false, true] {
            let mut checks = RelayChecks {
                streaming: true,
                max_body: 3,
                ..Default::default()
            };
            let mut recorder = recording_sink();
            let mut sink: Option<&mut dyn HttpSink> = Some(&mut recorder);
            let head = serde_json::to_vec(&json!({"status":200,"headers":[]})).unwrap();
            checks
                .consume_with_sink(
                    &delivery_frame(1, "HTTP_HEAD", &head, 0),
                    &mut Vec::new(),
                    &mut sink,
                )
                .unwrap();
            drop(sink);
            recorder.reject = reject;
            let mut sink: Option<&mut dyn HttpSink> = Some(&mut recorder);
            let error = checks
                .consume_with_sink(
                    &delivery_frame(2, "HTTP_BODY", if reject { b"abc" } else { b"abcd" }, 0),
                    &mut Vec::new(),
                    &mut sink,
                )
                .unwrap_err();
            assert!(error.contains(if reject {
                "listener failed"
            } else {
                "body limit"
            }));
            assert!(!checks.end);
            assert_eq!(checks.body, 0);
            assert!(checks.collected.is_empty());
        }
    }

    #[test]
    fn aggregate_bytes_and_encoded_metadata_preserve_original_payload() {
        let mut checks = RelayChecks::default();
        let head = serde_json::to_vec(&json!({"status":201,"headers":[]})).unwrap();
        checks
            .consume(&delivery_frame(1, "HTTP_HEAD", &head, 0), &mut Vec::new())
            .unwrap();
        for (sequence, bytes) in [b"data: ".as_slice(), b"\xff\x00\r\n\r\n".as_slice()]
            .iter()
            .enumerate()
        {
            checks
                .consume(
                    &delivery_frame(sequence as u64 + 2, "HTTP_BODY", bytes, checks.body),
                    &mut Vec::new(),
                )
                .unwrap();
        }
        assert_eq!(checks.collected, b"data: \xff\x00\r\n\r\n");
        let response = RawResponse {
            status: 201,
            content_type: None,
            body: checks.collected.clone(),
            body_length: checks.body,
            transport: json!({}),
            ca_metrics: json!({}),
        };
        let encoded = response.encode().unwrap();
        let length = u32::from_le_bytes(encoded[..4].try_into().unwrap()) as usize;
        assert_eq!(&encoded[4 + length..], checks.collected);
        let metadata: Value = serde_json::from_slice(&encoded[4..4 + length]).unwrap();
        assert_eq!(metadata["body_length"], checks.body);
    }

    #[test]
    fn deleted_reference_open_observes_cas_priority_and_fresh_sequence() {
        use secret_teeproxy_ta::{
            app::{App, Session, StoreClient},
            store::Persistence,
        };
        use std::sync::{Arc, Mutex};
        struct Memory(Option<Vec<u8>>);
        impl Persistence for Memory {
            fn load(&mut self) -> std::result::Result<Option<Vec<u8>>, String> {
                Ok(self.0.clone())
            }
            fn commit(&mut self, bytes: &[u8]) -> std::result::Result<(), String> {
                self.0 = Some(bytes.to_vec());
                Ok(())
            }
        }
        fn call(
            app: &App,
            session: &Arc<Mutex<Session>>,
            last: &mut Option<Frame>,
            opcode: u16,
            request_id: [u8; 16],
            mut metadata: Value,
            payload: &[u8],
        ) -> Frame {
            let seq = last.as_ref().map_or(1, |frame| frame.call_seq + 1);
            if let Some(previous) = last.as_ref() {
                metadata["ta_epoch"] = previous.metadata["ta_epoch"].clone();
                metadata["session_nonce"] = previous.metadata["session_nonce"].clone();
            }
            let frame = Frame {
                opcode,
                request_id,
                call_seq: seq,
                status: 0,
                metadata,
                payload: payload.to_vec(),
            };
            let request = encode_request(&frame).unwrap();
            let bytes = app
                .exchange(&request, &mut session.lock().unwrap())
                .unwrap();
            let status = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
            let reply = decode_reply(&bytes, &request, status).unwrap();
            *last = Some(reply.clone());
            reply
        }
        let store = StoreClient::start(|| Ok((Memory(None), [1; 16])), true).unwrap();
        let app = App::new(store);
        let management = app.open_session().unwrap();
        let mut previous = None;
        call(
            &app,
            &management,
            &mut previous,
            HELLO,
            [0; 16],
            json!({"role":"management","supported_versions":[{"major":1,"minor":0}]}),
            &[],
        );
        let reference = random_id();
        assert_eq!(
            call(
                &app,
                &management,
                &mut previous,
                CREDENTIAL_PUT,
                [0; 16],
                put_metadata(&reference, &random_id(), 0, false),
                FAKE_KEY
            )
            .status,
            OK
        );
        assert_eq!(
            call(
                &app,
                &management,
                &mut previous,
                CREDENTIAL_PUT,
                [0; 16],
                put_metadata(&reference, &random_id(), 1, false),
                FAKE_KEY
            )
            .status,
            OK
        );
        let deleted = call(
            &app,
            &management,
            &mut previous,
            CREDENTIAL_DELETE,
            [0; 16],
            delete_metadata(&reference, &random_id(), 2),
            &[],
        );
        let deleted_version = parse_counter(&deleted.metadata["result"]["version"]).unwrap();
        assert_eq!(deleted_version, 3);
        let request = app.open_session().unwrap();
        let mut previous = None;
        call(
            &app,
            &request,
            &mut previous,
            HELLO,
            [0; 16],
            json!({"role":"request","supported_versions":[{"major":1,"minor":0}]}),
            &[],
        );
        let stale = call(
            &app,
            &request,
            &mut previous,
            REQUEST_OPEN,
            [3; 16],
            open_metadata(&reference, 2, false),
            &[],
        );
        assert_eq!(stale.status, E_VERSION_CONFLICT);
        assert_eq!(stale.metadata["next_call_seq"], "3");
        let revoked = call(
            &app,
            &request,
            &mut previous,
            REQUEST_OPEN,
            [3; 16],
            open_metadata(&reference, deleted_version, false),
            &[],
        );
        assert_eq!(revoked.status, E_CREDENTIAL_REVOKED);
        assert_eq!(revoked.call_seq, 3);
        assert_eq!(revoked.metadata["next_call_seq"], "4");
        app.close_session(&mut request.lock().unwrap());
        app.close_session(&mut management.lock().unwrap());
    }

    #[test]
    fn deleted_upload_snapshot_uses_revoked_end_reason_without_error_field() {
        let mut reply = delivery_frame(1, "HTTP_END", &[], 0);
        reply.metadata["state"] = json!("FAILED");
        reply.metadata["progress"]["terminal"] =
            json!({"end_reason":"revoked","http_framing":"not_started","app_resources":"released"});
        assert!(verify_revoked_snapshot(&reply).is_ok());
        reply.metadata["state"] = json!("UPLOADING");
        assert!(verify_revoked_snapshot(&reply).is_err());
        reply.metadata["state"] = json!("FAILED");
        reply.metadata["progress"]["terminal"]["end_reason"] = json!("cancelled");
        assert!(verify_revoked_snapshot(&reply).is_err());
    }

    #[test]
    fn setup_and_connect_use_one_immutable_deadline() {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(200);
        let remaining = budget_remaining(deadline, None).unwrap();
        assert!(remaining <= Duration::from_millis(200));
        // Model setup/upload having already consumed the entire budget. A late
        // connect is rejected before DNS/socket work, including an IP override.
        let expired = start - Duration::from_nanos(1);
        assert!(
            upstream(
                "api.example.com",
                443,
                Some("127.0.0.1".parse().unwrap()),
                expired,
                None
            )
            .unwrap_err()
            .contains("deadline")
        );
        let cancelled = std::sync::atomic::AtomicBool::new(true);
        assert!(
            upstream("api.example.com", 443, None, deadline, Some(&cancelled))
                .unwrap_err()
                .contains("cancelled")
        );
        assert!(budget_remaining(expired, None).is_err());
    }

    #[test]
    fn upstream_target_accepts_ta_profiles_and_rejects_ambiguous_endpoints() {
        assert_eq!(connect_target(&json!({"host":"api.example.com","port":8443,"sni":"api.example.com","alpn":"http/1.1"})).unwrap(),("api.example.com".into(),8443));
        assert!(connect_target(&json!({"host":"api.example.com.","port":443,"sni":"api.example.com.","alpn":"http/1.1"})).is_ok());
        for host in [
            "",
            "API.example.com",
            "example.com/path",
            "api..example.com",
            "api.example.com\r\nInjected: x",
            "-bad.example",
        ] {
            assert!(
                connect_target(&json!({"host":host,"port":443,"sni":host,"alpn":"http/1.1"}))
                    .is_err()
            );
        }
        assert!(connect_target(&json!({"host":"api.example.com","port":443,"sni":"other.example.com","alpn":"http/1.1"})).is_err());
    }

    #[test]
    fn open_metadata_matches_closed_u64_string_contract() {
        for models in [false, true] {
            let mut metadata = open_metadata("00112233445566778899aabbccddeeff", 1, models);
            metadata["ta_epoch"] = json!("00112233445566778899aabbccddeeff");
            metadata["session_nonce"] = json!("00112233445566778899aabbccddeeff");
            let frame = Frame {
                opcode: REQUEST_OPEN,
                request_id: [1; 16],
                call_seq: 2,
                status: 0,
                metadata,
                payload: Vec::new(),
            };
            assert!(encode_request(&frame).is_ok());
        }
    }

    #[test]
    fn counters_are_canonical_and_bounded() {
        assert_eq!(parse_counter(&json!("0")).unwrap(), 0);
        assert_eq!(
            parse_counter(&json!(u64::MAX.to_string())).unwrap(),
            u64::MAX
        );
        for bad in [
            json!(0),
            json!(""),
            json!("00"),
            json!("+1"),
            json!("18446744073709551616"),
        ] {
            assert!(parse_counter(&bad).is_err());
        }
    }

    #[test]
    fn typed_event_offsets_coverage_and_order_are_verified() {
        let head = serde_json::to_vec(&json!({"status":401,"headers":[]})).unwrap();
        let mut payload = head.clone();
        payload.extend_from_slice(b"bad");
        let mut frame = Frame {
            opcode: STEP,
            request_id: [1; 16],
            call_seq: 2,
            status: OK,
            metadata: json!({"progress":{
            "emitted_tls_tx":"0","accepted_tls_rx":"0","emitted_http_body":"3","events":[
                {"event_seq":"1","kind":"HTTP_HEAD","offset":0,"length":head.len()},
                {"event_seq":"2","kind":"HTTP_BODY","offset":head.len(),"length":3,"stream_offset":"0"},
                {"event_seq":"3","kind":"HTTP_END","offset":head.len()+3,"length":0,"details":{"framing":"complete","body_bytes":"3"}}
            ]}}),
            payload,
        };
        let mut checks = RelayChecks::default();
        checks.consume(&frame, &mut Vec::new()).unwrap();
        assert_eq!(checks.head, Some(401));
        assert!(checks.end);
        assert_eq!(checks.body, 3);
        frame.metadata["progress"]["events"][1]["offset"] = json!(head.len() + 1);
        assert!(
            RelayChecks::default()
                .consume(&frame, &mut Vec::new())
                .is_err()
        );
    }
}

/// Explicit management operation. The caller owns and erases the input Key.
pub fn provision(namespace: &str, reference: &str, operation: &str, key: &[u8]) -> Result<Value> {
    let mut management = Channel::hello("management", false)?;
    let mut metadata = put_metadata(reference, operation, 0, false);
    metadata["namespace"] = json!(namespace);
    let written = management.call(CREDENTIAL_PUT, metadata, key)?;
    expect(&written, OK, "credential_provision_stdin")?;
    let queried = management.call(
        CREDENTIAL_QUERY,
        json!({"namespace":namespace,"credential_ref":reference}),
        &[],
    )?;
    expect(&queried, OK, "credential_provision_query")?;
    require(
        queried.metadata["result"]["state"] == "live"
            && queried.metadata["result"]["receipt"]["operation_id"] == operation
            && queried.metadata["result"]["version"] == written.metadata["result"]["version"],
        "provision receipt reconciliation",
    )?;
    Ok(queried.metadata["result"].clone())
}

/// Synthetic bodies contain only a caller-selected model and random marker.
pub fn chat_body(operation: &str, model: &str, stream: bool, nonce: &str) -> Result<Vec<u8>> {
    let prompt = format!("Reply with exactly this token and no other text: {nonce}");
    let body = match operation {
        "CHAT" => {
            json!({"model":model,"stream":stream,"max_tokens":512,"messages":[{"role":"user","content":prompt}]})
        }
        "RESPONSES" => {
            json!({"model":model,"stream":stream,"max_output_tokens":512,"input":prompt})
        }
        "MESSAGES" => {
            json!({"model":model,"stream":stream,"max_tokens":512,"messages":[{"role":"user","content":prompt}]})
        }
        _ => return Err("synthetic probe operation unsupported".into()),
    };
    serde_json::to_vec(&body).map_err(|_| "synthetic body encoding".into())
}

struct OpenGate {
    count: usize,
    state: std::sync::Mutex<(usize, bool)>,
    changed: std::sync::Condvar,
}
impl OpenGate {
    fn wait(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "parallel open gate poisoned")?;
        state.0 += 1;
        self.changed.notify_all();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(15), |state| {
                state.0 < self.count && !state.1
            })
            .map_err(|_| "parallel open gate poisoned")?;
        if state.1 || timeout.timed_out() && state.0 < self.count {
            drop(state);
            self.abort();
            return Err("parallel open barrier failed or timed out".into());
        }
        Ok(())
    }
    fn abort(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.1 = true;
            self.changed.notify_all();
        }
    }
}

/// Four actual request contexts must all have OPEN succeeded before any one
/// uploads or commits its body. This proves overlap at the TA admission layer.
pub fn parallel_chat(config: RawConfig, model: &str, stream: bool) -> Result<()> {
    let count = 4;
    let gate = std::sync::Arc::new(OpenGate {
        count,
        state: std::sync::Mutex::new((0, false)),
        changed: std::sync::Condvar::new(),
    });
    let mut owners = Vec::new();
    for index in 0..count {
        let gate = gate.clone();
        let config = config.clone();
        let model = model.to_owned();
        owners.push(std::thread::spawn(move || {
            let result: Result<()> = (|| {
                let random = random_id();
                let nonce = format!("LSP_OK_{}",&random[..8]);
                let body = chat_body(&config.operation,&model,stream,&nonce)?;
                let mut channel = Channel::hello("request",false)?;
                require(channel.generation_limit >= count,"TA request limit below four")?;
                let mut opened = || gate.wait();
                let response = request_with_hooks(&mut channel,&config,&body,None,None,Some(&mut opened))?;
                require(response.status == 200,"parallel HTTP response status")?;
                let observed = inspect_protocol(&response.body,stream,&nonce,&config.operation)?;
                emit(json!({"check":"parallel_chat_request_complete","ok":true,"index":index,"operation":config.operation,
                    "http_status":response.status,"body_length":response.body_length,"body_sha256":format!("{:x}",Sha256::digest(&response.body)),
                    "synthetic_nonce_observed":true,"completion":observed,"transport":response.transport,"ca_metrics":response.ca_metrics}));
                Ok(())
            })();
            if result.is_err() { gate.abort(); }
            result
        }));
    }
    let mut failures = Vec::new();
    for (index, owner) in owners.into_iter().enumerate() {
        match owner.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(format!("request {index}: {error}")),
            Err(_) => failures.push(format!("request {index}: owner panic")),
        }
    }
    let opened = gate
        .state
        .lock()
        .map_err(|_| "parallel open gate poisoned")?
        .0;
    emit(
        json!({"check":"parallel_chat_complete","ok":failures.is_empty() && opened == count,"requests":count,"opened_before_first_commit":opened,"all_open_before_commit":opened==count,"failures":failures.len()}),
    );
    require(failures.is_empty() && opened == count, &failures.join(", "))
}

fn sse_json_events(body: &[u8]) -> Result<Vec<Value>> {
    let text = std::str::from_utf8(body).map_err(|_| "SSE UTF-8 invalid")?;
    let mut output = Vec::new();
    let mut data = String::new();
    for fragment in text.split_inclusive('\n') {
        let line = fragment.strip_suffix('\n').unwrap_or(fragment);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            if !data.is_empty() {
                data.pop();
                if data != "[DONE]" {
                    output.push(serde_json::from_str(&data).map_err(|_| "SSE data JSON invalid")?);
                }
                data.clear();
            }
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push_str(value.strip_prefix(' ').unwrap_or(value));
            data.push('\n');
        }
    }
    require(data.is_empty(), "SSE final event truncated")?;
    Ok(output)
}

fn responses_text(response: &Value) -> String {
    response["output"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|item| item["content"].as_array().into_iter().flatten())
        .filter_map(|item| item["text"].as_str())
        .collect::<Vec<_>>()
        .join("")
}

fn observed_model(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|model| {
            !model.is_empty()
                && model.len() <= 128
                && model.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
                })
        })
        .map(str::to_owned)
}

pub fn inspect_protocol(body: &[u8], stream: bool, nonce: &str, operation: &str) -> Result<Value> {
    if operation == "CHAT" {
        return inspect_chat(body, stream, nonce);
    }
    let mut content = String::new();
    let mut complete = false;
    let mut stopped = false;
    let mut model = None;
    let events = if stream {
        sse_json_events(body)?
    } else {
        vec![serde_json::from_slice(body).map_err(|_| "protocol response JSON")?]
    };
    for event in events {
        model = observed_model(&event["model"])
            .or_else(|| observed_model(&event["response"]["model"]))
            .or_else(|| observed_model(&event["message"]["model"]))
            .or(model);
        require(
            event["error"].is_null()
                && !matches!(
                    event["type"].as_str(),
                    Some("error" | "response.failed" | "response.incomplete")
                ),
            "provider error event",
        )?;
        match operation {
            "RESPONSES" => {
                if stream {
                    if event["type"] == "response.output_text.delta" {
                        content.push_str(
                            event["delta"]
                                .as_str()
                                .ok_or("Responses delta text missing")?,
                        );
                    }
                    if event["type"] == "response.completed" {
                        complete = event["response"]["status"] == "completed";
                        if content.is_empty() {
                            content = responses_text(&event["response"]);
                        }
                    }
                } else {
                    content = responses_text(&event);
                    complete = event["status"] == "completed";
                }
            }
            "MESSAGES" => {
                if stream {
                    if event["type"] == "content_block_delta"
                        && event["delta"]["type"] == "text_delta"
                    {
                        content.push_str(
                            event["delta"]["text"]
                                .as_str()
                                .ok_or("Messages delta text missing")?,
                        );
                    }
                    if event["type"] == "message_delta" {
                        stopped = event["delta"]["stop_reason"] == "end_turn";
                    }
                    if event["type"] == "message_stop" {
                        complete = true;
                    }
                } else {
                    content = event["content"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|part| part["text"].as_str())
                        .collect::<Vec<_>>()
                        .join("");
                    complete = true;
                    stopped = event["stop_reason"] == "end_turn";
                }
            }
            _ => return Err("unsupported protocol observer".into()),
        }
    }
    require(
        content.contains(nonce) && complete && (operation != "MESSAGES" || stopped),
        "synthetic protocol nonce or terminal mismatch",
    )?;
    Ok(
        json!({"operation":operation,"protocol_terminal_observed":complete,"model_stop_reason":if operation=="MESSAGES" {"end_turn"} else {"completed"},"synthetic_nonce_observed":true}),
    )
}

/// Minimal observer for the synthetic CLI chat acceptance probe. It inspects
/// content internally and returns nonsecret completion facts.
pub fn inspect_chat(body: &[u8], stream: bool, nonce: &str) -> Result<Value> {
    let mut content = String::new();
    let mut finish = None;
    let mut done = false;
    let mut usage = Value::Null;
    let mut model = None;
    if stream {
        let text = std::str::from_utf8(body).map_err(|_| "SSE UTF-8 invalid")?;
        let mut event = String::new();
        for fragment in text.split_inclusive('\n') {
            let line = fragment.strip_suffix('\n').unwrap_or(fragment);
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() {
                if event.is_empty() {
                    continue;
                }
                if event.ends_with('\n') {
                    event.pop();
                }
                require(!done, "SSE data after DONE")?;
                if event == "[DONE]" {
                    done = true;
                } else {
                    let chunk: Value =
                        serde_json::from_str(&event).map_err(|_| "SSE data JSON invalid")?;
                    require(chunk.get("error").is_none(), "SSE provider error")?;
                    model = observed_model(&chunk["model"]).or(model);
                    if chunk.get("usage").is_some() && !chunk["usage"].is_null() {
                        usage = chunk["usage"].clone();
                    }
                    if let Some(delta) = chunk["choices"][0]["delta"]["content"].as_str() {
                        content.push_str(delta);
                    }
                    if let Some(reason) = chunk["choices"][0]["finish_reason"].as_str() {
                        finish = Some(reason.to_owned());
                    }
                }
                event.clear();
            } else if let Some(data) = line.strip_prefix("data:") {
                require(!done, "SSE data after DONE")?;
                event.push_str(data.strip_prefix(' ').unwrap_or(data));
                event.push('\n');
            }
        }
        require(done, "SSE DONE missing or truncated")?;
    } else {
        let decoded: Value = serde_json::from_slice(body).map_err(|_| "chat response JSON")?;
        usage = decoded["usage"].clone();
        model = observed_model(&decoded["model"]);
        content = decoded["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        finish = decoded["choices"][0]["finish_reason"]
            .as_str()
            .map(str::to_owned);
    }
    let safe_finish = match finish.as_deref() {
        Some("stop") => "stop",
        Some("length") => "length",
        Some("content_filter") => "content_filter",
        Some(_) => "unknown",
        None => "missing",
    };
    emit(
        json!({"check":"synthetic_chat_observation","model_stop_reason":safe_finish,"content_length":content.len(),"expected_length":nonce.len(),"nonce_observed":content.contains(nonce),
        "casefold_match":content.to_ascii_lowercase().contains(&nonce.to_ascii_lowercase()),
        "common_prefix_count":content.chars().zip(nonce.chars()).take_while(|(actual,expected)|actual==expected).count(),
        "diff_count":content.chars().zip(nonce.chars()).filter(|(actual,expected)|actual!=expected).count()+content.chars().count().abs_diff(nonce.chars().count()),
        "sse_done_observed":done,"usage":{"prompt_tokens":usage["prompt_tokens"].as_u64(),"completion_tokens":usage["completion_tokens"].as_u64(),"total_tokens":usage["total_tokens"].as_u64(),"reasoning_tokens":usage["completion_tokens_details"]["reasoning_tokens"].as_u64()}}),
    );
    require(
        content.contains(nonce) && finish.as_deref() == Some("stop"),
        "synthetic chat nonce or finish_reason mismatch",
    )?;
    Ok(json!({"model_stop_reason":"stop","sse_done_observed":done,"observed_model":model}))
}

#[cfg(test)]
mod observer_tests {
    use super::*;
    #[test]
    fn protocol_specific_terminal_events_and_truncation_are_observed() {
        let responses = b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"nonce\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n";
        assert!(inspect_protocol(responses, true, "nonce", "RESPONSES").is_ok());
        assert!(inspect_protocol(br#"{"status":"completed","error":null,"model":"deepseek-flash","output":[{"type":"message","content":[{"type":"output_text","text":"nonce"}]}]}"#, false,"nonce","RESPONSES").is_ok());
        assert!(inspect_protocol(br#"{"type":"message","stop_reason":"end_turn","content":[{"type":"text","text":"nonce"}]}"#,false,"nonce","MESSAGES").is_ok());
        assert!(
            inspect_protocol(
                &responses[..responses.len() - 1],
                true,
                "nonce",
                "RESPONSES"
            )
            .is_err()
        );
        let messages = b"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"nonce\"}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\ndata: {\"type\":\"message_stop\"}\n\n";
        assert!(inspect_protocol(messages, true, "nonce", "MESSAGES").is_ok());
        assert!(
            inspect_protocol(&messages[..messages.len() - 1], true, "nonce", "MESSAGES").is_err()
        );
        assert!(inspect_protocol(messages, true, "other", "MESSAGES").is_err());
        for operation in ["CHAT", "RESPONSES", "MESSAGES"] {
            let body: Value = serde_json::from_slice(
                &chat_body(operation, "deepseek-flash", true, "nonce").unwrap(),
            )
            .unwrap();
            assert_eq!(body["model"], "deepseek-flash");
            assert_eq!(body["stream"], true);
        }
    }
    #[test]
    fn parallel_open_gate_aborts_waiters_without_deadlock() {
        let gate = std::sync::Arc::new(OpenGate {
            count: 4,
            state: std::sync::Mutex::new((0, false)),
            changed: std::sync::Condvar::new(),
        });
        let waiting = gate.clone();
        let thread = std::thread::spawn(move || waiting.wait());
        while gate.state.lock().unwrap().0 == 0 {
            std::thread::yield_now();
        }
        gate.abort();
        assert!(thread.join().unwrap().is_err());
    }

    #[test]
    fn sse_probe_requires_nonce_finish_and_complete_done_event() {
        let body=b"data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"private internal text\",\"content\":\"nonce\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n";
        assert_eq!(
            inspect_chat(body, true, "nonce").unwrap()["sse_done_observed"],
            true
        );
        assert!(inspect_chat(&body[..body.len() - 2], true, "nonce").is_err());
        assert!(inspect_chat(&body[..body.len() - 1], true, "nonce").is_err());
        let mut late = body.to_vec();
        late.extend_from_slice(b"data: incomplete");
        assert!(inspect_chat(&late, true, "nonce").is_err());
        assert!(inspect_chat(body, true, "different").is_err());
        let missing_finish=b"data: {\"choices\":[{\"delta\":{\"content\":\"nonce\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n";
        assert!(inspect_chat(missing_finish, true, "nonce").is_err());
    }
}
