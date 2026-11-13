//! Reusable in-process GP/LSP backup CA and its interoperability driver.
use std::mem;
use std::ptr;
use zeroize::{Zeroize, Zeroizing};

use cc_teec::{
    TEEC_CloseSession, TEEC_FinalizeContext, TEEC_InitializeContext, TEEC_InvokeCommand,
    TEEC_OpenSession, raw,
};
pub use secret_teeproxy_ta::wire::*;
pub use serde_json::Value;
use serde_json::json;
pub use uuid::Uuid;

pub type Result<T> = std::result::Result<T, String>;

pub fn emit(value: Value) {
    #[cfg(feature = "cli")]
    println!("{value}");
    #[cfg(not(feature = "cli"))]
    let _ = value;
}
pub fn require(condition: bool, detail: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(detail.into())
    }
}

#[derive(Default, Clone, serde::Serialize)]
pub struct InvokeMetrics {
    pub open_session_us: u64,
    pub invoke_count: u64,
    pub invoke_total_us: u64,
    pub invoke_max_us: u64,
}
fn elapsed_us(started: std::time::Instant) -> u64 {
    started.elapsed().as_micros().min(u64::MAX as u128) as u64
}

fn invoke_failure(rc: u32, origin: u32, request: &[u8], capacity: usize) -> String {
    let opcode = request
        .get(8..10)
        .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
        .map(|value| format!("{value:#06x}"))
        .unwrap_or_else(|| "unknown".into());
    let sequence = request
        .get(40..48)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".into());
    let phase = cc_teec::get_last_invoke_phase();
    let mut message = format!(
        "invoke rc={rc:#010x} origin={origin} phase={} opcode={opcode} seq={sequence} input_len={} output_capacity={capacity}",
        phase,
        request.len(),
    );
    if matches!(phase, "build_parameters" | "update_operation") {
        let (reason, covered) = cc_teec::get_last_vma_failure();
        message.push_str(&format!(" vma_reason={reason} covered_vmas={covered}"));
    }
    message
}

pub struct Teec {
    context: Box<raw::TEEC_Context>,
    session: raw::TEEC_Session,
    metrics: InvokeMetrics,
}
impl Teec {
    pub fn open() -> Result<Self> {
        let started = std::time::Instant::now();
        // The SDK stores this context address inside the session. The Box keeps
        // its address stable when the wrapper moves after OpenSession.
        let mut context = Box::new(unsafe { mem::zeroed::<raw::TEEC_Context>() });
        let mut session = unsafe { mem::zeroed::<raw::TEEC_Session>() };
        let rc = TEEC_InitializeContext(ptr::null(), context.as_mut());
        require(
            rc == raw::TEEC_SUCCESS,
            &format!("initialize_context rc={rc:#010x}"),
        )?;
        let uuid = Uuid::parse_str(TA_UUID).unwrap();
        let (low, mid, high, node) = uuid.as_fields();
        let destination = raw::TEEC_UUID {
            timeLow: low,
            timeMid: mid,
            timeHiAndVersion: high,
            clockSeqAndNode: *node,
        };
        let mut origin = 0;
        let rc = TEEC_OpenSession(
            context.as_mut(),
            &mut session,
            &destination,
            raw::TEEC_LOGIN_PUBLIC,
            ptr::null(),
            ptr::null_mut(),
            &mut origin,
        );
        if rc != raw::TEEC_SUCCESS {
            TEEC_FinalizeContext(context.as_mut());
            return Err(format!("open_session rc={rc:#010x} origin={origin}"));
        }
        emit(json!({"check":"gp_open_session","ok":true}));
        Ok(Self {
            context,
            session,
            metrics: InvokeMetrics {
                open_session_us: elapsed_us(started),
                ..Default::default()
            },
        })
    }

    pub fn invoke(&mut self, request: &[u8], capacity: usize) -> Result<Invoke> {
        let mut input = Zeroizing::new(request.to_vec());
        let mut output = vec![0u8; capacity];
        let mut operation = unsafe { mem::zeroed::<raw::TEEC_Operation>() };
        operation.paramTypes = raw::TEEC_PARAM_TYPES(
            raw::TEEC_MEMREF_TEMP_INPUT,
            raw::TEEC_MEMREF_TEMP_OUTPUT,
            raw::TEEC_VALUE_OUTPUT,
            raw::TEEC_NONE,
        );
        require(
            operation.paramTypes == GP_PARAM_TYPES,
            "GP paramTypes mismatch",
        )?;
        operation.params[0].tmpref = raw::TEEC_TempMemoryReference {
            buffer: input.as_mut_ptr().cast(),
            size: input.len(),
        };
        operation.params[1].tmpref = raw::TEEC_TempMemoryReference {
            buffer: output.as_mut_ptr().cast(),
            size: capacity,
        };
        let mut origin = 0;
        let started = std::time::Instant::now();
        let rc = TEEC_InvokeCommand(&mut self.session, CMD_EXCHANGE, &mut operation, &mut origin);
        let duration = elapsed_us(started);
        self.metrics.invoke_count += 1;
        self.metrics.invoke_total_us += duration;
        self.metrics.invoke_max_us = self.metrics.invoke_max_us.max(duration);
        // Transport failure makes outputs unusable and this command is never replayed.
        if rc != raw::TEEC_SUCCESS {
            return Err(invoke_failure(rc, origin, request, capacity));
        }
        let size = unsafe { operation.params[1].tmpref.size };
        let values = unsafe { operation.params[2].value };
        require(size <= capacity, "SDK returned oversized p1")?;
        output.truncate(size);
        if values.a == E_OUTPUT_CAPACITY {
            require(
                size == 0 && values.b as usize == OUTPUT_FRAME_MAX,
                "invalid output-capacity response",
            )?;
            return Ok(Invoke::Capacity);
        }
        require(values.b as usize == size, "p2.b/p1.size association")?;
        let frame = decode_reply(&output, request, values.a)?;
        Ok(Invoke::Reply(frame))
    }
}
impl Drop for Teec {
    fn drop(&mut self) {
        TEEC_CloseSession(&mut self.session);
        TEEC_FinalizeContext(self.context.as_mut());
        emit(
            json!({"check":"gp_close_finalize_returned","ok":true,"manager_cleanup":"not_asserted"}),
        );
    }
}
pub enum Invoke {
    Capacity,
    Reply(Frame),
}

pub fn encode_request(frame: &Frame) -> Result<Vec<u8>> {
    frame.encode_request().map_err(|error| error.to_string())
}

pub fn decode_reply(bytes: &[u8], request: &[u8], status: u32) -> Result<Frame> {
    require(
        bytes.len() >= HEADER_BYTES && bytes.len() <= OUTPUT_FRAME_MAX,
        "reply frame length",
    )?;
    require(
        &bytes[..4] == b"LSP1" && bytes[4..8] == [1, 0, 0, 0],
        "reply magic/version",
    )?;
    let u16_at = |at| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
    let u32_at = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let u64_at = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    require(
        u16_at(10) == 1 && u16_at(12) == 64 && u16_at(14) == 0 && u64_at(56) == 0,
        "reply flags/reserved",
    )?;
    require(
        u32_at(16) as usize == bytes.len() && u32_at(48) == status,
        "frame_len/p2.a association",
    )?;
    require(
        bytes[8..10] == request[8..10] && bytes[24..48] == request[24..48],
        "reply opcode/request/seq association",
    )?;
    let meta_len = u32_at(20) as usize;
    let payload_len = u32_at(52) as usize;
    require(
        meta_len <= METADATA_MAX && HEADER_BYTES + meta_len + payload_len == bytes.len(),
        "reply metadata/payload lengths",
    )?;
    let metadata: Value = serde_json::from_slice(&bytes[HEADER_BYTES..HEADER_BYTES + meta_len])
        .map_err(|_| "reply JSON invalid")?;
    require(metadata.is_object(), "reply metadata must be object")?;
    let request_seq = u64::from_le_bytes(request[40..48].try_into().unwrap());
    require(
        metadata["next_call_seq"]
            .as_str()
            .and_then(|value| value.parse::<u64>().ok())
            == request_seq.checked_add(1),
        "reply next_call_seq association",
    )?;
    Ok(Frame {
        opcode: u16_at(8),
        request_id: bytes[24..40].try_into().unwrap(),
        call_seq: u64_at(40),
        status,
        metadata,
        payload: bytes[HEADER_BYTES + meta_len..].to_vec(),
    })
}

const LEGACY_UPLOAD_CHUNK: usize = 15000;

fn negotiated_input_limits(result: &Value) -> Result<(usize, usize)> {
    let advertised = match result["limits"].get("frame_input_max") {
        Some(value) => value.as_u64().ok_or("HELLO input frame limit invalid")?,
        None => LEGACY_INPUT_FRAME_MAX as u64,
    };
    let bulk = result["capabilities"]["features"]
        .as_array()
        .is_some_and(|features| features.iter().any(|feature| feature == "bulk_input_frames"));
    let local_max = if bulk { INPUT_FRAME_MAX } else { LEGACY_INPUT_FRAME_MAX };
    let frame_max = advertised.min(local_max as u64) as usize;
    let reserved = HEADER_BYTES + METADATA_MAX;
    require(frame_max > reserved, "HELLO input frame limit too small")?;
    // Legacy BODY_CHUNK metadata is closed and its maximum-width offsets fit
    // beside 15,000 payload bytes. Bulk frames reserve the full JSON allowance.
    let upload_chunk = if !bulk && frame_max == LEGACY_INPUT_FRAME_MAX {
        LEGACY_UPLOAD_CHUNK
    } else {
        frame_max - reserved
    };
    Ok((frame_max, upload_chunk))
}

fn upload_chunks(body: &[u8], chunk_size: usize) -> impl Iterator<Item = (usize, &[u8])> {
    body.chunks(chunk_size)
        .enumerate()
        .map(move |(index, chunk)| (index * chunk_size, chunk))
}

pub struct Channel {
    pub teec: Teec,
    pub seq: u64,
    pub epoch: String,
    pub nonce: String,
    pub request_id: [u8; 16],
    pub generation_limit: usize,
    pub session_limit: usize,
    pub input_frame_max: usize,
    pub upload_chunk_size: usize,
}
impl Channel {
    pub fn hello(role: &str, capacity_test: bool) -> Result<Self> {
        Self::hello_from(Teec::open()?, role, capacity_test)
    }

    pub fn hello_from(teec: Teec, role: &str, capacity_test: bool) -> Result<Self> {
        let mut channel = Self {
            teec,
            seq: 1,
            epoch: String::new(),
            nonce: String::new(),
            request_id: [0; 16],
            generation_limit: 0,
            session_limit: 0,
            input_frame_max: LEGACY_INPUT_FRAME_MAX,
            upload_chunk_size: LEGACY_UPLOAD_CHUNK,
        };
        let frame = Frame {
            opcode: HELLO,
            request_id: [0; 16],
            call_seq: 1,
            status: 0,
            metadata: json!({"role":role,"supported_versions":[{"major":1,"minor":0}],"client_name":"lsp-test-only-probe"}),
            payload: Vec::new(),
        };
        let bytes = encode_request(&frame)?;
        if capacity_test {
            require(
                matches!(channel.teec.invoke(&bytes, 1)?, Invoke::Capacity),
                "expected output-capacity rejection",
            )?;
            emit(json!({"check":"output_capacity_same_sequence_retry","ok":true,"call_seq":"1"}));
        }
        let reply = match channel.teec.invoke(&bytes, OUTPUT_FRAME_MAX)? {
            Invoke::Reply(reply) => reply,
            Invoke::Capacity => return Err("full-capacity response rejected".into()),
        };
        require(reply.status == OK, "HELLO business rejection")?;
        (channel.input_frame_max, channel.upload_chunk_size) =
            negotiated_input_limits(&reply.metadata["result"])?;
        channel.epoch = reply.metadata["ta_epoch"]
            .as_str()
            .ok_or("HELLO epoch missing")?
            .into();
        channel.nonce = reply.metadata["session_nonce"]
            .as_str()
            .ok_or("HELLO nonce missing")?
            .into();
        channel.generation_limit = reply.metadata["result"]["limits"]["max_concurrent_requests"]
            .as_u64()
            .ok_or("HELLO request limit missing")? as usize;
        channel.session_limit = reply.metadata["result"]["limits"]["max_sessions"]
            .as_u64()
            .ok_or("HELLO session limit missing")? as usize;
        channel.seq = 2;
        emit(
            json!({"check":"hello","ok":true,"role":role,"ta_epoch":channel.epoch,"session_nonce":channel.nonce,
            "result":reply.metadata["result"],"gp_p1_p2_frame_associations":true}),
        );
        Ok(channel)
    }

    pub fn call(&mut self, opcode: u16, mut metadata: Value, payload: &[u8]) -> Result<Frame> {
        metadata["ta_epoch"] = json!(self.epoch);
        metadata["session_nonce"] = json!(self.nonce);
        let mut frame = Frame {
            opcode,
            request_id: self.request_id,
            call_seq: self.seq,
            status: 0,
            metadata,
            payload: payload.to_vec(),
        };
        let bytes = Zeroizing::new(encode_request(&frame)?);
        frame.payload.zeroize();
        require(bytes.len() <= self.input_frame_max, "request exceeds peer input frame limit")?;
        let reply = match self.teec.invoke(&bytes, OUTPUT_FRAME_MAX)? {
            Invoke::Reply(reply) => reply,
            Invoke::Capacity => return Err("full-capacity response rejected".into()),
        };
        require(
            reply.metadata["ta_epoch"] == self.epoch
                && reply.metadata["session_nonce"] == self.nonce,
            "reply epoch/nonce association",
        )?;
        self.seq = self.seq.checked_add(1).ok_or("sequence overflow")?;
        Ok(reply)
    }
}

pub mod driver;
pub mod native;
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoke_failure_exposes_header_metadata_and_excludes_payload() {
        let mut request = vec![0u8; 64];
        request[8..10].copy_from_slice(&STEP.to_le_bytes());
        request[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        request.extend_from_slice(b"fixture-key-payload-must-remain-private");
        let message = invoke_failure(raw::TEEC_ERROR_BAD_PARAMETERS, 1, &request, 32768);
        assert!(message.contains("invoke rc=0xffff0006 origin=1 phase="));
        assert!(message.contains("opcode=0x0103 seq=18446744073709551615"));
        assert!(message.contains(&format!(
            "input_len={} output_capacity=32768",
            request.len()
        )));
        assert!(!message.contains("fixture-key"));
        assert!(!message.contains("top_byte"));
        let short = invoke_failure(raw::TEEC_ERROR_BAD_PARAMETERS, 1, &[0], 1);
        assert!(short.contains("opcode=unknown seq=unknown input_len=1 output_capacity=1"));
    }

    #[test]
    fn invoke_failure_includes_current_vma_reason_only_in_memory_phases() {
        let mut context: raw::TEEC_Context = unsafe { mem::zeroed() };
        let mut session = raw::TEEC_Session {
            imp: raw::TEEC_Session__Imp {
                ctx: &mut context,
                session_id: 7,
            },
        };
        let mut operation: raw::TEEC_Operation = unsafe { mem::zeroed() };
        operation.paramTypes = GP_PARAM_TYPES;
        let mut bytes = [0u8; 8];
        operation.params[0].tmpref = raw::TEEC_TempMemoryReference {
            buffer: bytes.as_mut_ptr().cast(),
            size: usize::MAX,
        };
        let mut origin = 0;
        let rc = TEEC_InvokeCommand(&mut session, CMD_EXCHANGE, &mut operation, &mut origin);
        assert_eq!(rc, raw::TEEC_ERROR_BAD_PARAMETERS);
        let message = invoke_failure(rc, origin, &bytes, 32768);
        assert!(message.contains("phase=build_parameters"));
        assert!(message.contains("vma_reason=overflow covered_vmas=0"));
        let rc = TEEC_InvokeCommand(ptr::null_mut(), CMD_EXCHANGE, ptr::null_mut(), &mut origin);
        let message = invoke_failure(rc, origin, &bytes, 32768);
        assert!(message.contains("phase=context"));
        assert!(!message.contains("vma_reason="));
        assert_eq!(cc_teec::get_last_vma_failure(), ("none", 0));
    }

    fn hello() -> Frame {
        Frame {
            opcode: HELLO,
            request_id: [0; 16],
            call_seq: 1,
            status: OK,
            metadata: json!({"role":"management","supported_versions":[{"major":1,"minor":0}]}),
            payload: Vec::new(),
        }
    }
    fn reply() -> Frame {
        Frame {
            opcode: HELLO,
            request_id: [0; 16],
            call_seq: 1,
            status: OK,
            metadata: json!({"next_call_seq":"2","ta_epoch":"00112233445566778899aabbccddeeff","session_nonce":"ffeeddccbbaa99887766554433221100",
                "state":"HELLO_READY","error":null,"result":{},"progress":null}),
            payload: Vec::new(),
        }
    }
    #[test]
    fn explicit_endpoint_reconfiguration_is_idempotent_and_immutable() {
        assert!(cc_teec::configure_vsock_endpoint(3001, 10099).is_ok());
        assert!(cc_teec::configure_vsock_endpoint(3001, 10099).is_ok());
        assert!(cc_teec::configure_vsock_endpoint(3002, 10099).is_err());
    }

    #[test]
    fn request_encoder_uses_shared_closed_wire_validation() {
        let mut frame = hello();
        let bytes = encode_request(&frame).unwrap();
        assert_eq!(Frame::decode_request(&bytes).unwrap(), frame);
        frame.metadata["unrecognized"] = json!(true);
        assert!(encode_request(&frame).is_err());
    }

    #[test]
    fn bulk_input_negotiation_bounds_new_and_legacy_peers() {
        let result = |limit: Value, features: Value| json!({
            "limits":{"frame_input_max":limit},"capabilities":{"features":features}
        });
        assert_eq!(negotiated_input_limits(&result(json!(61440), json!(["bulk_input_frames"]))).unwrap(), (61440, 57280));
        assert_eq!(negotiated_input_limits(&result(json!(u64::MAX), json!(["bulk_input_frames"]))).unwrap(), (61440, 57280));
        assert_eq!(negotiated_input_limits(&result(json!(16384), json!([]))).unwrap(), (16384, 15000));
        assert_eq!(negotiated_input_limits(&result(json!(61440), json!([]))).unwrap(), (16384, 15000));
        assert_eq!(negotiated_input_limits(&json!({})).unwrap(), (16384, 15000));
        assert_eq!(negotiated_input_limits(&result(json!(8192), json!([]))).unwrap(), (8192, 4032));
        assert!(negotiated_input_limits(&result(json!(4160), json!([]))).is_err());
        assert!(negotiated_input_limits(&result(json!("61440"), json!([]))).is_err());
        assert!(encode_request(&hello()).unwrap().len() < LEGACY_INPUT_FRAME_MAX);
        assert_eq!(OUTPUT_FRAME_MAX, 32768);
    }

    #[test]
    fn negotiated_upload_offsets_and_hash_preserve_body_for_each_peer() {
        use sha2::{Digest, Sha256};
        let body: Vec<u8> = (0..5_600_000).map(|index| (index % 251) as u8).collect();
        for (result, expected_calls) in [
            (json!({"limits":{"frame_input_max":61440},"capabilities":{"features":["bulk_input_frames"]}}), 98),
            (json!({"limits":{"frame_input_max":16384},"capabilities":{"features":[]}}), 374),
            (json!({"limits":{"frame_input_max":61440},"capabilities":{"features":[]}}), 374),
        ] {
            let (frame_max, upload_chunk_size) = negotiated_input_limits(&result).unwrap();
            let mut reconstructed = Vec::new();
            let mut calls = 0;
            for (offset, chunk) in upload_chunks(&body, upload_chunk_size) {
                let frame = Frame {
                    opcode: BODY_CHUNK,
                    request_id: [1; 16],
                    call_seq: calls + 2,
                    status: OK,
                    metadata: json!({"ta_epoch":"f".repeat(32),"session_nonce":"e".repeat(32),
                        "body_offset":offset.to_string()}),
                    payload: chunk.to_vec(),
                };
                let encoded = encode_request(&frame).unwrap();
                assert!(encoded.len() <= frame_max);
                let decoded = Frame::decode_request(&encoded).unwrap();
                assert_eq!(decoded.metadata["body_offset"], reconstructed.len().to_string());
                reconstructed.extend_from_slice(&decoded.payload);
                calls += 1;
            }
            assert_eq!(calls, expected_calls);
            assert_eq!(reconstructed, body);
            assert_eq!(Sha256::digest(&reconstructed), Sha256::digest(&body));
        }
    }
    #[test]
    fn reply_decoder_checks_all_frame_and_gp_status_associations() {
        let request = encode_request(&hello()).unwrap();
        let bytes = reply().encode_reply().unwrap();
        assert!(decode_reply(&bytes, &request, OK).is_ok());
        for offset in [0, 4, 8, 10, 12, 14, 16, 20, 24, 40, 48, 52, 56] {
            let mut corrupt = bytes.clone();
            corrupt[offset] ^= 1;
            assert!(
                decode_reply(&corrupt, &request, OK).is_err(),
                "offset {offset}"
            );
        }
        assert!(decode_reply(&bytes, &request, E_BUSY).is_err());
        let mut wrong_next = reply();
        wrong_next.metadata["next_call_seq"] = json!("3");
        assert!(decode_reply(&wrong_next.encode_reply().unwrap(), &request, OK).is_err());
    }
}

#[cfg(test)]
#[path = "../vendor/rust-libteec/src/teec/vmem.rs"]
mod sdk_vmem_regressions;
