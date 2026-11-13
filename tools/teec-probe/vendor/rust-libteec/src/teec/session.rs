// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! TEE 会话管理模块
//!
//! 负责 CA 与 TA 之间的会话生命周期管理，包括：
//! - 会话的打开、关闭
//! - 命令调用
//! - 取消请求
//!
//! 所有会话操作均通过机密通信通道（TLS + VSOCK）进行，
//! 请求和响应序列化为 `postcard` 格式后加密传输。

use std::ptr;

use log::{debug, warn};

use postcard::{take_from_bytes, to_allocvec};
use uuid::Uuid;

#[cfg(feature = "ca-sign-verify")]
use teec_protocol::CaAuthInfo;
use teec_protocol::{PacketType, TEE_Parameters, TEE_Request, TEE_Response};

use crate::{Error, ErrorKind, ErrorOrigin, InvokePhase, Result, raw, set_invoke_phase};

use super::context::ContextManager;
#[cfg(feature = "ca-sign-verify")]
use super::get_or_verify_ca;
use super::{build_parameters_from_operation, safe_ptr, update_operation_from_parameters};

pub(crate) fn open_session_impl(
    ctx: *mut raw::TEEC_Context,
    session: *mut raw::TEEC_Session,
    destination: *const raw::TEEC_UUID,
    connection_method: u32,
    operation: *mut raw::TEEC_Operation,
) -> Result<u32> {
    let _ = safe_ptr::deref_mut(ctx)?;
    let _ = safe_ptr::deref_mut(session)?;
    let uuid_nn = safe_ptr::deref(destination)?;
    // SAFETY: `uuid_nn` 已由 `deref` 验证为非空。`as_ref()` 返回对
    // 调用方提供的 UUID 的不可变引用，该引用在此处有效。
    let uuid = unsafe { uuid_nn.as_ref() };
    let uuid_str = uuid_to_string(uuid)?;
    debug!("[HOST] TEEC_OpenSession: uuid={uuid_str}");

    // 在 OpenSession 开始时立即执行 CA 认证（带缓存）
    // 尽早认证可以提前发现 CA 文件问题，避免后续不必要的操作
    #[cfg(feature = "ca-sign-verify")]
    let ca_auth_info = {
        let auth_result = get_or_verify_ca();

        // 记录认证结果（警告式，不阻断）
        if !auth_result.verified {
            warn!("CA 签名验证失败: ca_uuid={}", auth_result.ca_uuid);
        } else {
            debug!("CA 签名验证通过: ca_uuid={}", auth_result.ca_uuid);
        }

        // 转换为协议格式（直接使用 CaAuthInfo，无需转换）
        Some(CaAuthInfo {
            ca_uuid: auth_result.ca_uuid,
            verified: auth_result.verified,
        })
    };

    #[cfg(not(feature = "ca-sign-verify"))]
    let ca_auth_info: Option<teec_protocol::CaAuthInfo> = None;

    let params = if operation.is_null() {
        TEE_Parameters::default()
    } else {
        let mut operation_nn = safe_ptr::deref_mut(operation)?;
        // SAFETY: `operation_nn` 已验证非空，`deref_mut` 提供独占访问；
        // `as_mut()` 返回的可变引用可安全修改 `imp.session` 字段。
        let operation_ref = unsafe { operation_nn.as_mut() };
        // 与 invoke_command_impl 保持一致：将 operation 与本次打开的会话绑定，
        // 供后续 TEEC_RequestCancellation 使用。若遗漏此赋值，CA 传入仅按
        // GP 规范初始化 started 字段的 operation 时，取消路径会解引用
        // imp.session 中未初始化的垃圾指针。
        operation_ref.imp.session = session;

        build_parameters_from_operation(operation).map_err(|e| {
            warn!("[HOST] TEEC_OpenSession: uuid={uuid_str} 参数组装失败: {e}");
            e
        })?
    };

    let request = TEE_Request::OpenSession {
        uuid: uuid_str,
        connection_method,
        params,
        ca_auth_info,
    };

    let mut session_nn = safe_ptr::deref_mut(session)?;
    // SAFETY: `session_nn` 已验证非空；`as_mut()` 返回针对会话结构的
    // 可变引用，该引用在此作用域中有效。
    let session_ref = unsafe { session_nn.as_mut() };
    let response =
        send_request_and_recv_response(ctx, PacketType::OpenSession, &request).map_err(|e| {
            // uuid_str 已移入 request，错误路径由原始 uuid 重建，正常路径零开销
            warn!(
                "[HOST] TEEC_OpenSession: uuid={} 通信失败: {e}",
                uuid_to_string(uuid).unwrap_or_default()
            );
            e
        })?;

    match response {
        TEE_Response::OpenSession { session_id, result } => {
            debug!("[HOST] TEEC_OpenSession: session_id={session_id} result=0x{result:08x}");

            // 先检查结果，仅在成功时才写入会话状态：失败时保持 session
            // 结构体不变，避免 CA 在失败后误用被服务器返回值污染的
            // session_id/ctx（如调用 CloseSession 发送无效请求）。
            if result != raw::TEEC_SUCCESS {
                warn!(
                    "[HOST] TEEC_OpenSession: uuid={} TA 拒绝打开会话 result=0x{result:08x}",
                    uuid_to_string(uuid).unwrap_or_default()
                );
                return Err(Error::new(ErrorKind::from(result)).with_origin(ErrorOrigin::TEE));
            }

            session_ref.imp.ctx = ctx;
            session_ref.imp.session_id = session_id;

            Ok(result)
        }
        _ => {
            warn!(
                "[HOST] TEEC_OpenSession: uuid={} 响应类型非 OpenSession",
                uuid_to_string(uuid).unwrap_or_default()
            );
            Err(Error::new(ErrorKind::BadParameters).with_origin(ErrorOrigin::API))
        }
    }
}

pub(crate) fn close_session_impl(session: *mut raw::TEEC_Session) -> Result<()> {
    let mut session_nn = safe_ptr::deref_mut(session)?;
    // SAFETY: `session_nn` 已验证非空；`as_mut()` 返回针对会话结构的
    // 可变引用，可用于读取其字段。
    let session_ref = unsafe { session_nn.as_mut() };
    let session_id = session_ref.imp.session_id;
    let ctx = session_ref.imp.ctx;

    debug!(
        "[HOST] TEEC_CloseSession: session_id={session_id} ctx_is_null={}",
        ctx.is_null()
    );

    if ctx.is_null() {
        debug!("[HOST] TEEC_CloseSession: ctx is null, returning early");
        return Err(Error::new(ErrorKind::BadParameters));
    }

    let request = TEE_Request::CloseSession { session_id };
    let response = send_request_and_recv_response(ctx, PacketType::CloseSession, &request)?;

    match response {
        TEE_Response::CloseSession { result } => {
            debug!("[HOST] TEEC_CloseSession: result=0x{result:08x}, clearing session");
            session_ref.imp.ctx = ptr::null_mut();
            session_ref.imp.session_id = 0;
            Ok(())
        }
        _ => Err(Error::new(ErrorKind::BadParameters)),
    }
}

pub(crate) fn invoke_command_impl(
    session: *mut raw::TEEC_Session,
    cmd_id: u32,
    operation: *mut raw::TEEC_Operation,
) -> Result<u32> {
    set_invoke_phase(InvokePhase::Context);
    super::vmem::clear_last_vma_failure();
    let mut session_nn = safe_ptr::deref_mut(session)?;
    // SAFETY: `session_nn` 已验证非空；`as_mut()` 返回的可变引用在此
    // 作用域内有效，可用于读取 `imp.session_id` 和 `imp.ctx`。
    let session_ref = unsafe { session_nn.as_mut() };
    let session_id = session_ref.imp.session_id;
    let ctx = session_ref.imp.ctx;

    debug!("[HOST] TEEC_InvokeCommand: session_id={session_id} cmd_id={cmd_id}");

    if ctx.is_null() {
        warn!(
            "[HOST] TEEC_InvokeCommand: session_id={session_id} cmd_id={cmd_id} ctx 为空指针，拒绝调用"
        );
        return Err(Error::new(ErrorKind::BadParameters));
    }

    set_invoke_phase(InvokePhase::BuildParameters);
    let params = if operation.is_null() {
        TEE_Parameters::default()
    } else {
        let mut operation_nn = safe_ptr::deref_mut(operation)?;
        // SAFETY: `operation_nn` 已验证非空，且 `deref_mut` 提供独占访问；
        // 调用 `as_mut()` 可获得可变引用，可安全修改 `imp.session` 字段。
        let operation_ref = unsafe { operation_nn.as_mut() };
        operation_ref.imp.session = session;

        build_parameters_from_operation(operation).map_err(|e| {
            warn!("[HOST] TEEC_InvokeCommand: session_id={session_id} cmd_id={cmd_id} 参数组装失败: {e}");
            e
        })?
    };

    let request = TEE_Request::InvokeCommand {
        session_id,
        cmd_id,
        params,
    };

    let response = send_request_and_recv_response(ctx, PacketType::InvokeCommand, &request)
        .map_err(|e| {
            warn!(
                "[HOST] TEEC_InvokeCommand: session_id={session_id} cmd_id={cmd_id} 通信失败: {e}"
            );
            e
        })?;

    complete_invoke_response(session_id, cmd_id, operation, response)
}

fn complete_invoke_response(
    session_id: u32,
    cmd_id: u32,
    operation: *mut raw::TEEC_Operation,
    response: TEE_Response,
) -> Result<u32> {
    set_invoke_phase(InvokePhase::RemoteTaResult);
    match response {
        TEE_Response::InvokeCommand { params, result } => {
            if result != raw::TEEC_SUCCESS {
                let origin = if result == raw::TEEC_ERROR_TARGET_DEAD {
                    ErrorOrigin::TEE
                } else {
                    ErrorOrigin::API
                };
                warn!(
                    "[HOST] TEEC_InvokeCommand: session_id={session_id} cmd_id={cmd_id} TA 返回错误 result=0x{result:08x}"
                );
                return Err(Error::new(ErrorKind::from(result)).with_origin(origin));
            }

            if !operation.is_null() {
                set_invoke_phase(InvokePhase::UpdateOperation);
                update_operation_from_parameters(operation, params).map_err(|e| {
                    warn!("[HOST] TEEC_InvokeCommand: session_id={session_id} cmd_id={cmd_id} 响应参数写回失败: {e}");
                    e
                })?;
            }
            set_invoke_phase(InvokePhase::Complete);
            Ok(result)
        }
        _ => {
            warn!(
                "[HOST] TEEC_InvokeCommand: session_id={session_id} cmd_id={cmd_id} 响应类型非 InvokeCommand"
            );
            Err(Error::new(ErrorKind::BadParameters).with_origin(ErrorOrigin::API))
        }
    }
}

pub(crate) fn request_cancellation_impl(operation: *mut raw::TEEC_Operation) -> Result<()> {
    let mut operation_nn = safe_ptr::deref_mut(operation)?;
    // SAFETY: `operation_nn` 已验证非空，`deref_mut` 提供独占访问；
    // `as_mut()` 返回的可变引用可安全用于读取 `imp.session`。
    let operation_ref = unsafe { operation_nn.as_mut() };
    let session = operation_ref.imp.session;

    if session.is_null() {
        return Ok(());
    }

    let mut session_nn = safe_ptr::deref_mut(session)?;
    // SAFETY: `session_nn` 已验证非空；`as_mut()` 返回的可变引用在此作用域内有效，
    // 可用于读取 `imp.session_id` 和 `imp.ctx`。
    let session_ref = unsafe { session_nn.as_mut() };
    let session_id = session_ref.imp.session_id;
    let ctx = session_ref.imp.ctx;

    if ctx.is_null() {
        return Ok(());
    }

    let request = TEE_Request::RequestCancellation { session_id };
    let response = send_request_and_recv_response(ctx, PacketType::RequestCancellation, &request)?;

    match response {
        TEE_Response::RequestCancellation { result: _ } => {
            debug!("TEEC_RequestCancellation: 接收结果");
            Ok(())
        }
        _ => Err(Error::new(ErrorKind::BadParameters)),
    }
}

/// 将 GP TEE UUID 格式（`TEEC_UUID` 结构体）转换为标准 UUID 字符串。
///
/// 用于在 `TEEC_OpenSession` 中将 TA UUID 序列化为协议请求中的 `uuid` 字段。
pub(crate) fn uuid_to_string(uuid: &raw::TEEC_UUID) -> Result<String> {
    Ok(Uuid::from_fields(
        uuid.timeLow,
        uuid.timeMid,
        uuid.timeHiAndVersion,
        &uuid.clockSeqAndNode,
    )
    .to_string())
}

/// 通过机密通信通道发送请求并接收响应。
///
/// 流程：
/// 1. 从 `ContextManager` 获取 TLS 客户端连接
/// 2. 将 `TEE_Request` 序列化为 `postcard` 格式
/// 3. 通过 TLS 通道发送（带协议头）
/// 4. 先接收 4 字节长度前缀，再接收响应体
/// 5. 反序列化为 `TEE_Response` 并返回
///
/// 请求和响应均限制最大 64MB，防止 OOM 攻击。
fn send_request_and_recv_response(
    ctx: *mut raw::TEEC_Context,
    packet_type: PacketType,
    request: &TEE_Request,
) -> Result<TEE_Response> {
    debug!(
        "[HOST] send_request_and_recv_response: packet_type={:?}",
        packet_type
    );
    if matches!(packet_type, PacketType::InvokeCommand) {
        set_invoke_phase(InvokePhase::Context);
    }
    let client_arc = ContextManager::get_client(ctx)?;
    let mut client = client_arc
        .lock()
        .map_err(|_| Error::new(ErrorKind::Generic).with_origin(ErrorOrigin::API))?;
    debug!("[HOST] send_request_and_recv_response: lock acquired");

    if matches!(packet_type, PacketType::InvokeCommand) {
        set_invoke_phase(InvokePhase::Send);
    }

    let request_data = to_allocvec(request).map_err(|e| {
        warn!("序列化请求失败：{e}");
        Error::new(ErrorKind::BadFormat).with_origin(ErrorOrigin::API)
    })?;

    // 防止 OOM 攻击：限制请求数据最大为 64MB
    const MAX_REQUEST_SIZE: usize = 64 * 1024 * 1024; // 64MB

    if request_data.len() > MAX_REQUEST_SIZE {
        warn!(
            "请求数据过大：{} bytes (最大允许 {} bytes)",
            request_data.len(),
            MAX_REQUEST_SIZE
        );
        return Err(Error::new(ErrorKind::BadFormat).with_origin(ErrorOrigin::API));
    }

    client
        .send_data_with_header(packet_type, &request_data)
        .map_err(|e| {
            warn!("发送请求失败：{e}");
            Error::new(ErrorKind::Communication).with_origin(ErrorOrigin::COMMS)
        })?;
    debug!("[HOST] send_request_and_recv_response: send done, reading response length");

    let mut len_buf = [0u8; 4];

    client.recv_data(&mut len_buf).map_err(|e| {
        warn!("接收响应长度失败：{e}");
        Error::new(ErrorKind::Communication).with_origin(ErrorOrigin::COMMS)
    })?;

    // 防止整数溢出：先验证 u32 值在合理范围内，再转换为 usize
    let response_len_u32 = u32::from_ne_bytes(len_buf);
    const MAX_RESPONSE_SIZE: usize = 64 * 1024 * 1024; // 64MB

    if response_len_u32 > MAX_RESPONSE_SIZE as u32 {
        warn!(
            "响应数据过大：{} bytes (最大允许 {} bytes)",
            response_len_u32, MAX_RESPONSE_SIZE
        );
        return Err(Error::new(ErrorKind::BadFormat).with_origin(ErrorOrigin::COMMS));
    }

    let response_len = response_len_u32 as usize;
    debug!(
        "[HOST] send_request_and_recv_response: response_len={}",
        response_len
    );
    let mut response_data = vec![0u8; response_len];

    client.recv_data(&mut response_data).map_err(|e| {
        warn!("接收响应数据失败：{e}");
        Error::new(ErrorKind::Communication).with_origin(ErrorOrigin::COMMS)
    })?;
    debug!("[HOST] send_request_and_recv_response: response data received");

    take_from_bytes::<TEE_Response>(&response_data)
        .map(|(response, _)| response)
        .map_err(|e| {
            warn!("反序列化响应失败：{e}");
            Error::new(ErrorKind::BadFormat).with_origin(ErrorOrigin::API)
        })
}

#[cfg(test)]
mod session_tests {
    use super::*;

    fn invoke_response(result: u32) -> TEE_Response {
        TEE_Response::InvokeCommand {
            params: TEE_Parameters::default(),
            result,
        }
    }

    #[test]
    fn invoke_context_failure_resets_prior_phase_and_preserves_gp_result() {
        set_invoke_phase(InvokePhase::UpdateOperation);
        let buffer = [0u8; 8];
        assert!(!super::super::vmem::range_readable(
            buffer.as_ptr(),
            usize::MAX
        ));
        assert_eq!(crate::get_last_vma_failure(), ("overflow", 0));
        let mut origin = 99;
        let result =
            crate::TEEC_InvokeCommand(ptr::null_mut(), 0x1000, ptr::null_mut(), &mut origin);
        assert_eq!(result, raw::TEEC_ERROR_BAD_PARAMETERS);
        assert_eq!(origin, ErrorOrigin::API as u32);
        assert_eq!(crate::get_last_invoke_phase(), "context");
        assert_eq!(crate::get_last_vma_failure(), ("none", 0));
    }

    #[test]
    fn invoke_real_parameter_build_and_context_lookup_have_distinct_phases() {
        let mut context: raw::TEEC_Context = unsafe { std::mem::zeroed() };
        let mut session = raw::TEEC_Session {
            imp: raw::TEEC_Session__Imp {
                ctx: &mut context,
                session_id: 7,
            },
        };
        let mut operation = make_operation(&mut session);
        operation.paramTypes = 4; // Unsupported GP parameter type.
        let mut origin = 99;
        assert_eq!(
            crate::TEEC_InvokeCommand(&mut session, 0x1000, &mut operation, &mut origin),
            raw::TEEC_ERROR_BAD_PARAMETERS,
        );
        assert_eq!(origin, ErrorOrigin::API as u32);
        assert_eq!(crate::get_last_invoke_phase(), "build_parameters");
        operation.paramTypes = 0;
        assert_eq!(
            crate::TEEC_InvokeCommand(&mut session, 0x1000, &mut operation, &mut origin),
            raw::TEEC_ERROR_BAD_PARAMETERS,
        );
        assert_eq!(origin, ErrorOrigin::API as u32);
        assert_eq!(crate::get_last_invoke_phase(), "context");
    }

    #[test]
    fn remote_invoke_failure_keeps_legacy_result_and_origin_mapping() {
        for (result, origin) in [
            (raw::TEEC_ERROR_BAD_PARAMETERS, ErrorOrigin::API),
            (raw::TEEC_ERROR_TARGET_DEAD, ErrorOrigin::TEE),
        ] {
            let error =
                complete_invoke_response(7, 0x1000, ptr::null_mut(), invoke_response(result))
                    .unwrap_err();
            assert_eq!(error.raw_code(), result);
            assert_eq!(error.origin(), Some(origin));
            assert_eq!(crate::get_last_invoke_phase(), "remote_TA_result");
        }
        let error = complete_invoke_response(
            7,
            0x1000,
            ptr::null_mut(),
            TEE_Response::CloseSession {
                result: raw::TEEC_SUCCESS,
            },
        )
        .unwrap_err();
        assert_eq!(error.raw_code(), raw::TEEC_ERROR_BAD_PARAMETERS);
        assert_eq!(error.origin(), Some(ErrorOrigin::API));
        assert_eq!(crate::get_last_invoke_phase(), "remote_TA_result");
    }

    #[test]
    fn real_response_writeback_failure_and_success_are_distinguished() {
        let mut operation = make_operation(ptr::null_mut());
        operation.paramTypes = raw::TEEC_MEMREF_TEMP_OUTPUT;
        let mut params = TEE_Parameters::default();
        params.0.param.data = vec![1];
        let response = TEE_Response::InvokeCommand {
            params,
            result: raw::TEEC_SUCCESS,
        };
        let error = complete_invoke_response(7, 0x1000, &mut operation, response).unwrap_err();
        assert_eq!(error.raw_code(), raw::TEEC_ERROR_BAD_PARAMETERS);
        assert_eq!(crate::get_last_invoke_phase(), "update_operation");
        assert_eq!(
            complete_invoke_response(
                7,
                0x1000,
                ptr::null_mut(),
                invoke_response(raw::TEEC_SUCCESS)
            )
            .unwrap(),
            raw::TEEC_SUCCESS
        );
        assert_eq!(crate::get_last_invoke_phase(), "complete");
    }

    fn make_operation(session: *mut raw::TEEC_Session) -> raw::TEEC_Operation {
        raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                value: raw::TEEC_Value { a: 0, b: 0 },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp { session },
        }
    }

    #[test]
    fn test_request_cancellation_null_session_ctx_returns_ok() {
        // OpenSession 失败后 session.imp.ctx 保持 null（失败时不写入会话
        // 状态）：对绑定了该 session 的 operation 发起取消请求应安全返回 Ok，
        // 而不是解引用 null 或发送无效请求。
        let mut session = raw::TEEC_Session {
            imp: raw::TEEC_Session__Imp {
                ctx: ptr::null_mut(),
                session_id: 0,
            },
        };
        let mut op = make_operation(&mut session as *mut raw::TEEC_Session);

        let result = request_cancellation_impl(&mut op as *mut raw::TEEC_Operation);
        assert!(result.is_ok(), "ctx 为 null 时取消请求应安全返回 Ok");
    }

    #[test]
    fn test_request_cancellation_null_session_ptr_returns_ok() {
        // CA 未将 operation 传给 OpenSession/InvokeCommand 就调用取消：
        // imp.session 为 null 时应安全返回 Ok。
        let mut op = make_operation(ptr::null_mut());

        let result = request_cancellation_impl(&mut op as *mut raw::TEEC_Operation);
        assert!(result.is_ok(), "session 为 null 时取消请求应安全返回 Ok");
    }

    #[test]
    fn test_request_cancellation_unregistered_ctx_rejected() {
        // 垃圾/未登记的 ctx 指针（模拟 CA 未初始化内存中的残值）：
        // ContextManager::get_client 的地址登记校验应拒绝，不得解引用
        // 垃圾指针导致崩溃或借用其他上下文的连接。
        let mut fake_ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: 0x7fff,
                reg_mem: false,
                memref_null: false,
            },
        };
        let mut session = raw::TEEC_Session {
            imp: raw::TEEC_Session__Imp {
                ctx: &mut fake_ctx as *mut raw::TEEC_Context,
                session_id: 1,
            },
        };
        let mut op = make_operation(&mut session as *mut raw::TEEC_Session);

        let result = request_cancellation_impl(&mut op as *mut raw::TEEC_Operation);
        assert!(
            result.is_err(),
            "未登记的 ctx 地址应被 get_client 地址校验拒绝"
        );
    }
}
