// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! # rust-libteec
//!
//! GlobalPlatform TEE Client API 的 Rust 实现，提供与可信执行环境(TEE)通信的接口。
//!
//! ## 主要功能
//!
//! - **TEE 上下文管理**: 初始化和销毁 TEE 连接
//! - **会话管理**: 打开/关闭与 Trusted Application 的会话
//! - **命令调用**: 在 TA 中执行命令并传递参数（通过机密通信通道序列化传输）
//! - **共享内存**: 管理 MEMREF 类型参数的本地缓冲区（数据通过机密通信通道传输，非真正共享）
//! - **机密通信**: 基于 TLS + VSOCK 的加密通信通道，CA 与 TA 之间的所有数据都通过此通道传输
//! - **CA 认证**: 自动验证客户端应用的签名和证书链，并向 TA 提供 CA 身份信息（`ca_uuid`/`verified`）
//!
//! ## 特性标志
//!
//! - `ca-sign-verify`: 启用 CA 认证功能（默认启用）
//! - `test-root-ca`: 使用 tasign 内置测试根证书（开发调试用，默认关闭）
//! - `debug_level_0` ~ `debug_level_4`: 控制日志详细程度（默认 level_2）
//! - `fuzz`: 仅模糊测试启用，导出内部函数与 C API 转发入口（产品构建不带，见 `fuzz/README.md`）

/// Explicit TLS ciphertext fault injection for SDK regression tests.
/// Disabled by default; ordinary TEEC clients never use this transport.
#[cfg(feature = "attack-test")]
pub mod attack_test;

mod cc_client;
mod error;
mod teec;
mod teec_trace;

pub use self::{
    error::{Error, ErrorKind, ErrorOrigin, Result},
    teec::{
        TEEC_AllocateSharedMemory, TEEC_CloseSession, TEEC_FinalizeContext, TEEC_InitializeContext,
        TEEC_InvokeCommand, TEEC_OpenSession, TEEC_RegisterSharedMemory,
        TEEC_RegisterSharedMemoryFileDescriptor, TEEC_ReleaseSharedMemory,
        TEEC_RequestCancellation,
    },
    teec_trace::*,
};

#[cfg(feature = "ca-sign-verify")]
pub use self::teec::{clear_cache, get_or_verify_ca};

/// 重新导出 GP TEE Client API 原始类型（常量、结构体、联合体等），
/// 以 `raw` 模块别名暴露给 FFI 边界使用。
pub use teec_api_types as raw;

/// CA 认证信息，包含 CA 的 UUID 与验签结果，
/// 在 OpenSession 时随请求发送给 TA，供 TA 侧识别调用者。
pub use teec_protocol::CaAuthInfo;

/// Task-owned immutable endpoint configuration for the in-process APK adapter.
pub use self::cc_client::vsock_define::configure_vsock_endpoint;

#[derive(Clone, Copy)]
pub(crate) enum InvokePhase {
    NotInvoked,
    Context,
    BuildParameters,
    Send,
    RemoteTaResult,
    UpdateOperation,
    Complete,
}

std::thread_local! {
    static LAST_INVOKE_PHASE: std::cell::Cell<InvokePhase> =
        const { std::cell::Cell::new(InvokePhase::NotInvoked) };
}

pub(crate) fn set_invoke_phase(phase: InvokePhase) {
    LAST_INVOKE_PHASE.with(|current| current.set(phase));
}

/// Process-local diagnostic for the calling thread's most recent Invoke.
/// Each Invoke resets the phase before validating any pointer. No payload,
/// pointer, identity or transport error contents are retained here.
pub fn get_last_invoke_phase() -> &'static str {
    LAST_INVOKE_PHASE.with(|current| match current.get() {
        InvokePhase::NotInvoked => "not_invoked",
        InvokePhase::Context => "context",
        InvokePhase::BuildParameters => "build_parameters",
        InvokePhase::Send => "send",
        InvokePhase::RemoteTaResult => "remote_TA_result",
        InvokePhase::UpdateOperation => "update_operation",
        InvokePhase::Complete => "complete",
    })
}

/// Static failure reason and bounded coverage count for this thread's most
/// recent VMA check. Reset before each Invoke and each VMA validation.
pub fn get_last_vma_failure() -> (&'static str, u16) {
    teec::vmem::get_last_vma_failure()
}

#[cfg(test)]
mod invoke_phase_tests {
    use super::*;

    #[test]
    fn phase_labels_are_closed_and_thread_local() {
        for (phase, label) in [
            (InvokePhase::NotInvoked, "not_invoked"),
            (InvokePhase::Context, "context"),
            (InvokePhase::BuildParameters, "build_parameters"),
            (InvokePhase::Send, "send"),
            (InvokePhase::RemoteTaResult, "remote_TA_result"),
            (InvokePhase::UpdateOperation, "update_operation"),
            (InvokePhase::Complete, "complete"),
        ] {
            set_invoke_phase(phase);
            assert_eq!(get_last_invoke_phase(), label);
        }
        std::thread::spawn(|| {
            assert_eq!(get_last_invoke_phase(), "not_invoked");
            set_invoke_phase(InvokePhase::Send);
            assert_eq!(get_last_invoke_phase(), "send");
        })
        .join()
        .unwrap();
        assert_eq!(get_last_invoke_phase(), "complete");
    }
}
/// 模糊测试专用导出：仅在 `fuzz` feature 启用时暴露内部函数，
/// 使 fuzzer 能直接调用实际代码路径，而不必在 target 里复刻一份逻辑。
#[cfg(feature = "fuzz")]
pub mod fuzz {
    use teec_protocol::TEE_Parameters;

    use crate::Result;
    use crate::raw::{TEEC_Operation, TEEC_UUID};

    pub use crate::teec::fuzz_api::*;

    /// 暴露 `teec::uuid_to_string` 给 fuzzer（包装 pub(crate) 实现，避免代码重复）。
    pub fn uuid_to_string(uuid: &TEEC_UUID) -> Result<String> {
        crate::teec::uuid_to_string(uuid)
    }

    /// 暴露 `teec::build_parameters_from_operation` 给 fuzzer。
    /// 该函数包含 12+ match 分支，是参数构建路径中分支覆盖的关键点。
    pub fn build_parameters_from_operation(
        operation: *mut TEEC_Operation,
    ) -> Result<TEE_Parameters> {
        crate::teec::build_parameters_from_operation(operation)
    }

    /// 暴露 vsock CID 配置读取给 fuzzer（环境变量解析 + 默认值回退）。
    pub fn get_vsock_cid() -> u32 {
        crate::cc_client::vsock_define::get_vsock_cid()
    }

    /// 暴露 vsock 端口配置读取给 fuzzer（环境变量解析 + 默认值回退）。
    pub fn get_vsock_port() -> u32 {
        crate::cc_client::vsock_define::get_vsock_port()
    }
}
