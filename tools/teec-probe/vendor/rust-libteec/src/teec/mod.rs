// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! TEE 客户端库实现，基于 GlobalPlatform TEE Client API 规范
//!
//! 提供与可信执行环境(TEE)通信的接口，包括：
//! - 上下文管理（初始化/销毁）
//! - 会话管理（打开/关闭）
//! - 命令调用（通过机密通信通道序列化传输参数）
//! - 共享内存管理（用于 MEMREF 类型参数的缓冲区管理）
//! - CA 认证（校验 CA 签名，并向 TA 提供 CA 身份信息供其鉴权）
//! - 地址空间区间校验（对 TMPREF 与注册内存的读写做纵深防御式越界检查）
//!
//! ## 通信机制
//!
//! CA 与 TA 之间的所有通信都通过机密通信通道（TLS + VSOCK）进行：
//! - 请求和响应数据被序列化为字节流，通过 TLS 加密后发送
//! - 共享内存（TEEC_SharedMemory）仅用于管理 MEMREF 参数的本地缓冲区
//! - 真正的“共享”是通过网络传输实现的，而非传统意义上的内存映射
//!
//! ## 线程安全
//!
//! 所有 FFI 函数都是线程安全的，内部使用 `DashMap` 和 `Mutex` 保证并发访问安全。
//! 但是，同一会话上的并发操作可能导致竞态条件，建议调用方进行同步。
//!
//! ## 错误处理
//!
//! FFI 函数返回 `TEEC_Result`（u32），通过 `ret_origin` 参数返回错误来源。
//! 内部使用 Rust 的 `Result<T, Error>` 进行错误处理，最后转换为 C 风格的返回值。

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

mod c_api;
#[cfg(feature = "ca-sign-verify")]
mod ca_auth;
mod context;
#[cfg(feature = "fuzz")]
pub mod fuzz_api;
mod operation;
mod safe_ptr;
mod session;
mod shared_memory;
pub(crate) mod vmem;

pub use c_api::{
    TEEC_AllocateSharedMemory, TEEC_CloseSession, TEEC_FinalizeContext, TEEC_InitializeContext,
    TEEC_InvokeCommand, TEEC_OpenSession, TEEC_RegisterSharedMemory,
    TEEC_RegisterSharedMemoryFileDescriptor, TEEC_ReleaseSharedMemory, TEEC_RequestCancellation,
};
#[cfg(feature = "ca-sign-verify")]
pub use ca_auth::{clear_cache, get_or_verify_ca};
pub use operation::{build_parameters_from_operation, update_operation_from_parameters};
// 仅对 crate 内部可见：供 `fuzz` feature 的导出模块包装调用（见 src/lib.rs）；
// 随该 feature 一起条件编译，避免非 fuzz 构建下触发 unused_imports 警告。
#[cfg(feature = "fuzz")]
pub(crate) use session::uuid_to_string;
