// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! 模糊测试内部接口（仅在 `fuzz` feature 下编译）。
//!
//! fuzz target 只能看到 crate 的公开面，而本库多数健壮性逻辑位于
//! `pub(crate)` / `pub(super)` 层级：共享内存分配与回收、memref 边界校验、
//! 参数读写访问器、上下文登记表、`/proc/self/maps` 区间校验。
//! 若在 target 里复刻这些逻辑，测得的覆盖率是假的（覆盖的是复刻品）；
//! 本模块以薄包装转发到真实实现，使覆盖率对应真实代码路径。
//!
//! 约束：
//! - 只做转发，不在包装里复制或放宽任何校验逻辑；
//! - 不导出 `CcClient`、`ShmEntry` 等内部类型，避免内部类型泄漏到公开面；
//! - 不参与非 fuzz 构建，也不进入 C ABI。

use teec_protocol::TEE_Parameters;

use super::context::ContextManager;
use super::operation::OperationParams;
use super::shared_memory::SharedMemoryManager;
use super::vmem;
use crate::Result;
use crate::raw;

/// 构造真实实现的参数视图（`OperationParams::new` 只做空指针校验）。
///
/// 生命周期由调用方承担：`operation` 是裸指针，编译器无法把返回值的 `'a`
/// 绑定到任何借用上，因此包装函数必须**立即使用**该视图、不得把它存进结构体
/// 或跨语句持有（所有包装函数都是 `op_params(op)?` 后一路同步调用）。
fn op_params<'a>(operation: *mut raw::TEEC_Operation) -> Result<OperationParams<'a>> {
    OperationParams::new(operation)
}

// 参数访问器

/// 读取参数位图（`TEEC_PARAM_TYPES` 的 4 个 4-bit 字段）。
pub fn op_param_types(operation: *mut raw::TEEC_Operation) -> Result<u32> {
    op_params(operation).map(|p| p.param_types())
}

/// 读取 `idx` 的 VALUE 字段。
pub fn op_get_value(operation: *mut raw::TEEC_Operation, idx: usize) -> Result<(u32, u32)> {
    op_params(operation)?.get_value(idx)
}

/// 写入 `idx` 的 VALUE 字段。
pub fn op_set_value(operation: *mut raw::TEEC_Operation, idx: usize, a: u32, b: u32) -> Result<()> {
    op_params(operation)?.set_value(idx, a, b)
}

/// 读取 `idx` 的 TEMP 缓冲区（含 `vmem` 可读性校验与越界判断）。
pub fn op_get_tmpref_data(operation: *mut raw::TEEC_Operation, idx: usize) -> Result<Vec<u8>> {
    op_params(operation)?.get_tmpref_data(idx)
}

/// 写入 `idx` 的 TEMP 缓冲区（含截断与 `vmem` 可写性校验）。
pub fn op_set_tmpref_data(
    operation: *mut raw::TEEC_Operation,
    idx: usize,
    data: &[u8],
) -> Result<()> {
    op_params(operation)?.set_tmpref_data(idx, data)
}

/// 读取 TEMP 参数的声明大小。
pub fn op_get_tmpref_size(operation: *mut raw::TEEC_Operation, idx: usize) -> Result<usize> {
    op_params(operation)?.get_tmpref_size(idx)
}

/// 读取 MEMREF 参数的声明大小。
pub fn op_get_memref_size(operation: *mut raw::TEEC_Operation, idx: usize) -> Result<usize> {
    op_params(operation)?.get_memref_size(idx)
}

/// 读取 MEMREF 的 parent 方向标志（先校验 parent 已登记）。
pub fn op_get_memref_parent_flags(operation: *mut raw::TEEC_Operation, idx: usize) -> Result<u32> {
    op_params(operation)?.get_memref_parent_flags(idx)
}

/// 读取整块 MEMREF 缓冲区。
pub fn op_get_memref_data_whole(
    operation: *mut raw::TEEC_Operation,
    idx: usize,
) -> Result<Vec<u8>> {
    op_params(operation)?.get_memref_data_whole(idx)
}

/// 写回整块 MEMREF 缓冲区。
pub fn op_set_memref_data_whole(
    operation: *mut raw::TEEC_Operation,
    idx: usize,
    data: &[u8],
) -> Result<()> {
    op_params(operation)?.set_memref_data_whole(idx, data)
}

/// 按方向标志读取部分 MEMREF 缓冲区。
pub fn op_get_memref_data_partial(
    operation: *mut raw::TEEC_Operation,
    idx: usize,
    req_flags: u32,
) -> Result<Vec<u8>> {
    op_params(operation)?.get_memref_data_partial(idx, req_flags)
}

/// 写回部分 MEMREF 缓冲区（按 `memref.offset`）。
pub fn op_set_memref_data_partial(
    operation: *mut raw::TEEC_Operation,
    idx: usize,
    data: &[u8],
) -> Result<()> {
    op_params(operation)?.set_memref_data_partial(idx, data)
}

/// 参数写回总入口（`TEEC_InvokeCommand` 成功路径上的 12 分支 match）。
pub fn op_update_from_parameters(
    operation: *mut raw::TEEC_Operation,
    params: TEE_Parameters,
) -> Result<()> {
    super::operation::update_operation_from_parameters(operation, params)
}

// 共享内存管理

/// 分配或注册共享内存（`register = false` 时为 `TEEC_AllocateSharedMemory` 路径）。
pub fn shm_allocate(
    ctx: *mut raw::TEEC_Context,
    shm: *mut raw::TEEC_SharedMemory,
    register: bool,
) -> Result<()> {
    SharedMemoryManager::allocate(ctx, shm, register)
}

/// 释放共享内存（对未登记/被篡改的句柄应为幂等 no-op）。
pub fn shm_release(shm: *mut raw::TEEC_SharedMemory) {
    SharedMemoryManager::release(shm);
}

/// 结构体地址是否登记为本库分配的共享内存（纯地址比较）。
pub fn shm_is_registered(shm: *const raw::TEEC_SharedMemory) -> bool {
    SharedMemoryManager::is_registered(shm)
}

/// 在锁保护下读取共享内存区段（memref 读取路径的权威边界校验）。
pub fn shm_read_buffer(
    parent: *const raw::TEEC_SharedMemory,
    offset: usize,
    size: usize,
) -> Result<Vec<u8>> {
    SharedMemoryManager::read_buffer_locked(parent, offset, size)
}

/// 在锁保护下写入共享内存区段（memref 写回路径的权威边界校验）。
pub fn shm_write_buffer(
    parent: *const raw::TEEC_SharedMemory,
    offset: usize,
    data: &[u8],
) -> Result<()> {
    SharedMemoryManager::write_buffer_locked(parent, offset, data)
}

/// 按上下文清理共享内存（`TEEC_FinalizeContext` 的清理路径）。
pub fn shm_release_by_context(ctx: *mut raw::TEEC_Context) {
    SharedMemoryManager::release_by_context(ctx);
}

// 上下文

/// 上下文是否已登记（纯地址比较）。
pub fn ctx_is_registered(ctx: *mut raw::TEEC_Context) -> bool {
    ContextManager::is_registered(ctx)
}

/// 取上下文的登记 id（未登记返回 `None`）。
pub fn ctx_registered_id(ctx: *mut raw::TEEC_Context) -> Option<i32> {
    ContextManager::registered_id(ctx)
}

/// 注销上下文（未登记、或 fd 与登记值不一致时应拒绝清理）。
pub fn ctx_remove(ctx: *mut raw::TEEC_Context) {
    ContextManager::remove_context(ctx);
}

/// 取上下文对应的通信客户端；内部类型不外泄，只返回是否成功。
pub fn ctx_get_client_ok(ctx: *mut raw::TEEC_Context) -> Result<()> {
    ContextManager::get_client(ctx).map(|_| ())
}

// 其他内部逻辑

/// `/proc/self/maps` 区间校验的纯函数入口（覆盖解析/权限/跨 VMA 分支）。
pub fn vmem_check_range(maps: &str, start: usize, end: usize, writable: bool) -> Option<bool> {
    vmem::check_range_in_maps_for_fuzz(maps, start, end, writable)
}

/// 真实 `vmem::range_readable`（读取 `/proc/self/maps` 与缓存快速路径）。
pub fn vmem_range_readable(start: *const u8, len: usize) -> bool {
    vmem::range_readable(start, len)
}

/// 真实 `vmem::range_writable`。
pub fn vmem_range_writable(start: *const u8, len: usize) -> bool {
    vmem::range_writable(start, len)
}

/// CA 认证主要入口（读 `/proc/self/exe` → ELF 验签 → 缓存），返回 `(uuid, 是否通过)`。
#[cfg(feature = "ca-sign-verify")]
pub fn ca_auth_info() -> (String, bool) {
    let info = super::ca_auth::get_or_verify_ca();
    (info.ca_uuid, info.verified)
}

/// 清空 CA 认证缓存（下一次调用将重新验签）。
#[cfg(feature = "ca-sign-verify")]
pub fn ca_auth_clear_cache() {
    super::ca_auth::clear_cache();
}

// C ABI 入口

// `c_api` 模块本身不对外公开（FFI 符号由链接器可见），但 fuzz target 需要
// 以 Rust 调用方式直达这 10 个入口，否则 `src/teec/c_api.rs` 永远无法被覆盖。
// 这里逐个转发，不加任何参数预处理或错误码改写。

/// 转发 `TEEC_InitializeContext`。
pub fn ffi_initialize_context(
    name: *const core::ffi::c_char,
    ctx: *mut raw::TEEC_Context,
) -> raw::TEEC_Result {
    super::c_api::TEEC_InitializeContext(name, ctx)
}

/// 转发 `TEEC_FinalizeContext`。
pub fn ffi_finalize_context(ctx: *mut raw::TEEC_Context) {
    super::c_api::TEEC_FinalizeContext(ctx);
}

/// 转发 `TEEC_OpenSession`。
#[allow(clippy::too_many_arguments)]
pub fn ffi_open_session(
    ctx: *mut raw::TEEC_Context,
    session: *mut raw::TEEC_Session,
    destination: *const raw::TEEC_UUID,
    connection_method: u32,
    connection_data: *const core::ffi::c_void,
    operation: *mut raw::TEEC_Operation,
    ret_origin: *mut u32,
) -> raw::TEEC_Result {
    super::c_api::TEEC_OpenSession(
        ctx,
        session,
        destination,
        connection_method,
        connection_data,
        operation,
        ret_origin,
    )
}

/// 转发 `TEEC_CloseSession`。
pub fn ffi_close_session(session: *mut raw::TEEC_Session) {
    super::c_api::TEEC_CloseSession(session);
}

/// 转发 `TEEC_InvokeCommand`。
pub fn ffi_invoke_command(
    session: *mut raw::TEEC_Session,
    cmd_id: u32,
    operation: *mut raw::TEEC_Operation,
    error_origin: *mut u32,
) -> raw::TEEC_Result {
    super::c_api::TEEC_InvokeCommand(session, cmd_id, operation, error_origin)
}

/// 转发 `TEEC_RequestCancellation`。
pub fn ffi_request_cancellation(operation: *mut raw::TEEC_Operation) {
    super::c_api::TEEC_RequestCancellation(operation);
}

/// 转发 `TEEC_RegisterSharedMemory`。
pub fn ffi_register_shared_memory(
    ctx: *mut raw::TEEC_Context,
    shm: *mut raw::TEEC_SharedMemory,
) -> raw::TEEC_Result {
    super::c_api::TEEC_RegisterSharedMemory(ctx, shm)
}

/// 转发 `TEEC_RegisterSharedMemoryFileDescriptor`。
pub fn ffi_register_shared_memory_fd(
    ctx: *mut raw::TEEC_Context,
    shm: *mut raw::TEEC_SharedMemory,
    fd: i32,
) -> raw::TEEC_Result {
    super::c_api::TEEC_RegisterSharedMemoryFileDescriptor(ctx, shm, fd)
}

/// 转发 `TEEC_AllocateSharedMemory`。
pub fn ffi_allocate_shared_memory(
    ctx: *mut raw::TEEC_Context,
    shm: *mut raw::TEEC_SharedMemory,
) -> raw::TEEC_Result {
    super::c_api::TEEC_AllocateSharedMemory(ctx, shm)
}

/// 转发 `TEEC_ReleaseSharedMemory`。
pub fn ffi_release_shared_memory(shm: *mut raw::TEEC_SharedMemory) {
    super::c_api::TEEC_ReleaseSharedMemory(shm);
}
