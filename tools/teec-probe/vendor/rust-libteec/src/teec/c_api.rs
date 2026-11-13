// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! GlobalPlatform TEE Client API — 对外 C 接口层
//!
//! 本模块是所有 `TEEC_*` FFI 函数的唯一入口，每个函数都是一个薄包装：
//!
//! 1. 打印调试日志
//! 2. 调用对应子模块中的 `_impl` 领域逻辑函数（或 `SharedMemoryManager` 方法）
//! 3. 通过 `handle_error` 将 `Result` 转换为 C 风格的 `TEEC_Result` + `ret_origin`
//!
//! 这种集中编排使得：
//! - C API 全貌一目了然（审计友好）
//! - 领域模块（`context`、`session`、`shared_memory`）只关心业务逻辑
//! - 编译优化（`_impl` 函数小、易内联）

use std::ffi::{c_char, c_void};

use log::{debug, warn};

use super::{
    context::{ContextManager, initialize_context_impl},
    safe_ptr,
    session::{
        close_session_impl, invoke_command_impl, open_session_impl, request_cancellation_impl,
    },
    shared_memory::SharedMemoryManager,
};
use crate::{ErrorKind, ErrorOrigin, Result, raw};

/// 统一的错误处理入口：将 `Result<u32>` 映射为 C 风格返回值。
///
/// - 成功时直接返回 `u32` 结果码
/// - 失败时通过 `ret_origin` 指针（若非空）写入错误来源，
///   并返回 `Error::raw_code()` 对应的 TEEC_Result 错误码
fn handle_error(result: Result<u32>, ret_origin: *mut u32) -> raw::TEEC_Result {
    match result {
        Ok(code) => code,
        Err(e) => {
            if !ret_origin.is_null() {
                // SAFETY: `ret_origin` 已通过 null 检查验证为非空指针。
                // 写入 u32 值是安全的，调用方保证指针有效且可写。
                unsafe {
                    *ret_origin = e.origin().unwrap_or(ErrorOrigin::API) as u32;
                }
            }
            e.raw_code()
        }
    }
}

/// TEEC_InitializeContext() - 初始化 TEE 上下文，建立与 TEE 的机密通信连接。
///
/// @param name  可选的名称字符串（当前实现忽略）。
/// @param ctx   要初始化的上下文结构指针。
///
/// @return TEEC_SUCCESS       上下文初始化成功。
/// @return TEEC_Result        出现错误。
#[unsafe(no_mangle)]
pub extern "C" fn TEEC_InitializeContext(
    _name: *const c_char,
    ctx: *mut raw::TEEC_Context,
) -> raw::TEEC_Result {
    debug!("TEEC_InitializeContext");

    match initialize_context_impl(ctx) {
        Ok(_) => raw::TEEC_SUCCESS,
        Err(e) => e.raw_code(),
    }
}

/// TEEC_FinalizeContext() - 销毁保存连接信息的上下文。
///
/// 该函数用于销毁已初始化的 TEE 上下文，关闭客户端应用与 TEE 之间的连接。
/// 仅当与该上下文关联的所有会话已关闭且所有共享内存块已释放时才可调用。
///
/// @param ctx  要销毁的上下文。
#[unsafe(no_mangle)]
pub extern "C" fn TEEC_FinalizeContext(ctx: *mut raw::TEEC_Context) {
    debug!("[HOST] TEEC_FinalizeContext");

    // 解引用前先按地址登记表校验：未通过 TEEC_InitializeContext 登记的
    // 指针（垃圾/未初始化内存）直接忽略，避免读取任意内存。
    if !ContextManager::is_registered(ctx) {
        debug!("TEEC_FinalizeContext: ctx 未初始化，忽略");
        return;
    }

    if let Ok(ctx_nn) = safe_ptr::deref(ctx) {
        // SAFETY: `ctx_nn` 已由 `deref` 验证为非空。`as_ref()` 返回的不可变引用
        // 在此作用域内有效。
        let ctx_ref = unsafe { ctx_nn.as_ref() };
        let ctx_id = ctx_ref.imp.fd;
        if ctx_id < 0 {
            debug!("TEEC_FinalizeContext: context already finalized (fd={ctx_id})");
            return;
        }
    }

    SharedMemoryManager::release_by_context(ctx);
    ContextManager::remove_context(ctx);
}

/// TEEC_OpenSession() - 与指定的受信任应用打开一个新会话。
///
/// @param ctx                已初始化的 TEE 上下文，在其作用域内打开会话。
/// @param session            要初始化的会话结构体指针。
/// @param destination        标识要打开会话的受信任应用的 UUID 结构。
/// @param connection_method  要使用的连接方法。
/// @param connection_data    与所选连接方法有关的连接数据。本实现不支持，
///                           应设置为 NULL。
/// @param operation          用于会话的操作结构。若不需要则传入 NULL。
///                           TMPREF 参数的安全契约与 TEEC_InvokeCommand
///                           相同（buffer/size 须真实有效）。
/// @param ret_origin         若函数返回非 TEEC_SUCCESS，此参数将保存错误来源。
///
/// @return TEEC_SUCCESS      成功打开会话。
/// @return TEEC_Result       出现错误。
#[unsafe(no_mangle)]
pub extern "C" fn TEEC_OpenSession(
    ctx: *mut raw::TEEC_Context,
    session: *mut raw::TEEC_Session,
    destination: *const raw::TEEC_UUID,
    connection_method: u32,
    _connection_data: *const c_void,
    operation: *mut raw::TEEC_Operation,
    ret_origin: *mut u32,
) -> raw::TEEC_Result {
    debug!("TEEC_OpenSession");

    let result = open_session_impl(ctx, session, destination, connection_method, operation);

    handle_error(result, ret_origin)
}

/// TEEC_CloseSession() - 关闭已与受信任应用打开的会话。
///
/// @param session 要关闭的会话。
#[unsafe(no_mangle)]
pub extern "C" fn TEEC_CloseSession(session: *mut raw::TEEC_Session) {
    debug!("TEEC_CloseSession");

    if let Err(e) = close_session_impl(session) {
        // CloseSession 失败不应该阻断清理，但需要记录错误以便调试
        warn!("TEEC_CloseSession 失败：{e}");
    }
}

/// TEEC_InvokeCommand() - 在指定的受信任应用中执行命令。
///
/// 安全契约：TMPREF 参数的 `buffer`/`size` 由 CA 保证真实有效；
/// 库在读写前会校验区间完整位于单个可读/可写 VMA 内，`size` 大于
/// 实际分配时返回 TEEC_ERROR_BAD_PARAMETERS 而非越界访问。
///
/// @param session        已打开的受信任应用会话句柄。
/// @param cmd_id         要在受信任应用中调用的命令标识符。
/// @param operation      用于调用命令的操作结构；若不需要则传入 NULL。
/// @param error_origin   若函数返回非 TEEC_SUCCESS，此参数将保存错误来源。
///
/// @return TEEC_SUCCESS  操作成功。
/// @return TEEC_Result   出现错误。
#[unsafe(no_mangle)]
pub extern "C" fn TEEC_InvokeCommand(
    session: *mut raw::TEEC_Session,
    cmd_id: u32,
    operation: *mut raw::TEEC_Operation,
    error_origin: *mut u32,
) -> raw::TEEC_Result {
    debug!("TEEC_InvokeCommand");

    let result = invoke_command_impl(session, cmd_id, operation);

    handle_error(result, error_origin)
}

/// TEEC_RequestCancellation() - 请求取消正在等待的打开会话或命令调用。
///
/// @param operation 指向先前传递给 open session 或 invoke 的操作结构的指针。
#[unsafe(no_mangle)]
pub extern "C" fn TEEC_RequestCancellation(operation: *mut raw::TEEC_Operation) {
    debug!("TEEC_RequestCancellation");

    if let Err(e) = request_cancellation_impl(operation) {
        // RequestCancellation 失败不应该阻断，但需要记录错误以便调试
        warn!("TEEC_RequestCancellation 失败：{e}");
    }
}

/// TEEC_RegisterSharedMemory() - 将现有内存块注册为在指定上下文作用域内的
/// 共享内存块。
///
/// 安全契约：注册时按 `shm->size` 拷贝 `shm->buffer` 的内容，CA 须保证
/// `[buffer, buffer+size)` 真实可读；库会校验该区间位于单个可读 VMA 内，
/// 校验失败返回 TEEC_ERROR_BAD_PARAMETERS。
///
/// @param ctx       已初始化的 TEE 上下文。
/// @param sharedMem 要注册的共享内存结构指针。
///
/// @return TEEC_SUCCESS              注册成功。
/// @return TEEC_ERROR_OUT_OF_MEMORY  内存不足。
/// @return TEEC_Result               其他错误。
#[unsafe(no_mangle)]
pub extern "C" fn TEEC_RegisterSharedMemory(
    ctx: *mut raw::TEEC_Context,
    shm: *mut raw::TEEC_SharedMemory,
) -> raw::TEEC_Result {
    debug!("TEEC_RegisterSharedMemory");

    match SharedMemoryManager::allocate(ctx, shm, true) {
        Ok(_) => raw::TEEC_SUCCESS,
        Err(e) => e.raw_code(),
    }
}

/// TEEC_RegisterSharedMemoryFileDescriptor() - 通过文件描述符注册共享内存。
///
/// @param ctx    已初始化的 TEE 上下文。
/// @param shm    指向共享内存结构的指针。
/// @param fd     要注册的共享内存文件描述符。
///
/// @return TEEC_ERROR_NOT_IMPLEMENTED  当前版本未实现此功能。
#[unsafe(no_mangle)]
pub extern "C" fn TEEC_RegisterSharedMemoryFileDescriptor(
    _ctx: *mut raw::TEEC_Context,
    _shm: *mut raw::TEEC_SharedMemory,
    _fd: i32,
) -> raw::TEEC_Result {
    // TODO: 实现此函数
    ErrorKind::NotImplemented.into()
}

/// TEEC_AllocateSharedMemory() - 为 TEE 分配共享内存。
///
/// @param ctx        已初始化的 TEE 上下文。
/// @param sharedMem  指向要分配的共享内存结构的指针（由调用者填写希望的属性）。
///
/// @return TEEC_SUCCESS              分配/注册成功。
/// @return TEEC_ERROR_OUT_OF_MEMORY  内存不足。
/// @return TEEC_Result               其他错误。
#[unsafe(no_mangle)]
pub extern "C" fn TEEC_AllocateSharedMemory(
    ctx: *mut raw::TEEC_Context,
    shm: *mut raw::TEEC_SharedMemory,
) -> raw::TEEC_Result {
    debug!("TEEC_AllocateSharedMemory");

    match SharedMemoryManager::allocate(ctx, shm, false) {
        Ok(_) => raw::TEEC_SUCCESS,
        Err(e) => e.raw_code(),
    }
}

/// TEEC_ReleaseSharedMemory() - 释放或取消注册共享内存。
///
/// @param sharedMem  要释放或取消注册的共享内存指针。
#[unsafe(no_mangle)]
pub extern "C" fn TEEC_ReleaseSharedMemory(shm: *mut raw::TEEC_SharedMemory) {
    debug!("TEEC_ReleaseSharedMemory");
    SharedMemoryManager::release(shm);
}

#[cfg(test)]
mod c_api_tests {
    use std::ptr;

    use super::*;

    // 单元测试直接调用这些 FFI 入口，确保 `#[no_mangle]` 符号在单元测试二进制中
    // 被引用保留并被执行；否则链接器会回收未引用的符号，使 llvm-cov 在
    // 多二进制聚合覆盖率时对同名函数报告 hash 不匹配警告。

    /// TEEC_InvokeCommand 空指针健全性：空会话应返回 BAD_PARAMETERS。
    #[test]
    fn test_invoke_command_null_session() {
        let res = TEEC_InvokeCommand(ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut());
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// TEEC_InvokeCommand 未初始化会话：仍应返回 BAD_PARAMETERS 且不崩溃。
    #[test]
    fn test_invoke_command_uninitialized_session() {
        let mut session = raw::TEEC_Session {
            imp: raw::TEEC_Session__Imp {
                ctx: ptr::null_mut(),
                session_id: 0,
            },
        };
        let mut error_origin = 0u32;
        let res = TEEC_InvokeCommand(&mut session, 1, ptr::null_mut(), &mut error_origin);
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// TEEC_RegisterSharedMemory 空指针健全性：应返回 BAD_PARAMETERS。
    #[test]
    fn test_register_shared_memory_null_args() {
        let res = TEEC_RegisterSharedMemory(ptr::null_mut(), ptr::null_mut());
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// TEEC_RegisterSharedMemory 空缓冲区：应返回 BAD_PARAMETERS 且不崩溃。
    #[test]
    fn test_register_shared_memory_null_buffer() {
        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: -1,
                reg_mem: false,
                memref_null: false,
            },
        };
        let mut shm = raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 1024,
            flags: raw::TEEC_MEM_INPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                alloced_size: 0,
                shadow_buffer: ptr::null_mut(),
                registered_fd: -1,
                flags: 0,
            },
        };
        let res = TEEC_RegisterSharedMemory(&mut ctx, &mut shm);
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// TEEC_RequestCancellation 空指针健全性：不应崩溃。
    #[test]
    fn test_request_cancellation_null_operation() {
        TEEC_RequestCancellation(ptr::null_mut());
    }

    /// TEEC_RequestCancellation 未关联会话的操作：不应崩溃。
    #[test]
    fn test_request_cancellation_detached_operation() {
        let mut operation = raw::TEEC_Operation {
            started: 1,
            paramTypes: 0,
            params: [unsafe { std::mem::zeroed() }; 4],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };
        TEEC_RequestCancellation(&mut operation);
    }

    /// TEEC_InitializeContext 空指针健全性：空上下文应返回 BAD_PARAMETERS。
    #[test]
    fn test_initialize_context_null_ctx() {
        let res = TEEC_InitializeContext(ptr::null(), ptr::null_mut());
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// TEEC_InitializeContext 无真实 TEE 环境：初始化失败但不应崩溃。
    #[test]
    fn test_initialize_context_no_tee() {
        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: -1,
                reg_mem: false,
                memref_null: false,
            },
        };
        // 忽略返回值：无真实 TEE 环境时返回通信错误，重点是确保不崩溃
        let _ = TEEC_InitializeContext(ptr::null(), &mut ctx);
    }

    /// TEEC_OpenSession 全空指针健全性：应返回 BAD_PARAMETERS。
    #[test]
    fn test_open_session_null_args() {
        let res = TEEC_OpenSession(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            0,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// TEEC_OpenSession 空 destination：应返回 BAD_PARAMETERS 且不崩溃。
    #[test]
    fn test_open_session_null_destination() {
        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: -1,
                reg_mem: false,
                memref_null: false,
            },
        };
        let mut session = raw::TEEC_Session {
            imp: raw::TEEC_Session__Imp {
                ctx: ptr::null_mut(),
                session_id: 0,
            },
        };
        let res = TEEC_OpenSession(
            &mut ctx,
            &mut session,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// TEEC_CloseSession 空指针健全性：不应崩溃。
    #[test]
    fn test_close_session_null() {
        TEEC_CloseSession(ptr::null_mut());
    }

    /// TEEC_CloseSession 未初始化会话：不应崩溃，session_id 保持为 0。
    #[test]
    fn test_close_session_uninitialized() {
        let mut session = raw::TEEC_Session {
            imp: raw::TEEC_Session__Imp {
                ctx: ptr::null_mut(),
                session_id: 0,
            },
        };
        TEEC_CloseSession(&mut session);
        assert_eq!(session.imp.session_id, 0);
    }

    /// TEEC_FinalizeContext 空指针健全性：不应崩溃。
    #[test]
    fn test_finalize_context_null() {
        TEEC_FinalizeContext(ptr::null_mut());
    }

    /// TEEC_FinalizeContext 未初始化上下文（fd=-1）：应安全早退。
    #[test]
    fn test_finalize_context_uninitialized() {
        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: -1,
                reg_mem: false,
                memref_null: false,
            },
        };
        TEEC_FinalizeContext(&mut ctx);
    }

    /// TEEC_AllocateSharedMemory 空指针健全性：应返回 BAD_PARAMETERS。
    #[test]
    fn test_allocate_shared_memory_null_args() {
        let res = TEEC_AllocateSharedMemory(ptr::null_mut(), ptr::null_mut());
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// TEEC_AllocateSharedMemory 零大小分配：应返回 BAD_PARAMETERS。
    #[test]
    fn test_allocate_shared_memory_zero_size() {
        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: -1,
                reg_mem: false,
                memref_null: false,
            },
        };
        let mut shm = raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 0,
            flags: raw::TEEC_MEM_INPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                alloced_size: 0,
                shadow_buffer: ptr::null_mut(),
                registered_fd: -1,
                flags: 0,
            },
        };
        let res = TEEC_AllocateSharedMemory(&mut ctx, &mut shm);
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// TEEC_ReleaseSharedMemory 空指针健全性：不应崩溃。
    #[test]
    fn test_release_shared_memory_null() {
        TEEC_ReleaseSharedMemory(ptr::null_mut());
    }

    /// TEEC_ReleaseSharedMemory 未登记共享内存：应安全早退，不崩溃。
    #[test]
    fn test_release_shared_memory_unregistered() {
        let mut shm = raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 0,
            flags: 0,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                alloced_size: 0,
                shadow_buffer: ptr::null_mut(),
                registered_fd: -1,
                flags: 0,
            },
        };
        TEEC_ReleaseSharedMemory(&mut shm);
    }
}
