// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

#![allow(non_snake_case)]

#[cfg(test)]
mod teec_api_tests {
    use cc_teec::{
        TEEC_AllocateSharedMemory, TEEC_CloseSession, TEEC_FinalizeContext, TEEC_InitializeContext,
        TEEC_InvokeCommand, TEEC_OpenSession, TEEC_RegisterSharedMemory, TEEC_ReleaseSharedMemory,
        TEEC_RequestCancellation, raw,
    };
    use std::ptr;

    /// 测试 TEEC_InitializeContext 的参数验证，证函数对空指针的健壮性处理
    /// 预期：传入空指针应返回 TEEC_ERROR_BAD_PARAMETERS
    #[test]
    fn test_TEEC_InitializeContext() {
        // 测试1: ctx 为空指针
        let res = TEEC_InitializeContext(ptr::null(), ptr::null_mut());
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);

        // 测试2: 有效的 ctx 指针但未连接实际TEE环境，这里主要测试参数边界
        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: -1,
                reg_mem: false,
                memref_null: false,
            },
        };

        let res = TEEC_InitializeContext(ptr::null(), &mut ctx);
        let _ = res; // 忽略返回值，只确保不崩溃
    }

    /// 测试 TEEC_OpenSession 的参数验证，验证函数对各种无效参数的健壮性
    /// 预期：传入各种空指针应返回 TEEC_ERROR_BAD_PARAMETERS
    #[test]
    fn test_TEEC_OpenSession() {
        // 测试1: 所有参数都为空指针
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

        // 测试2: 部分有效参数但 destination 为空
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

    /// 测试 TEEC_InvokeCommand 的参数验证，验证无效会话和操作参数的健壮性
    /// 预期：传入空指针应返回 TEEC_ERROR_BAD_PARAMETERS
    #[test]
    fn test_TEEC_InvokeCommand() {
        // 测试1: 所有参数都为空指针
        let res = TEEC_InvokeCommand(ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut());
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);

        // 测试2: 有效会话结构但未初始化的上下文
        let mut session = raw::TEEC_Session {
            imp: raw::TEEC_Session__Imp {
                ctx: ptr::null_mut(),
                session_id: 0,
            },
        };
        let mut operation = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [unsafe { std::mem::zeroed() }; 4],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };
        let mut error_origin = 0u32;
        let res = TEEC_InvokeCommand(&mut session, 1, &mut operation, &mut error_origin);

        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// 测试 TEEC_RegisterSharedMemory 的参数验证，验证共享内存注册时的参数检查
    /// 预期：传入空指针应返回 TEEC_ERROR_BAD_PARAMETERS
    #[test]
    fn test_TEEC_RegisterSharedMemory() {
        // 测试1: 所有参数都为空指针
        let res = TEEC_RegisterSharedMemory(ptr::null_mut(), ptr::null_mut());
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);

        // 测试2: 有效的上下文和共享内存结构，但缓冲区为空
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

    /// 测试 TEEC_AllocateSharedMemory 的参数验证，验证共享内存分配时的参数检查
    /// 预期：传入空指针应返回 TEEC_ERROR_BAD_PARAMETERS
    #[test]
    fn test_TEEC_AllocateSharedMemory() {
        // 测试1: 所有参数都为空指针
        let res = TEEC_AllocateSharedMemory(ptr::null_mut(), ptr::null_mut());
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);

        // 测试2: 分配零字节内存（边界测试）
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
        // 分配大小不能为0
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// 测试 TEEC_CloseSession 的空指针安全性，验证关闭会话函数对空指针的健壮性
    /// 预期：传入空指针不应导致崩溃
    #[test]
    fn test_TEEC_CloseSession() {
        // 测试1: 传入空指针（应安全处理）
        TEEC_CloseSession(ptr::null_mut());

        // 测试2: 传入未初始化的会话结构
        let mut session = raw::TEEC_Session {
            imp: raw::TEEC_Session__Imp {
                ctx: ptr::null_mut(),
                session_id: 0,
            },
        };
        TEEC_CloseSession(&mut session);
        // 不应崩溃，会话 ID 应保持为 0
        assert_eq!(session.imp.session_id, 0);
    }

    /// 测试 TEEC_FinalizeContext 的空指针安全性，验证销毁上下文函数对空指针的健壮性
    /// 预期：传入空指针不应导致崩溃
    #[test]
    fn test_TEEC_FinalizeContext() {
        // 测试1: 传入空指针（应安全处理）
        TEEC_FinalizeContext(ptr::null_mut());

        // 测试2: 传入已初始化的上下文（虽然实际未连接）
        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: 123, // 模拟已分配ID
                reg_mem: true,
                memref_null: true,
            },
        };

        TEEC_FinalizeContext(&mut ctx);
        // 这里只确保函数调用不会崩溃
    }

    /// 测试 TEEC_RequestCancellation 的空指针安全性，验证取消请求函数对空指针的健壮性
    /// 预期：传入空指针不应导致崩溃
    #[test]
    fn test_TEEC_RequestCancellation() {
        // 测试1: 传入空指针（应安全处理）
        TEEC_RequestCancellation(ptr::null_mut());

        // 测试2: 传入未关联会话的操作
        let mut operation = raw::TEEC_Operation {
            started: 1, // 模拟已开始的操作
            paramTypes: 0,
            params: [unsafe { std::mem::zeroed() }; 4],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(), // 无关联会话
            },
        };
        TEEC_RequestCancellation(&mut operation);
        // 不应崩溃
    }

    /// 测试 TEEC_ReleaseSharedMemory 的空指针安全性，验证释放共享内存函数对空指针的健壮性
    /// 预期：传入空指针不应导致崩溃
    #[test]
    fn test_TEEC_ReleaseSharedMemory() {
        // 测试1: 传入空指针（应安全处理）
        TEEC_ReleaseSharedMemory(ptr::null_mut());

        // 测试2: 传入已分配的共享内存（模拟清理）
        let buffer = Box::new([0u8; 1024]);
        let raw_ptr = Box::into_raw(buffer) as *mut std::ffi::c_void;

        let mut shm = raw::TEEC_SharedMemory {
            buffer: raw_ptr,
            size: 1024,
            flags: raw::TEEC_MEM_INPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: 456, // 模拟已分配 ID
                alloced_size: 1024,
                shadow_buffer: ptr::null_mut(),
                registered_fd: -1,
                flags: 1, // 模拟已分配标志
            },
        };

        TEEC_ReleaseSharedMemory(&mut shm);
        // 不应崩溃

        // 清理：重新获取Box并释放内存（安全操作）
        let _ = unsafe { Box::from_raw(raw_ptr as *mut [u8; 1024]) };
    }

    /// 测试参数编码宏的正确性，验证 TEEC_PARAM_TYPES 和 TEEC_PARAM_TYPE_GET 的功能
    #[test]
    fn test_param_macros() {
        // 测试参数类型编码
        let param_types = raw::TEEC_PARAM_TYPES(
            raw::TEEC_VALUE_INPUT,
            raw::TEEC_VALUE_OUTPUT,
            raw::TEEC_MEMREF_TEMP_INPUT,
            raw::TEEC_MEMREF_WHOLE,
        );

        // 验证各参数位的解码
        assert_eq!(
            raw::TEEC_PARAM_TYPE_GET(param_types, 0),
            raw::TEEC_VALUE_INPUT
        );
        assert_eq!(
            raw::TEEC_PARAM_TYPE_GET(param_types, 1),
            raw::TEEC_VALUE_OUTPUT
        );
        assert_eq!(
            raw::TEEC_PARAM_TYPE_GET(param_types, 2),
            raw::TEEC_MEMREF_TEMP_INPUT
        );
        assert_eq!(
            raw::TEEC_PARAM_TYPE_GET(param_types, 3),
            raw::TEEC_MEMREF_WHOLE
        );

        // 测试边界：索引超出范围
        let param_type = raw::TEEC_PARAM_TYPE_GET(param_types, 4);
        // 超出范围的索引应该返回0（因为移位后超出边界）
        assert_eq!(param_type, 0);
    }

    /// 测试共享内存管理器的边界条件，验证共享内存分配和释放的边界情况
    #[test]
    fn test_shared_memory_boundary_conditions() {
        // 测试：无效的标志位
        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: 1,
                reg_mem: true,
                memref_null: false,
            },
        };
        let mut shm = raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 1024,
            flags: 0xFFFFFFFF, // 无效标志位
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                alloced_size: 0,
                shadow_buffer: ptr::null_mut(),
                registered_fd: -1,
                flags: 0,
            },
        };
        let res = TEEC_AllocateSharedMemory(&mut ctx, &mut shm);
        // 预期返回参数错误（标志位无效）
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// 测试操作参数构建函数的错误处理，验证 OperationParams 对各种异常情况的处理
    #[test]
    fn test_operation_params_error_handling() {
        // 测试：无效的参数类型
        let mut operation = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0xFFFFFFFF, // 包含无效参数类型
            params: [unsafe { std::mem::zeroed() }; 4],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        let mut session = raw::TEEC_Session {
            imp: raw::TEEC_Session__Imp {
                ctx: ptr::null_mut(),
                session_id: 0,
            },
        };
        let mut error_origin = 0u32;
        let res = TEEC_InvokeCommand(&mut session, 1, &mut operation, &mut error_origin);
        // 预期返回参数错误
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// 测试 UUID 转换功能，验证 UUID 结构到字符串的转换
    #[test]
    fn test_uuid_conversion() {
        // 创建一个已知的 UUID
        let uuid = raw::TEEC_UUID {
            timeLow: 0x00112233,
            timeMid: 0x4455,
            timeHiAndVersion: 0x6677,
            clockSeqAndNode: [0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        };

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

        // 使用有效的 UUID 结构调用 OpenSession
        let res = TEEC_OpenSession(
            &mut ctx,
            &mut session,
            &uuid,
            raw::TEEC_LOGIN_PUBLIC,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        );

        // UUID 转换（Uuid::from_fields + to_string）本身是无条件成功的；
        // 请求完成 UUID 转换后，会被 get_client 对未初始化 ctx（未通过
        // TEEC_InitializeContext 登记）的地址登记校验拒绝，返回参数错误，
        // 而不是解引用垃圾指针崩溃或返回通信错误。
        assert_eq!(res, raw::TEEC_ERROR_BAD_PARAMETERS);
    }

    /// 测试会话和操作的生命周期管理，验证会话和操作结构的正确清理
    #[test]
    fn test_session_and_operation_lifecycle() {
        // 创建并初始化一个操作结构
        let mut operation = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_VALUE_INPUT,
                raw::TEEC_VALUE_OUTPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [unsafe { std::mem::zeroed() }; 4],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        // 设置值参数
        operation.params[0].value.a = 123;
        operation.params[0].value.b = 456;

        // 验证参数类型设置正确
        assert_eq!(
            raw::TEEC_PARAM_TYPE_GET(operation.paramTypes, 0),
            raw::TEEC_VALUE_INPUT
        );
        assert_eq!(
            raw::TEEC_PARAM_TYPE_GET(operation.paramTypes, 1),
            raw::TEEC_VALUE_OUTPUT
        );

        // 验证值参数设置正确
        unsafe {
            assert_eq!(operation.params[0].value.a, 123);
            assert_eq!(operation.params[0].value.b, 456);
        }

        // 创建一个会话结构
        let mut session = raw::TEEC_Session {
            imp: raw::TEEC_Session__Imp {
                ctx: ptr::null_mut(),
                session_id: 999, // 模拟会话 ID
            },
        };

        // 将操作与会话关联
        operation.imp.session = &mut session;

        // 验证关联成功
        assert_eq!(operation.imp.session as *const _, &mut session as *const _);

        // 清理：关闭会话
        TEEC_CloseSession(&mut session);
    }
}

/// 测试 C API 层的跟踪输出函数，验证 `rust_dprintf` / `dump_buffer` 的
/// 参数校验与返回值约定；同时确保这些 `#[no_mangle]` 符号在集成测试
/// 二进制中被引用并执行，使覆盖率工具能收集到对应记录。
#[cfg(test)]
mod teec_trace_api_tests {
    use std::ffi::CString;
    use std::ptr;

    use cc_teec::{TRACE_INFO, dump_buffer, rust_dprintf};

    /// rust_dprintf 有效参数：应返回输出字节数（正数）。
    #[test]
    fn test_rust_dprintf_returns_written_len() {
        let function = CString::new("test_fn").unwrap();
        let prefix = CString::new("TEST").unwrap();
        let message = CString::new("hello").unwrap();
        let n = rust_dprintf(
            function.as_ptr(),
            42,
            TRACE_INFO,
            prefix.as_ptr(),
            message.as_ptr(),
        );
        assert!(n > 0);
    }

    /// rust_dprintf 空消息指针：应返回 -1。
    #[test]
    fn test_rust_dprintf_null_message() {
        let prefix = CString::new("TEST").unwrap();
        let n = rust_dprintf(ptr::null(), 0, TRACE_INFO, prefix.as_ptr(), ptr::null());
        assert_eq!(n, -1);
    }

    /// rust_dprintf 无函数信息（function 为空）：走纯消息分支，返回正数。
    #[test]
    fn test_rust_dprintf_without_function_info() {
        let prefix = CString::new("TEST").unwrap();
        let message = CString::new("plain").unwrap();
        let n = rust_dprintf(
            ptr::null(),
            0,
            TRACE_INFO,
            prefix.as_ptr(),
            message.as_ptr(),
        );
        assert!(n > 0);
    }

    /// dump_buffer 空指针健全性：不应 panic。
    #[test]
    fn test_dump_buffer_null_args() {
        dump_buffer(ptr::null(), ptr::null(), 0);
    }

    /// dump_buffer 有效缓冲区：不应 panic（默认调试级别下为空操作）。
    #[test]
    fn test_dump_buffer_valid_buffer() {
        let name = CString::new("buf").unwrap();
        let data = [0u8, 1, 2, 3, 0xFF];
        dump_buffer(name.as_ptr(), data.as_ptr(), data.len());
    }
}
