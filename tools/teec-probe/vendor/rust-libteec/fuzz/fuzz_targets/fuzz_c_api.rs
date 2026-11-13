// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 KylinSoft Co., Ltd.

//! `TEEC_*` C ABI 入口的健壮性 fuzz。
//!
//! 直接调用 `cc_teec` 导出的 10 个 `extern "C"` 入口，覆盖 `src/teec/c_api.rs`
//! （错误码与错误来源回写、空指针早退、共享内存 FFI 转发）、`src/teec/context.rs`
//! 的登记校验分支，以及 `src/teec/session.rs` 的入口校验路径。
//!
//! 检验属性：
//! 1. 参数非法时任何入口都不得 panic，必须返回错误码（void 入口静默返回）。
//! 2. 空指针形态固定返回 `TEEC_ERROR_BAD_PARAMETERS`，且失败时
//!    `ret_origin`/`error_origin` 出参必被回写，取值只能是 `ErrorOrigin`
//!    的 5 个变体之一（API/COMMS/TEE/TA/UNKNOWN）。
//! 3. 未经 `ffi_initialize_context` 登记的上下文/会话永远不能成功；堆栈上
//!    伪造的上下文绝不能出现在登记表里。
//! 4. 注册/分配成功的共享内存必须可读回、可释放，且同轮释放（零泄漏）。
//!    register 路径必须逐字节拷贝源缓冲区。
//! 5. `ffi_register_shared_memory_fd` 恒为「未实现」。
//!
//! **刻意不做的调用**：绝不以非空上下文调用 `ffi_initialize_context`。
//! 该路径会进入 `CcClient::init()` 建立真实 vsock 连接并执行 ECDH/TLS 握手
//! （本机 CID 103:9999 确有服务在监听，connect 耗时 ~13ms），属于对外副作用
//! 且可能长时间阻塞，不适合放进 fuzz 循环。因此初始化只走空上下文这一形态
//! （`deref_mut` 失败 → BAD_PARAMETERS）。

#![no_main]

use std::ffi::{CString, c_void};
use std::mem;
use std::ptr;

use arbitrary::Arbitrary;
use cc_teec::fuzz::{
    ctx_is_registered, ctx_registered_id, ffi_allocate_shared_memory, ffi_close_session,
    ffi_finalize_context, ffi_initialize_context, ffi_invoke_command, ffi_open_session,
    ffi_register_shared_memory, ffi_register_shared_memory_fd, ffi_release_shared_memory,
    ffi_request_cancellation, shm_is_registered, shm_read_buffer,
};
use cc_teec::raw;
use libfuzzer_sys::fuzz_target;

/// 出参哨兵：失败调用必须覆盖它，未写入即说明回写路径被破坏。
const ORIGIN_SENTINEL: u32 = 0xDEAD_BEEF;

/// `ErrorOrigin` 的最大合法取值（`UNKNOWN` 无显式判别值，等于 `TA + 1`）。
const MAX_ERROR_ORIGIN: u32 = 5;

/// harness 自有缓冲区长度；共享内存的声明长度一律夹到它以内。
const BACKING_LEN: usize = 1 << 12;

#[derive(Debug, Arbitrary)]
struct Input {
    /// CA 名称字符串（库忽略其内容，但指针必须有效）。
    name: Vec<u8>,
    /// 伪造上下文的 fd 数值（负值对应「已终结」分支）。
    ctx_fd: i32,
    /// 会话 id。
    session_id: u32,
    /// 目标 UUID 的 16 个原始字节。
    uuid: [u8; 16],
    /// 连接方式（本实现忽略）。
    connection_method: u32,
    /// 命令 id。
    cmd_id: u32,
    /// 共享内存声明长度（会被夹到 `BACKING_LEN` 以内）。
    shm_size: u16,
    /// 共享内存方向标志的原始值。
    shm_flags: u8,
    /// true = 走 `ffi_register_shared_memory`，false = 走 `ffi_allocate_shared_memory`。
    shm_register: bool,
    /// true = 调用共享内存入口时把上下文指针置空。
    shm_null_ctx: bool,
}

/// 覆盖共享内存 `flags` 的五种形态：0（非法）、单向、双向、含非法位。
fn flags_of(bits: u8) -> u32 {
    match bits % 5 {
        0 => 0,
        1 => raw::TEEC_MEM_INPUT,
        2 => raw::TEEC_MEM_OUTPUT,
        3 => raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT,
        _ => raw::TEEC_MEM_INPUT | 0x8000_0000,
    }
}

fn uuid_of(bytes: [u8; 16]) -> raw::TEEC_UUID {
    raw::TEEC_UUID {
        timeLow: u32::from_ne_bytes(bytes[0..4].try_into().expect("4 字节")),
        timeMid: u16::from_ne_bytes(bytes[4..6].try_into().expect("2 字节")),
        timeHiAndVersion: u16::from_ne_bytes(bytes[6..8].try_into().expect("2 字节")),
        clockSeqAndNode: bytes[8..16].try_into().expect("8 字节"),
    }
}

fuzz_target!(|input: Input| {
    let name_bytes: Vec<u8> = input.name.iter().copied().filter(|b| *b != 0).collect();
    let name = CString::new(name_bytes).expect("已过滤 NUL 字节");

    // 1) 空指针形态：固定错误码，且出参必须被回写
    assert_eq!(
        ffi_initialize_context(ptr::null(), ptr::null_mut()),
        raw::TEEC_ERROR_BAD_PARAMETERS,
        "空上下文不得初始化成功"
    );
    assert_eq!(
        ffi_initialize_context(name.as_ptr(), ptr::null_mut()),
        raw::TEEC_ERROR_BAD_PARAMETERS,
        "带名称但空上下文仍须被拒绝"
    );

    // 空出参指针：不得崩溃（回写被跳过）。
    let _ = ffi_open_session(
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null(),
        0,
        ptr::null(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    let mut origin = ORIGIN_SENTINEL;
    assert_eq!(
        ffi_open_session(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            input.connection_method,
            ptr::null(),
            ptr::null_mut(),
            &mut origin,
        ),
        raw::TEEC_ERROR_BAD_PARAMETERS,
        "空上下文/会话/目标不得打开会话"
    );
    assert_ne!(
        origin, ORIGIN_SENTINEL,
        "OpenSession 失败必须回写 ret_origin"
    );

    let mut origin = ORIGIN_SENTINEL;
    assert_eq!(
        ffi_invoke_command(ptr::null_mut(), input.cmd_id, ptr::null_mut(), &mut origin),
        raw::TEEC_ERROR_BAD_PARAMETERS,
        "空会话不得调用命令"
    );
    assert_ne!(
        origin, ORIGIN_SENTINEL,
        "InvokeCommand 失败必须回写 error_origin"
    );

    assert_eq!(
        ffi_register_shared_memory(ptr::null_mut(), ptr::null_mut()),
        raw::TEEC_ERROR_BAD_PARAMETERS,
        "空指针不得注册共享内存"
    );
    assert_eq!(
        ffi_allocate_shared_memory(ptr::null_mut(), ptr::null_mut()),
        raw::TEEC_ERROR_BAD_PARAMETERS,
        "空指针不得分配共享内存"
    );
    assert_eq!(
        ffi_register_shared_memory_fd(ptr::null_mut(), ptr::null_mut(), input.ctx_fd),
        raw::TEEC_ERROR_NOT_IMPLEMENTED,
        "文件描述符注册恒为未实现"
    );
    ffi_release_shared_memory(ptr::null_mut());
    ffi_finalize_context(ptr::null_mut());
    ffi_close_session(ptr::null_mut());
    ffi_request_cancellation(ptr::null_mut());

    // 2) 未登记的上下文/会话：入口校验分支
    let mut ctx: raw::TEEC_Context = unsafe { mem::zeroed() };
    ctx.imp.fd = input.ctx_fd;
    let ctx_ptr: *mut raw::TEEC_Context = &mut ctx;

    let mut session: raw::TEEC_Session = unsafe { mem::zeroed() };
    session.imp.session_id = input.session_id;
    session.imp.ctx = ctx_ptr;
    let session_ptr: *mut raw::TEEC_Session = &mut session;

    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    let op_ptr: *mut raw::TEEC_Operation = &mut op;

    let dest = uuid_of(input.uuid);

    // 非空但未登记的上下文：OpenSession 会先校验 CA 签名、构建参数，
    // 最终因取不到通信客户端（未登记）而失败。
    let mut origin = ORIGIN_SENTINEL;
    let res = ffi_open_session(
        ctx_ptr,
        session_ptr,
        &dest,
        input.connection_method,
        ptr::null(),
        op_ptr,
        &mut origin,
    );
    assert_ne!(
        res,
        raw::TEEC_SUCCESS,
        "未登记上下文不得打开会话（res={res:#x}）"
    );
    assert_ne!(
        origin, ORIGIN_SENTINEL,
        "OpenSession 失败必须回写 ret_origin"
    );
    assert!(
        origin <= MAX_ERROR_ORIGIN,
        "ret_origin={origin:#x} 不是 ErrorOrigin 的合法变体"
    );

    ffi_close_session(session_ptr);
    let mut origin = ORIGIN_SENTINEL;
    assert_ne!(
        ffi_invoke_command(session_ptr, input.cmd_id, op_ptr, &mut origin),
        raw::TEEC_SUCCESS,
        "上下文未登记的会话不得调用命令"
    );
    assert_ne!(
        origin, ORIGIN_SENTINEL,
        "InvokeCommand 失败必须回写 error_origin"
    );
    assert!(
        origin <= MAX_ERROR_ORIGIN,
        "error_origin={origin:#x} 不是 ErrorOrigin 的合法变体"
    );

    // 取消请求：operation 未绑定会话 → 直接返回；绑定后会话上下文未登记 →
    // 记录警告后返回。两者都不得 panic。
    ffi_request_cancellation(op_ptr);
    op.imp.session = session_ptr;
    assert_eq!(
        op.imp.session, session_ptr,
        "绑定写入必须生效（否则后续路径不可信）"
    );
    ffi_request_cancellation(op_ptr);
    op.imp.session = ptr::null_mut();
    assert!(op.imp.session.is_null(), "会话绑定应可被清除");

    // 未登记的上下文：FinalizeContext 必须直接忽略（不得触碰登记表）。
    ffi_finalize_context(ctx_ptr);
    assert!(!ctx_is_registered(ctx_ptr), "伪造上下文不得进入登记表");
    assert_eq!(ctx_registered_id(ctx_ptr), None, "伪造上下文不得有登记 id");

    // 2b) 未连接会话（上下文为空）：close/invoke/取消 必须走早退分支
    let mut orphan: raw::TEEC_Session = unsafe { mem::zeroed() };
    orphan.imp.session_id = input.session_id;
    assert!(orphan.imp.ctx.is_null(), "初始上下文必须为空");
    let orphan_ptr: *mut raw::TEEC_Session = &mut orphan;

    ffi_close_session(orphan_ptr);
    let mut origin = ORIGIN_SENTINEL;
    assert_eq!(
        ffi_invoke_command(orphan_ptr, input.cmd_id, op_ptr, &mut origin),
        raw::TEEC_ERROR_BAD_PARAMETERS,
        "未连接会话调用命令必须返回参数错误"
    );
    assert_ne!(
        origin, ORIGIN_SENTINEL,
        "未连接会话调用失败必须回写 error_origin"
    );
    assert!(
        origin <= MAX_ERROR_ORIGIN,
        "error_origin={origin:#x} 不是 ErrorOrigin 的合法变体"
    );

    // 会话绑定到「上下文为空」的会话后取消：同样必须安静返回。
    op.imp.session = orphan_ptr;
    ffi_request_cancellation(op_ptr);
    op.imp.session = ptr::null_mut();
    assert!(op.imp.session.is_null(), "会话绑定应可被清除");

    // 3) 共享内存 FFI：分配/注册 → 读回 → 释放
    let mut backing = vec![0u8; BACKING_LEN];
    for (i, b) in backing.iter_mut().enumerate() {
        *b = (i as u8) ^ 0x5A;
    }
    let declared = (input.shm_size as usize) % (BACKING_LEN + 1);

    let mut shm: raw::TEEC_SharedMemory = unsafe { mem::zeroed() };
    shm.imp.id = -1; // 未登记句柄的规范取值
    shm.size = declared;
    shm.flags = flags_of(input.shm_flags);
    shm.buffer = if input.shm_register {
        backing.as_mut_ptr().cast::<c_void>()
    } else {
        ptr::null_mut()
    };

    let shm_ctx: *mut raw::TEEC_Context = if input.shm_null_ctx {
        ptr::null_mut()
    } else {
        ctx_ptr
    };
    let res = if input.shm_register {
        ffi_register_shared_memory(shm_ctx, &mut shm)
    } else {
        ffi_allocate_shared_memory(shm_ctx, &mut shm)
    };

    if res == raw::TEEC_SUCCESS {
        assert!(shm_is_registered(&shm), "分配成功即必须登记");
        assert_eq!(shm.size, declared, "分配成功后声明的长度应保持不变");
        let shadow = shm_read_buffer(&shm, 0, declared).expect("已登记区段必须可读回");
        assert_eq!(shadow.len(), declared, "读回长度应等于声明长度");
        if input.shm_register {
            assert_eq!(
                shadow,
                backing[..declared].to_vec(),
                "注册路径必须逐字节拷贝源缓冲区"
            );
        }
        ffi_release_shared_memory(&mut shm);
        assert!(!shm_is_registered(&shm), "释放后不得仍处于登记状态");
        // 幂等：句柄已被清零，再次释放应为 no-op。
        ffi_release_shared_memory(&mut shm);
    } else {
        assert_eq!(shm.imp.id, -1, "失败不得留下已登记的句柄");
        assert!(!shm_is_registered(&shm), "失败不得留下登记项");
    }
});
