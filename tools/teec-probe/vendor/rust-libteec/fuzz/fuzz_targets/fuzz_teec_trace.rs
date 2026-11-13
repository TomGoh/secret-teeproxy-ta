// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Fuzz target: `rust_dprintf` 和 `dump_buffer`。
//!
//! 这两个是 TEE 客户端库的日志输出函数，接受 C 字符串指针和原始缓冲区。
//! `rust_dprintf` 解析 C 字符串为 UTF-8 并格式化输出；`dump_buffer` 以
//! hex+ASCII 格式 dump 内存。两者均需安全处理空指针和无效 UTF-8。
//!
//! 检验属性：
//! * 任意字节流构造的 C 字符串传给 `rust_dprintf` 不 panic；
//! * 无效 UTF-8 字节构造的 C 字符串传给 `rust_dprintf` 不 panic；
//! * 空指针传给 `rust_dprintf` 安全返回；
//! * 任意字节缓冲区传给 `dump_buffer` 不 panic；
//! * 空指针 / 零长度传给 `dump_buffer` 不 panic。

#![no_main]

use std::ffi::CString;

use arbitrary::{Arbitrary, Unstructured};
use cc_teec::{dump_buffer, rust_dprintf};
use libfuzzer_sys::fuzz_target;

/// 日志级别常量（与 teec_trace 一致）。
const TRACE_ERROR: i32 = 1;
const TRACE_INFO: i32 = 2;
const TRACE_FLOW: i32 = 4;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // --- rust_dprintf 测试 ---

    // 1) 用字节流构造 function / prefix / message C 字符串（仅可打印 ASCII，
    //    避免日志输出噪声，同时覆盖任意长度组合）
    let func_bytes: Vec<u8> = {
        let len = u.int_in_range(0..=64usize).unwrap_or(0);
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            let b = u.int_in_range(0x20..=0x7Eu8).unwrap_or(b'x');
            v.push(b);
        }
        v
    };
    let prefix_bytes: Vec<u8> = {
        let len = u.int_in_range(0..=32usize).unwrap_or(0);
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            let b = u.int_in_range(0x20..=0x7Eu8).unwrap_or(b'p');
            v.push(b);
        }
        v
    };
    let msg_bytes: Vec<u8> = {
        let len = u.int_in_range(0..=128usize).unwrap_or(0);
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            let b = u.int_in_range(0x20..=0x7Eu8).unwrap_or(b'm');
            v.push(b);
        }
        v
    };

    let func_cstr = CString::new(func_bytes).unwrap_or_default();
    let prefix_cstr = CString::new(prefix_bytes).unwrap_or_default();
    let msg_cstr = CString::new(msg_bytes).unwrap_or_default();

    let level: i32 = u
        .int_in_range(TRACE_ERROR..=TRACE_FLOW)
        .unwrap_or(TRACE_INFO);
    let line: i32 = u.int_in_range(0..=1000).unwrap_or(0);

    // 正常调用
    let _ = rust_dprintf(
        func_cstr.as_ptr(),
        line,
        level,
        prefix_cstr.as_ptr(),
        msg_cstr.as_ptr(),
    );

    // function 为 null
    let _ = rust_dprintf(
        std::ptr::null(),
        line,
        level,
        prefix_cstr.as_ptr(),
        msg_cstr.as_ptr(),
    );

    // prefix 为 null
    let _ = rust_dprintf(
        func_cstr.as_ptr(),
        line,
        level,
        std::ptr::null(),
        msg_cstr.as_ptr(),
    );

    // message 为 null
    let _ = rust_dprintf(
        func_cstr.as_ptr(),
        line,
        level,
        prefix_cstr.as_ptr(),
        std::ptr::null(),
    );

    // 全部为 null
    let _ = rust_dprintf(
        std::ptr::null(),
        0,
        TRACE_ERROR,
        std::ptr::null(),
        std::ptr::null(),
    );

    // line <= 0 的分支
    let _ = rust_dprintf(
        func_cstr.as_ptr(),
        -1,
        level,
        prefix_cstr.as_ptr(),
        msg_cstr.as_ptr(),
    );

    // 2) 无效 UTF-8 测试：构造包含非 UTF-8 字节的 C 字符串
    let invalid_utf8_len = u.int_in_range(1..=32usize).unwrap_or(1);
    let mut invalid_bytes = Vec::with_capacity(invalid_utf8_len + 1);
    for _ in 0..invalid_utf8_len {
        let b = u8::arbitrary(&mut u).unwrap_or(0xFF);
        invalid_bytes.push(b);
    }
    // 确保至少包含一个非 UTF-8 字节
    invalid_bytes.push(0xFF);
    // 过滤内部 NUL 并添加 NUL 终止符
    let invalid_no_nul: Vec<u8> = invalid_bytes.iter().filter(|&&b| b != 0).copied().collect();
    let invalid_cstr = CString::new(invalid_no_nul.clone()).unwrap_or_default();

    let result = rust_dprintf(
        func_cstr.as_ptr(),
        line,
        level,
        prefix_cstr.as_ptr(),
        invalid_cstr.as_ptr(),
    );
    // 无效 UTF-8 的 message 应使 rust_dprintf 返回 -1
    // （invalid_no_nul 必含 0xFF 且不含 NUL，条件恒真，无需再判断）
    assert_eq!(result, -1, "无效 UTF-8 的 message 应返回 -1");

    // 也可以直接用 c 字符串字面量构造不含 NUL 的非法 UTF-8 CStr
    let bad_cstr = c"valid\xFFpart";
    let _ = rust_dprintf(
        func_cstr.as_ptr(),
        line,
        level,
        prefix_cstr.as_ptr(),
        bad_cstr.as_ptr(),
    );

    // --- dump_buffer 测试 ---

    let buf_len: usize = u.int_in_range(0..=256usize).unwrap_or(0);
    let mut buf = Vec::with_capacity(buf_len);
    for _ in 0..buf_len {
        buf.push(u8::arbitrary(&mut u).unwrap_or(0));
    }

    let name_cstr = CString::new("fuzz_buf").unwrap_or_default();

    // 正常调用
    dump_buffer(name_cstr.as_ptr(), buf.as_ptr(), buf.len());

    // 空缓冲区
    dump_buffer(name_cstr.as_ptr(), std::ptr::null(), 0);

    // name 为 null
    dump_buffer(std::ptr::null(), buf.as_ptr(), buf.len());

    // 全部为 null / 零
    dump_buffer(std::ptr::null(), std::ptr::null(), 0);
});
