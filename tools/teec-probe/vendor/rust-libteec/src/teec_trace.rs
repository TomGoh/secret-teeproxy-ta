// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! TEE 日志跟踪模块。
//!
//! 提供 C FFI 兼容的日志输出功能，包括：
//! - [`rust_dprintf`]：格式化日志输出（级别/线程ID/函数名/行号/消息）
//! - [`dump_buffer`]：十六进制内存 dump（类似 hexdump -C）
//! - 4 个日志级别常量：[`TRACE_ERROR`]、[`TRACE_INFO`]、[`TRACE_DEBUG`]、[`TRACE_FLOW`]

use std::ffi::{CStr, c_char, c_int};

use libc::size_t;

/// 错误级别日志，用于报告严重错误。
pub const TRACE_ERROR: c_int = 1;
/// 信息级别日志，用于报告一般性运行信息。
pub const TRACE_INFO: c_int = 2;
/// 调试级别日志，用于输出详细的调试信息。
pub const TRACE_DEBUG: c_int = 3;
/// 流程级别日志，用于跟踪函数进出等执行流程。
pub const TRACE_FLOW: c_int = 4;

/// 获取当前线程的系统线程 ID（通过 `SYS_gettid` 系统调用）。
///
/// 用于日志输出中的线程标识，便于多线程调试。
fn get_thread_id() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

/// 判断字节是否为可打印ASCII字符（32-126）
#[allow(dead_code)]
fn is_printable_ascii(byte: u8) -> bool {
    (32..=126).contains(&byte)
}

/// 将日志级别常量转换为对应的字符串表示。
///
/// - `TRACE_ERROR` → `"ERR"`
/// - `TRACE_INFO`  → `"INF"`
/// - `TRACE_DEBUG` → `"DBG"`
/// - `TRACE_FLOW`  → `"FLW"`
/// - 其他值        → `""`
fn get_level_string(level: c_int) -> &'static str {
    match level {
        TRACE_ERROR => "ERR",
        TRACE_INFO => "INF",
        TRACE_DEBUG => "DBG",
        TRACE_FLOW => "FLW",
        _ => "",
    }
}

// 说明：当前只输出到标准输出，不支持通过环境变量指定日志文件
// （TEEC_LOG_FILE 未实现）；如需落盘请在调用方重定向。

/// 格式化输出日志信息到标准输出，格式为:
/// 级别 \[线程ID\] 前缀:函数名:行号: 消息
///
/// # 参数
/// - function: 函数名（可为null）
/// - line: 行号（<=0时忽略函数信息）
/// - level: 日志级别
/// - prefix: 模块前缀
/// - message: 日志消息
///
/// # 返回值
/// - 成功时返回输出的字节数，失败时返回-1
#[expect(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_dprintf(
    function: *const c_char,
    line: c_int,
    level: c_int,
    prefix: *const c_char,
    message: *const c_char,
) -> c_int {
    if prefix.is_null() || message.is_null() {
        return -1;
    }

    let msg = {
        // SAFETY: 已经检查 message 不为空
        let c_str = unsafe { CStr::from_ptr(message) };
        match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let output = if !function.is_null() && line > 0 {
        // SAFETY: 已经检查 function 不为空
        // 使用 unwrap_or 提供有意义的默认值，避免静默失败
        let function_str = unsafe { CStr::from_ptr(function) }
            .to_str()
            .unwrap_or("<invalid_utf8>");

        // SAFETY: 已经检查 prefix 不为空
        let prefix_str = unsafe { CStr::from_ptr(prefix) }
            .to_str()
            .unwrap_or("<invalid_utf8>");
        let thread_id = get_thread_id();
        let level_str = get_level_string(level);

        format!("{level_str} [{thread_id}] {prefix_str}:{function_str}:{line}: {msg}\n")
    } else {
        format!("{msg}\n")
    };

    print!("{output}");

    output.len() as c_int
}

/// 十六进制dump函数，用于调试级别3和4
///
/// 以十六进制和 ASCII 形式输出内存缓冲区内容，格式类似 hexdump -C
/// 每行显示 16 字节，左侧为十六进制，右侧为可打印 ASCII 字符
///
/// # 参数
/// - bname: 缓冲区名称，显示在输出开头
/// - buffer: 待dump的内存缓冲区起始地址
/// - blen: 缓冲区长度
#[cfg(any(feature = "debug_level_3", feature = "debug_level_4"))]
#[expect(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn dump_buffer(bname: *const c_char, buffer: *const u8, blen: size_t) {
    if bname.is_null() || buffer.is_null() || blen == 0 {
        return;
    }

    // SAFETY: 已经检查 bname 不为空
    // 使用 unwrap_or 提供有意义的默认值，便于识别编码问题
    let bname_str = unsafe { CStr::from_ptr(bname) }
        .to_str()
        .unwrap_or("<invalid_utf8>");

    eprintln!("#### {bname_str}");

    // SAFETY: 创建缓冲区切片，已经检查 buffer 不为空且 blen 指定了有效长度
    let buffer_slice = unsafe { std::slice::from_raw_parts(buffer, blen) };
    let mut offset = 0;

    while offset < buffer_slice.len() {
        // 打印十六进制部分（每字节两位十六进制数）
        for i in 0..16 {
            if offset + i < buffer_slice.len() {
                eprint!("{:02x} ", buffer_slice[offset + i]);
            } else {
                eprint!("   "); // 填充空格保持对齐
            }

            if i == 7 {
                eprint!(" "); // 在8字节后添加额外空格
            }
        }

        eprint!(" |");

        // 打印 ASCII
        for i in 0..16 {
            if offset + i < buffer_slice.len() {
                let byte = buffer_slice[offset + i];
                if is_printable_ascii(byte) {
                    eprint!("{}", byte as char);
                } else {
                    eprint!("."); // 不可打印字符显示为.
                }
            }
        }

        eprintln!("|");

        offset += 16;
    }
}

/// dump_buffer 的空实现，用于未启用调试特性时
///
/// 保持相同的函数签名但函数体为空，避免链接错误
#[cfg(not(any(feature = "debug_level_3", feature = "debug_level_4")))]
#[unsafe(no_mangle)]
pub extern "C" fn dump_buffer(_bname: *const c_char, _buffer: *const u8, _blen: size_t) {
    // 空操作，仅在启用 debug_level_3 或 debug_level_4 时才有实际功能
}

#[cfg(test)]
mod teec_trace_tests {
    use super::*;
    use std::ffi::CString;

    fn make_c_string_with_ptr(s: &str) -> (CString, *const c_char) {
        let cstr = CString::new(s).expect("Failed to create CString");
        let ptr = cstr.as_ptr();
        (cstr, ptr)
    }

    #[test]
    fn test_is_printable_ascii() {
        // 测试各种边界情况
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b'z'));
        assert!(is_printable_ascii(b' '));
        assert!(is_printable_ascii(b'~'));

        assert!(!is_printable_ascii(0));
        assert!(!is_printable_ascii(31));
        assert!(!is_printable_ascii(127));
        assert!(!is_printable_ascii(128));
        assert!(!is_printable_ascii(255));
    }

    #[test]
    fn test_get_level_string() {
        // 测试所有预定义的日志级别
        assert_eq!(get_level_string(TRACE_ERROR), "ERR");
        assert_eq!(get_level_string(TRACE_INFO), "INF");
        assert_eq!(get_level_string(TRACE_DEBUG), "DBG");
        assert_eq!(get_level_string(TRACE_FLOW), "FLW");
        assert_eq!(get_level_string(0), ""); // 未知级别
        assert_eq!(get_level_string(999), ""); // 无效级别
    }

    #[test]
    fn test_rust_dprintf_valid_input() {
        let function = Some("test_function");
        let line = 42;
        let level = TRACE_INFO;
        let prefix = "mylib";
        let message = "This is a test message";

        let (_function_cstr, function_ptr) = if let Some(func) = function {
            make_c_string_with_ptr(func)
        } else {
            // 空字符串永远不会失败，使用 expect 提供清晰的错误信息
            let cstr = CString::new("").expect("Empty string should always create CString");
            (cstr, std::ptr::null())
        };

        let (_prefix_cstr, prefix_ptr) = make_c_string_with_ptr(prefix);
        let (_message_cstr, message_ptr) = make_c_string_with_ptr(message);

        let result = rust_dprintf(function_ptr, line, level, prefix_ptr, message_ptr);

        assert!(result > 0);
    }

    #[test]
    fn test_rust_dprintf_different_levels() {
        for (level, _expected_prefix) in [
            (TRACE_ERROR, "ERR"),
            (TRACE_INFO, "INF"),
            (TRACE_DEBUG, "DBG"),
            (TRACE_FLOW, "FLW"),
        ] {
            let function = Some("func");
            let line = 1;

            let (_function_cstr, function_ptr) = if let Some(func) = function {
                make_c_string_with_ptr(func)
            } else {
                // 空字符串永远不会失败，使用 expect 提供清晰的错误信息
                let cstr = CString::new("").expect("Empty string should always create CString");
                (cstr, std::ptr::null())
            };

            let (_prefix_cstr, prefix_ptr) = make_c_string_with_ptr("prefix");
            let (_message_cstr, message_ptr) = make_c_string_with_ptr("message");

            let result = rust_dprintf(function_ptr, line, level, prefix_ptr, message_ptr);

            assert!(result > 0);
        }
    }

    #[test]
    fn test_rust_dprintf_no_function_info() {
        let level = TRACE_INFO;
        let prefix = "prefix";
        let message = "simple message";

        let (_prefix_cstr, prefix_ptr) = make_c_string_with_ptr(prefix);
        let (_message_cstr, message_ptr) = make_c_string_with_ptr(message);

        let result = rust_dprintf(std::ptr::null(), 0, level, prefix_ptr, message_ptr);

        // 当 function 为 null 时，输出格式应该只有消息和换行
        // 返回值应该是消息长度加换行符
        assert_eq!(result, (message.len() + 1) as i32); // +1 为换行符
    }

    #[test]
    fn test_rust_dprintf_null_pointers() {
        // 测试空指针处理
        let (_prefix_cstr, prefix_ptr) = make_c_string_with_ptr("prefix");
        let result = rust_dprintf(
            std::ptr::null(),
            0,
            TRACE_INFO,
            prefix_ptr,
            std::ptr::null(),
        );
        assert_eq!(result, -1);

        let (_message_cstr, message_ptr) = make_c_string_with_ptr("message");
        let result = rust_dprintf(
            std::ptr::null(),
            0,
            TRACE_INFO,
            std::ptr::null(),
            message_ptr,
        );
        assert_eq!(result, -1);

        let result = rust_dprintf(
            std::ptr::null(),
            0,
            TRACE_INFO,
            std::ptr::null(),
            std::ptr::null(),
        );
        assert_eq!(result, -1);
    }

    #[test]
    fn test_rust_dprintf_invalid_utf8() {
        // 测试无效 UTF-8 输入的处理
        let invalid_utf8 = b"valid\xFFpart\0";
        let cstr = unsafe { CStr::from_bytes_with_nul_unchecked(invalid_utf8) };
        let ptr = cstr.as_ptr();

        let (_prefix_cstr, prefix_ptr) = make_c_string_with_ptr("prefix");
        let result = rust_dprintf(std::ptr::null(), 0, TRACE_INFO, prefix_ptr, ptr);

        // 应该返回 -1，因为 UTF-8 转换失败
        assert_eq!(result, -1);
    }

    #[test]
    fn test_thread_id_positive() {
        // 线程 ID 应该是正数
        let thread_id = get_thread_id();
        assert!(thread_id > 0);
    }

    #[test]
    fn test_integration_style() {
        // 模拟实际使用场景
        let test_cases = vec![
            (
                Some("connect"),
                101,
                TRACE_ERROR,
                "network",
                "Connection failed",
            ),
            (
                Some("process"),
                205,
                TRACE_INFO,
                "worker",
                "Processing item",
            ),
            (
                Some("validate"),
                42,
                TRACE_DEBUG,
                "parser",
                "Validating input",
            ),
            (Some("loop"), 15, TRACE_FLOW, "main", "Iteration complete"),
        ];

        for (func, line, level, prefix, msg) in test_cases {
            let (_function_cstr, function_ptr) = if let Some(f) = func {
                make_c_string_with_ptr(f)
            } else {
                // 空字符串永远不会失败，使用 expect 提供清晰的错误信息
                let cstr = CString::new("").expect("Empty string should always create CString");
                (cstr, std::ptr::null())
            };

            let (_prefix_cstr, prefix_ptr) = make_c_string_with_ptr(prefix);
            let (_message_cstr, message_ptr) = make_c_string_with_ptr(msg);

            let result = rust_dprintf(function_ptr, line, level, prefix_ptr, message_ptr);

            // 基本验证：函数应成功执行
            assert!(
                result > 0,
                "Failed for case: {:?}",
                (func, line, level, prefix, msg)
            );
        }
    }

    #[test]
    fn test_performance_no_panics() {
        // 确保多次调用不会 panic
        let (_prefix_cstr, prefix_ptr) = make_c_string_with_ptr("perf");
        let (_message_cstr, message_ptr) = make_c_string_with_ptr("test");

        for _ in 0..1000 {
            let result = rust_dprintf(std::ptr::null(), 0, TRACE_INFO, prefix_ptr, message_ptr);
            assert!(result >= 0);
        }
    }

    // 测试 dump_buffer 的条件编译
    #[test]
    fn test_dump_buffer_exists() {
        // 验证dump_buffer函数存在且可调用
        let buffer = b"Hello, World!";
        let (_name_cstr, name_ptr) = make_c_string_with_ptr("test_buffer");

        // 安全调用，只是验证接口存在
        dump_buffer(name_ptr, buffer.as_ptr(), buffer.len());

        // 测试空指针和零长度
        dump_buffer(std::ptr::null(), std::ptr::null(), 0);
        dump_buffer(name_ptr, std::ptr::null(), 10);
        dump_buffer(std::ptr::null(), buffer.as_ptr(), buffer.len());
    }

    #[test]
    fn test_dump_buffer_edge_cases() {
        // 测试 dump_buffer 的边界情况
        let buffer: [u8; 0] = [];
        let (_name_cstr, name_ptr) = make_c_string_with_ptr("empty");

        dump_buffer(name_ptr, buffer.as_ptr(), buffer.len());

        let small_buffer = b"short";
        let (_name2_cstr, name2_ptr) = make_c_string_with_ptr("small");

        dump_buffer(name2_ptr, small_buffer.as_ptr(), small_buffer.len());

        let non_printable = [0u8, 1, 2, 3, 128, 255, 10, 13];
        let (_name3_cstr, name3_ptr) = make_c_string_with_ptr("non_printable");

        dump_buffer(name3_ptr, non_printable.as_ptr(), non_printable.len());
    }
}

#[cfg(all(test, any(feature = "debug_level_3", feature = "debug_level_4")))]
mod dump_buffer_tests {
    use super::*;
    use std::ffi::CString;

    // 测试辅助函数
    fn make_c_string_with_ptr(s: &str) -> (CString, *const c_char) {
        let cstr = CString::new(s).expect("Failed to create CString");
        let ptr = cstr.as_ptr();
        (cstr, ptr)
    }

    #[test]
    fn test_dump_buffer_output() {
        // 测试实际的dump_buffer输出格式（仅在启用相关特性时）
        let buffer = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%";
        let (_name_cstr, name_ptr) = make_c_string_with_ptr("hex_dump_test");

        // 这个测试主要确保函数不 panic
        dump_buffer(name_ptr, buffer.as_ptr(), buffer.len());
    }

    #[test]
    fn test_dump_buffer_exact_format() {
        // 测试精确的格式输出
        let buffer = vec![
            // 第一行：可打印ASCII
            b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D',
            b'E', b'F', // 第二行：混合内容
            0x00, 0x7F, 0x80, 0xFF, 32, 126, 10, 13, 255, 1, 2, 3, b'X', b'Y', b'Z', 0,
        ];

        let (_name_cstr, name_ptr) = make_c_string_with_ptr("exact_format_test");

        // 这个测试主要确保函数不 panic
        dump_buffer(name_ptr, buffer.as_ptr(), buffer.len());
    }
}
