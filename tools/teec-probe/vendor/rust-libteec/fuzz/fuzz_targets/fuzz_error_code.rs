// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Fuzz target: `ErrorKind` / `ErrorOrigin` 错误码映射与错误格式化。
//!
//! `ErrorKind::from`（`num_enum::FromPrimitive`）与 `Error::from_raw_error`
//! 是所有 TEE API 返回值 → Rust 错误类型的必经路径；`message()` 的 `as_str()`
//! match 覆盖全部 20 个错误分支。错误码来自 TEE OS / 对端，属于不可信输入。
//!
//! 检验属性：
//! * 任意 u32 错误码转换为 `ErrorKind` / `ErrorOrigin` 不 panic；
//! * `Error::from_raw_error(code).kind()` 与直接转换一致；
//! * `message()`、`raw_code()`、Debug / Display 格式化不 panic；
//! * 已注册错误码的 `raw_code()` 往返一致（未知码映射到 Unknown 后不保证相等）；
//! * 全部 20 个已注册 ErrorKind 变体的 `as_str()` 分支均被执行。

#![no_main]

use arbitrary::Unstructured;
use cc_teec::raw;
use cc_teec::{Error, ErrorKind, ErrorOrigin};
use libfuzzer_sys::fuzz_target;

/// 所有已注册 ErrorKind 的原始错误码。
const REGISTERED_ERROR_CODES: &[u32] = &[
    raw::TEEC_ERROR_GENERIC,
    raw::TEEC_ERROR_ACCESS_DENIED,
    raw::TEEC_ERROR_CANCEL,
    raw::TEEC_ERROR_ACCESS_CONFLICT,
    raw::TEEC_ERROR_EXCESS_DATA,
    raw::TEEC_ERROR_BAD_FORMAT,
    raw::TEEC_ERROR_BAD_PARAMETERS,
    raw::TEEC_ERROR_BAD_STATE,
    raw::TEEC_ERROR_ITEM_NOT_FOUND,
    raw::TEEC_ERROR_NOT_IMPLEMENTED,
    raw::TEEC_ERROR_NOT_SUPPORTED,
    raw::TEEC_ERROR_NO_DATA,
    raw::TEEC_ERROR_OUT_OF_MEMORY,
    raw::TEEC_ERROR_BUSY,
    raw::TEEC_ERROR_COMMUNICATION,
    raw::TEEC_ERROR_SECURITY,
    raw::TEEC_ERROR_SHORT_BUFFER,
    raw::TEEC_ERROR_EXTERNAL_CANCEL,
    raw::TEEC_ERROR_TARGET_DEAD,
];

/// 所有已注册 ErrorOrigin 的原始错误码。
const REGISTERED_ORIGIN_CODES: &[u32] = &[
    raw::TEEC_ORIGIN_API,
    raw::TEEC_ORIGIN_COMMS,
    raw::TEEC_ORIGIN_TEE,
    raw::TEEC_ORIGIN_TRUSTED_APP,
];

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let code: u32 = u.arbitrary().unwrap_or(0);

    let kind = ErrorKind::from(code);
    let e = Error::from_raw_error(code);
    assert_eq!(e.kind(), kind, "from_raw_error 与 ErrorKind::from 必须一致");
    let _msg = e.message();
    let raw_code = e.raw_code();
    let _ = format!("{e}");
    let _ = format!("{e:?}");

    match kind {
        ErrorKind::Unknown => {}
        _ => assert_eq!(
            raw_code, code,
            "已注册错误码 0x{code:x} 的 raw_code() 往返必须一致"
        ),
    }

    let origin = ErrorOrigin::from(code);
    let _origin_back = u32::from(origin);

    // 穷举全部已注册 ErrorKind，覆盖 as_str 的全部 match 分支
    for &c in REGISTERED_ERROR_CODES {
        let k = ErrorKind::from(c);
        let err = Error::from_raw_error(c);
        assert_ne!(k, ErrorKind::Unknown, "已注册码 0x{c:x} 不应映射到 Unknown");
        assert_eq!(err.raw_code(), c, "已注册码 0x{c:x} raw_code 往返一致");
        let msg = err.message();
        assert!(!msg.is_empty(), "as_str() 不应返回空字符串");
        let _ = format!("{err}");
        let _ = format!("{err:?}");

        let err_with_origin = Error::new(k).with_origin(ErrorOrigin::API);
        assert_eq!(err_with_origin.origin(), Some(ErrorOrigin::API));
        let _ = format!("{err_with_origin}");
        let _ = format!("{err_with_origin:?}");
    }

    let unknown = Error::from_raw_error(0xDEAD_BEEF);
    assert_eq!(unknown.kind(), ErrorKind::Unknown);
    let _ = unknown.message();

    for &c in REGISTERED_ORIGIN_CODES {
        let o = ErrorOrigin::from(c);
        assert_ne!(
            o,
            ErrorOrigin::UNKNOWN,
            "已注册来源码 0x{c:x} 不应映射到 UNKNOWN"
        );
        assert_eq!(u32::from(o), c, "已注册来源码 0x{c:x} 往返一致");
    }
    let unknown_origin = ErrorOrigin::from(0xFF);
    assert_eq!(unknown_origin, ErrorOrigin::UNKNOWN);
});
