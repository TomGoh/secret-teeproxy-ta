// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Fuzz target: `teec_protocol::TEE_Request` 序列化 / 反序列化。
//!
//! 覆盖 `TEE_Request` 全部四个变体（OpenSession / CloseSession / InvokeCommand /
//! RequestCancellation）以及 `TEE_Parameters`（4 个参数 × 8 种参数类型）的
//! postcard 编解码路径——这是 rust-libteec 与 TEE OS 通信协议的核心数据面。
//!
//! 检验属性：
//! * 任意结构化请求均可序列化，且 `反序列化(序列化(x))` 后再次序列化字节完全一致
//!   （postcard round-trip 稳定）；
//! * 序列化输出被 `take_from_bytes` 完全消费（无剩余尾部字节）；
//! * 任意原始字节流反序列化 `TEE_Request`（模拟服务端收到任意请求流）不 panic。
//!
//! 输入处理遵循 Wfuzz 规范：用 `Unstructured` 按固定顺序消费字节流构造结构化
//! 输入，每个取值均以 `unwrap_or` 提供默认值，保证输入不足时 target 不 panic。

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use postcard::{take_from_bytes, to_allocvec};
use teec_protocol::{CaAuthInfo, TEE_Request};

#[path = "fuzz_common.rs"]
mod fuzz_common;

use fuzz_common::*;

/// uuid 字符串长度上界。
const MAX_UUID_LEN: usize = 64;

/// 从字节流构造任意 UTF-8 字符串（lossy 转换，保证不 panic）。
fn arbitrary_string(u: &mut Unstructured) -> String {
    let len = u.int_in_range(0..=MAX_UUID_LEN as u32).unwrap_or(0) as usize;
    let bytes = u.bytes(len).unwrap_or(&[]);
    String::from_utf8_lossy(bytes).into_owned()
}

/// 从字节流构造任意 `CaAuthInfo`（CA 认证信息）。
fn arbitrary_ca_auth_info(u: &mut Unstructured) -> CaAuthInfo {
    CaAuthInfo {
        ca_uuid: arbitrary_string(u),
        verified: bool::arbitrary(u).unwrap_or(false),
    }
}

/// 从字节流构造任意 `TEE_Request`（变体索引优先消费，保证各变体可复现覆盖）。
fn arbitrary_request(u: &mut Unstructured) -> TEE_Request {
    match u.int_in_range(0..=3).unwrap_or(0) {
        0 => TEE_Request::OpenSession {
            uuid: arbitrary_string(u),
            connection_method: u32::arbitrary(u).unwrap_or(0),
            params: arbitrary_params(u),
            ca_auth_info: if bool::arbitrary(u).unwrap_or(false) {
                Some(arbitrary_ca_auth_info(u))
            } else {
                None
            },
        },
        1 => TEE_Request::CloseSession {
            session_id: u32::arbitrary(u).unwrap_or(0),
        },
        2 => TEE_Request::InvokeCommand {
            session_id: u32::arbitrary(u).unwrap_or(0),
            cmd_id: u32::arbitrary(u).unwrap_or(0),
            params: arbitrary_params(u),
        },
        _ => TEE_Request::RequestCancellation {
            session_id: u32::arbitrary(u).unwrap_or(0),
        },
    }
}

/// postcard round-trip 属性：`ser(de(ser(x))) == ser(x)`，且无剩余字节。
fn check_roundtrip(req: &TEE_Request) {
    let bytes = to_allocvec(req).expect("任意结构化请求必须可序列化");
    let (req2, rest) = take_from_bytes::<TEE_Request>(&bytes).expect("序列化产物必须可反序列化");
    assert!(rest.is_empty(), "round-trip 后不得有剩余字节");
    let bytes2 = to_allocvec(&req2).expect("反序列化结果必须可再次序列化");
    assert_eq!(bytes, bytes2, "round-trip 序列化字节必须一致");
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // 1) 结构化输入 round-trip。
    let req = arbitrary_request(&mut u);
    check_roundtrip(&req);

    // 2) 原始字节流直接反序列化（模拟服务端解析任意请求流）：不得 panic。
    let _ = take_from_bytes::<TEE_Request>(data);
});
