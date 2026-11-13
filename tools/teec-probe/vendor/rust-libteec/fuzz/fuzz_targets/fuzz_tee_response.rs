// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Fuzz target: `teec_protocol::TEE_Response` 反序列化 / 序列化。
//!
//! 这是 rust-libteec 中最贴近真实数据面的解析路径：响应字节流来自服务端，
//! 经 `postcard::take_from_bytes::<TEE_Response>` 解析。服务端响应内容由远端
//! TEE OS 控制，属于不可信输入，必须对任意字节流安全。
//!
//! 检验属性：
//! * 任意原始字节流反序列化 `TEE_Response` 不 panic（Ok / Err 均可接受）；
//! * 反序列化成功的结果必须能再次序列化，且 round-trip 字节一致；
//! * 结构化构造的响应（全部四个变体 × 参数类型组合）round-trip 稳定。

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use postcard::{take_from_bytes, to_allocvec};
use teec_protocol::TEE_Response;

#[path = "fuzz_common.rs"]
mod fuzz_common;

use fuzz_common::*;

fn arbitrary_response(u: &mut Unstructured) -> TEE_Response {
    match u.int_in_range(0..=3).unwrap_or(0) {
        0 => TEE_Response::OpenSession {
            session_id: u32::arbitrary(u).unwrap_or(0),
            result: u32::arbitrary(u).unwrap_or(0),
        },
        1 => TEE_Response::CloseSession {
            result: u32::arbitrary(u).unwrap_or(0),
        },
        2 => TEE_Response::InvokeCommand {
            params: arbitrary_params(u),
            result: u32::arbitrary(u).unwrap_or(0),
        },
        _ => TEE_Response::RequestCancellation {
            result: u32::arbitrary(u).unwrap_or(0),
        },
    }
}

fuzz_target!(|data: &[u8]| {
    // 1) 任意字节流直接反序列化（模拟收到服务端响应）：不得 panic。
    if let Ok((resp, _rest)) = take_from_bytes::<TEE_Response>(data) {
        let bytes = to_allocvec(&resp).expect("反序列化结果必须可序列化");
        let (resp2, rest2) =
            take_from_bytes::<TEE_Response>(&bytes).expect("round-trip 反序列化必须成功");
        assert!(rest2.is_empty(), "序列化产物必须被完全消费");
        let bytes2 = to_allocvec(&resp2).expect("二次序列化必须成功");
        assert_eq!(bytes, bytes2, "round-trip 序列化字节必须一致");
    }

    // 2) 结构化输入 round-trip（覆盖全部变体与参数类型组合）。
    let mut u = Unstructured::new(data);
    let resp = arbitrary_response(&mut u);
    let bytes = to_allocvec(&resp).expect("任意结构化响应必须可序列化");
    let (resp2, rest) = take_from_bytes::<TEE_Response>(&bytes).expect("序列化产物必须可反序列化");
    assert!(rest.is_empty());
    let bytes2 = to_allocvec(&resp2).expect("反序列化结果必须可再次序列化");
    assert_eq!(bytes, bytes2, "round-trip 序列化字节必须一致");
});
