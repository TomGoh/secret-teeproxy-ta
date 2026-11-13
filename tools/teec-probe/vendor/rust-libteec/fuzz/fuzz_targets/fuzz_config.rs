// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Fuzz target: 配置确定性与 PSK 协商协议解析全路径。
//!
//! 检验属性：
//! * `get_psk_identity()` 非空且每次一致；
//! * 任意字符串解析为 u32 不 panic，合法数字一致，失败回退默认值；
//! * 真实 `get_vsock_cid`/`get_vsock_port` 调用不 panic；
//! * `parse_ecdh_response` 对任意字节流不 panic（Ok/Err 均可接受）；
//! * `build_ecdh_response` → `parse_ecdh_response` round-trip 字段一致；
//! * `derive_psk` 确定性：相同输入派生相同 32 字节 PSK。

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use cc_teec::fuzz::{get_vsock_cid, get_vsock_port};
use libfuzzer_sys::fuzz_target;
use xtee_psk::constants::{PSK_LEN, SM2_POINT_LEN, get_psk_identity};
use xtee_psk::ecdh::derive_psk;
use xtee_psk::protocol::{build_ecdh_response, parse_ecdh_response};

const DEFAULT_VSOCK_SERVER_CID: u32 = 103;
const DEFAULT_VSOCK_PORT: u32 = 9999;

/// 复刻 `vsock_define` 的 `s.parse().ok().unwrap_or(default)` 解析逻辑。
fn parse_or_default(s: &str, default: u32) -> u32 {
    s.parse().ok().unwrap_or(default)
}

/// 从字节流构造定长数组（长度不足补零，保证 EC point 长度约束）。
fn fixed_array<const N: usize>(u: &mut Unstructured) -> [u8; N] {
    let mut out = [0u8; N];
    for slot in out.iter_mut() {
        *slot = u8::arbitrary(u).unwrap_or(0);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // PSK identity 确定性
    let identity = get_psk_identity();
    assert!(!identity.is_empty(), "PSK identity 不能为空");
    let rounds = u.int_in_range(1..=4usize).unwrap_or(1);
    for _ in 0..rounds {
        assert_eq!(
            get_psk_identity(),
            identity,
            "get_psk_identity 必须每次返回相同值"
        );
    }

    // VSOCK 配置解析（复刻解析逻辑）
    let str_len = u.int_in_range(0..=64usize).unwrap_or(0);
    let mut str_bytes = Vec::with_capacity(str_len);
    for _ in 0..str_len {
        let b = u8::arbitrary(&mut u).unwrap_or(0);
        str_bytes.push(b);
    }
    let s = String::from_utf8_lossy(&str_bytes);

    let _cid = parse_or_default(&s, DEFAULT_VSOCK_SERVER_CID);
    let _port = parse_or_default(&s, DEFAULT_VSOCK_PORT);

    // 合法数字字符串
    let num: u32 = u.arbitrary().unwrap_or(0);
    let num_str = num.to_string();
    assert_eq!(
        parse_or_default(&num_str, DEFAULT_VSOCK_SERVER_CID),
        num,
        "合法数字字符串解析必须与原值一致"
    );

    // 空字符串回退
    assert_eq!(
        parse_or_default("", DEFAULT_VSOCK_SERVER_CID),
        DEFAULT_VSOCK_SERVER_CID
    );
    assert_eq!(parse_or_default("", DEFAULT_VSOCK_PORT), DEFAULT_VSOCK_PORT);

    // 真实函数安全调用
    let _real_cid = get_vsock_cid();
    let _real_port = get_vsock_port();

    // ECDH 响应帧：任意字节流解析不 panic
    let _ = parse_ecdh_response(data);

    // ECDH 响应帧：结构化输入 build → parse round-trip
    let server_point = fixed_array::<SM2_POINT_LEN>(&mut u);
    let long_term_point = fixed_array::<SM2_POINT_LEN>(&mut u);
    let sig_len = u.int_in_range(0..=128usize).unwrap_or(0);
    let mut signature = Vec::with_capacity(sig_len);
    for _ in 0..sig_len {
        signature.push(u8::arbitrary(&mut u).unwrap_or(0));
    }

    let frame = build_ecdh_response(&server_point, &signature, &long_term_point);
    let parsed = parse_ecdh_response(&frame).expect("合法构造的响应帧必须可解析");
    assert_eq!(
        parsed.server_point,
        &server_point[..],
        "server_point round-trip 一致"
    );
    assert_eq!(
        parsed.signature,
        &signature[..],
        "signature round-trip 一致"
    );
    assert_eq!(
        parsed.long_term_point,
        &long_term_point[..],
        "long_term_point round-trip 一致"
    );

    // PSK 派生确定性（HKDF-SM3）：相同输入必须派生相同 32 字节 PSK
    let shared = fixed_array::<32>(&mut u);
    let client_point = fixed_array::<SM2_POINT_LEN>(&mut u);
    let server_point2 = fixed_array::<SM2_POINT_LEN>(&mut u);

    if let Ok(psk1) = derive_psk(&shared, &client_point, &server_point2)
        && let Ok(psk2) = derive_psk(&shared, &client_point, &server_point2)
    {
        assert_eq!(psk1, psk2, "derive_psk 必须确定性");
        assert_eq!(psk1.len(), PSK_LEN, "PSK 长度必须为 32 字节");
    }
});
