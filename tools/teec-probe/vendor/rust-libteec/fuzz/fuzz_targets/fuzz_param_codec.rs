// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Fuzz target: 参数类型编解码全路径。
//!
//! 检验属性：
//! * 任意 u32 → TEE_ParamType 转换不 panic，合法值映射正确，非法值→None；
//! * TEEC_PARAM_TYPES 编码→TEEC_PARAM_TYPE_GET 解码 round-trip 一致；
//! * 编码结果高 16 bit 为零（4×4 bit）；
//! * 穷举全部 8 个合法 TEE_ParamType 值，确保 match 全部分支被覆盖。

#![no_main]

use arbitrary::Unstructured;
use cc_teec::raw::{TEEC_PARAM_TYPE_GET, TEEC_PARAM_TYPES};
use libfuzzer_sys::fuzz_target;
use teec_protocol::TEE_ParamType;

/// TEE_ParamType 的全部合法 u32 值及其期望枚举。
const LEGAL_PARAM_TYPES: &[(u32, TEE_ParamType)] = &[
    (0, TEE_ParamType::None),
    (1, TEE_ParamType::ValueInput),
    (2, TEE_ParamType::ValueOutput),
    (3, TEE_ParamType::ValueInout),
    (5, TEE_ParamType::MemrefInput),
    (6, TEE_ParamType::MemrefOutput),
    (7, TEE_ParamType::MemrefInout),
];

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // TEE_ParamType::from(u32) — 随机输入
    let val: u32 = u.arbitrary().unwrap_or(0);
    let pt = TEE_ParamType::from(val);

    match val {
        0 => assert_eq!(pt, TEE_ParamType::None),
        1 => assert_eq!(pt, TEE_ParamType::ValueInput),
        2 => assert_eq!(pt, TEE_ParamType::ValueOutput),
        3 => assert_eq!(pt, TEE_ParamType::ValueInout),
        5 => assert_eq!(pt, TEE_ParamType::MemrefInput),
        6 => assert_eq!(pt, TEE_ParamType::MemrefOutput),
        7 => assert_eq!(pt, TEE_ParamType::MemrefInout),
        _ => assert_eq!(pt, TEE_ParamType::None, "非法值 {} 应映射为 None", val),
    }
    assert_eq!(TEE_ParamType::default(), TEE_ParamType::None);

    // 穷举全部合法值，覆盖 match 全部分支
    for &(v, expected) in LEGAL_PARAM_TYPES {
        assert_eq!(TEE_ParamType::from(v), expected, "合法值 {v} 映射必须正确");
    }
    // 非法值均映射为 None
    for &illegal in &[4u32, 8, 99, u32::MAX] {
        assert_eq!(
            TEE_ParamType::from(illegal),
            TEE_ParamType::None,
            "非法值 {illegal} 必须映射为 None"
        );
    }

    // TEEC_PARAM_TYPES 编码 / TEEC_PARAM_TYPE_GET 解码
    let p0_raw: u32 = u.arbitrary().unwrap_or(0);
    let p1_raw: u32 = u.arbitrary().unwrap_or(0);
    let p2_raw: u32 = u.arbitrary().unwrap_or(0);
    let p3_raw: u32 = u.arbitrary().unwrap_or(0);
    let p0 = p0_raw & 0xF;
    let p1 = p1_raw & 0xF;
    let p2 = p2_raw & 0xF;
    let p3 = p3_raw & 0xF;

    let encoded = TEEC_PARAM_TYPES(p0, p1, p2, p3);

    assert_eq!(TEEC_PARAM_TYPE_GET(encoded, 0), p0, "p0 解码不一致");
    assert_eq!(TEEC_PARAM_TYPE_GET(encoded, 1), p1, "p1 解码不一致");
    assert_eq!(TEEC_PARAM_TYPE_GET(encoded, 2), p2, "p2 解码不一致");
    assert_eq!(TEEC_PARAM_TYPE_GET(encoded, 3), p3, "p3 解码不一致");
    assert_eq!(encoded >> 16, 0, "编码结果高 16 bit 必须为零");

    let re_encoded = TEEC_PARAM_TYPES(
        TEEC_PARAM_TYPE_GET(encoded, 0),
        TEEC_PARAM_TYPE_GET(encoded, 1),
        TEEC_PARAM_TYPE_GET(encoded, 2),
        TEEC_PARAM_TYPE_GET(encoded, 3),
    );
    assert_eq!(encoded, re_encoded, "编码 round-trip 必须一致");

    // 穷举合法值组合
    for &(v0, _) in LEGAL_PARAM_TYPES {
        for &(v1, _) in LEGAL_PARAM_TYPES {
            let enc = TEEC_PARAM_TYPES(v0, v1, 0, 0);
            assert_eq!(TEEC_PARAM_TYPE_GET(enc, 0), v0);
            assert_eq!(TEEC_PARAM_TYPE_GET(enc, 1), v1);
            assert_eq!(TEEC_PARAM_TYPE_GET(enc, 2), 0);
            assert_eq!(TEEC_PARAM_TYPE_GET(enc, 3), 0);
        }
    }
});
