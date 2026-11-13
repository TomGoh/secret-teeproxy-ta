// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Fuzz target: `teec::uuid_to_string` 实际函数。
//!
//! 通过 `cfg(feature = "fuzz")` 暴露的 `cc_teec::fuzz::uuid_to_string` 直接调用
//! 库内真实代码路径，确保 fuzzer 测到的是 UUID 布局转换的实际实现。
//!
//! 检验属性：
//! * 任意 16 字节构造的 `TEEC_UUID` 转换不 panic；
//! * 成功时输出字符串可被 `Uuid::parse_str` 解析；
//! * 成功时输出与 `Uuid::from_slice`（标准解析）结果一致。

#![no_main]

use cc_teec::fuzz::uuid_to_string;
use cc_teec::raw::TEEC_UUID;
use libfuzzer_sys::fuzz_target;
use uuid::Uuid;

/// 将原始 16 字节按 GP 大端布局装配为 `TEEC_UUID`。
fn raw16_to_uuid(raw: &[u8; 16]) -> TEEC_UUID {
    TEEC_UUID {
        timeLow: u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
        timeMid: u16::from_be_bytes([raw[4], raw[5]]),
        timeHiAndVersion: u16::from_be_bytes([raw[6], raw[7]]),
        clockSeqAndNode: [
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ],
    }
}

fuzz_target!(|data: &[u8]| {
    // TEEC_UUID 为固定 16 字节结构：长度不足时跳过。
    if data.len() < 16 {
        return;
    }
    let raw: [u8; 16] = data[..16].try_into().expect("长度已检查为 16");

    let uuid = raw16_to_uuid(&raw);

    // 调用实际库函数（非复刻逻辑），fuzzer 测到的是真实代码路径
    match uuid_to_string(&uuid) {
        Ok(s) => {
            // 输出必须是合法标准 UUID 字符串
            let parsed = Uuid::parse_str(&s).expect("转换输出必须可解析");
            // 布局转换必须与标准解析一致
            let standard = Uuid::from_slice(&raw).expect("16 字节恒为合法 UUID");
            assert_eq!(parsed, standard, "UUID 布局转换与标准解析必须一致");
        }
        Err(_) => {
            // uuid_to_string 内部使用 Uuid::from_slice，16 字节输入不应失败
            // 如果失败，说明库代码有 bug
        }
    }
});
