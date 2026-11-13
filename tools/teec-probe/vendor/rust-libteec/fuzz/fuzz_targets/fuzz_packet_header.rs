// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Fuzz target: `teec_protocol::PacketHeader` 协议头解析与类型转换。
//!
//! 检验属性：
//! * 16 字节输入解析出的协议头 `as_bytes()` 与输入字节完全一致（字节级 round-trip）；
//! * `PacketType::from(data_type)` 与 `u64::from(...)` 双向转换一致；
//! * 穷举全部 5 个合法 PacketType 值，确保 match 全部分支被覆盖；
//! * 任意 `data_size` / `data_type` 取值解析不 panic。
//!
//! 注意：`PacketHeader::from_bytes` 内部使用 bytemuck `from_bytes`，要求输入
//! 指针按结构体对齐（含 u64 字段，对齐 8）；libFuzzer 输入切片对齐不受保证，
//! 故先复制到栈上对齐数组再解析，避免未定义行为。

#![no_main]

use libfuzzer_sys::fuzz_target;
use teec_protocol::{PacketHeader, PacketType};

/// PacketType 的全部 5 个合法 u64 值。
const LEGAL_PACKET_TYPE_VALUES: &[u64] = &[0, 1, 2, 3, 4];

fuzz_target!(|data: &[u8]| {
    // 协议头固定 16 字节：长度不足时跳过。
    if data.len() < PacketHeader::SIZE {
        return;
    }

    // 复制到对齐的栈数组，满足 bytemuck 对齐要求。
    let mut buf = [0u8; PacketHeader::SIZE];
    buf.copy_from_slice(&data[..PacketHeader::SIZE]);
    let header = PacketHeader::from_bytes(&buf);

    // 字节级 round-trip。
    assert_eq!(
        header.as_bytes(),
        &buf[..],
        "协议头字节 round-trip 必须一致"
    );

    // 类型双向转换一致性。
    let pt = PacketType::from(header.data_type);
    let back = u64::from(pt);
    if header.data_type <= 4 {
        assert_eq!(
            back, header.data_type,
            "合法 data_type {} 双向转换必须一致",
            header.data_type
        );
    }

    let _ = header.data_size;

    // 穷举全部 5 个合法 PacketType，覆盖 match 全部分支
    for &v in LEGAL_PACKET_TYPE_VALUES {
        let pt = PacketType::from(v);
        assert_eq!(u64::from(pt), v, "合法值 {v} 双向转换必须一致");
    }
    // 非法值→Unknown(0)
    for &illegal in &[5u64, 99, u64::MAX] {
        assert_eq!(
            u64::from(PacketType::from(illegal)),
            0,
            "非法值 {illegal} 必须映射为 Unknown(0)"
        );
    }
});
