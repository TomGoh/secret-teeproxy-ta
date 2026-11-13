// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! fuzz_tee_request / fuzz_tee_response / fuzz_param_codec 共享的辅助函数。

pub use arbitrary::Unstructured;
pub use teec_protocol::{TEE_Param, TEE_ParamType, TEE_Parameter, TEE_Parameters, TEE_Value};

/// 数据字段长度上界，避免单个迭代内存膨胀。
const MAX_DATA_LEN: usize = 512;

/// 从字节流构造任意 `TEE_ParamType`（覆盖 0..=7 全部合法取值及未知值）。
pub fn arbitrary_param_type(u: &mut Unstructured) -> TEE_ParamType {
    match u.int_in_range(0..=7).unwrap_or(0) {
        0 => TEE_ParamType::None,
        1 => TEE_ParamType::ValueInput,
        2 => TEE_ParamType::ValueOutput,
        3 => TEE_ParamType::ValueInout,
        5 => TEE_ParamType::MemrefInput,
        6 => TEE_ParamType::MemrefOutput,
        7 => TEE_ParamType::MemrefInout,
        _ => TEE_ParamType::None,
    }
}

/// 从字节流构造任意长度受限的字节向量。
pub fn arbitrary_data(u: &mut Unstructured) -> Vec<u8> {
    use arbitrary::Arbitrary;
    let len = u.int_in_range(0..=MAX_DATA_LEN as u32).unwrap_or(0) as usize;
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        v.push(u8::arbitrary(u).unwrap_or(0));
    }
    v
}

/// 从字节流构造任意 `TEE_Value`。
pub fn arbitrary_value(u: &mut Unstructured) -> TEE_Value {
    use arbitrary::Arbitrary;
    TEE_Value {
        a: u32::arbitrary(u).unwrap_or(0),
        b: u32::arbitrary(u).unwrap_or(0),
    }
}

/// 从字节流构造任意 `TEE_Parameter`。
pub fn arbitrary_param(u: &mut Unstructured) -> TEE_Parameter {
    TEE_Parameter {
        param_type: arbitrary_param_type(u),
        param: TEE_Param {
            data: arbitrary_data(u),
            values: arbitrary_value(u),
        },
    }
}

/// 从字节流构造任意 `TEE_Parameters`（固定 4 个参数，顺序固定保证可复现）。
pub fn arbitrary_params(u: &mut Unstructured) -> TEE_Parameters {
    TEE_Parameters(
        arbitrary_param(u),
        arbitrary_param(u),
        arbitrary_param(u),
        arbitrary_param(u),
    )
}
