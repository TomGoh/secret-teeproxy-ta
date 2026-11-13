// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Fuzz target: TEEC_Operation 参数构建全路径（直接调用实际库函数）。
//!
//! 覆盖：
//! 1. `SharedMemoryManager::allocate` 标志位验证（复刻）— 依赖全局状态无法直接调用；
//! 2. `build_parameters_from_operation` — 直接调用实际库函数，覆盖 12+ match 分支，
//!    这是参数构建路径中分支最密集的函数。
//!
//! 检验属性：
//! * 任意 (size, flags) 共享内存验证不 panic；
//! * 任意 `TEEC_Operation` 构建参数不 panic（Ok/Err 均可接受）；
//! * 空 `operation` 指针返回 Err。

#![no_main]

use std::mem::MaybeUninit;

use arbitrary::Unstructured;
use cc_teec::fuzz::build_parameters_from_operation;
use cc_teec::raw;
use libfuzzer_sys::fuzz_target;

/// 复刻 `SharedMemoryManager::allocate` 的标志位验证。
fn validate_shm_flags(size: usize, flags: u32) -> bool {
    !(size == 0 || flags == 0 || flags & !(raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT) != 0)
}

/// 构造一个 `TEEC_Operation`，其中 `paramTypes` 由 4 个 4-bit 值编码。
///
/// 对 VALUE/MEMREF 类型参数写入任意 `value.{a,b}`；对 TEMP 类型参数保持
/// zeroed（`tmpref.buffer` 为 null、size 为 0）。
///
/// 注意：`TEEC_Parameter` 是 union，其前 8 字节在 64 位平台上同时是
/// `tmpref.buffer` / `memref.parent` 指针。对 MEMREF 类型写入任意值会产生
/// 垃圾 parent 指针；库的 memref 访问器在解引用前按地址登记表校验，
/// 对未登记的父共享内存直接返回 Err，因此该输入空间现在是安全的，
/// 可以放开给 fuzzer 覆盖（此前仅判空，垃圾指针会触发解引用崩溃）。
fn make_operation(param_types: u32, values: &[(u32, u32); 4]) -> raw::TEEC_Operation {
    let mut op = MaybeUninit::<raw::TEEC_Operation>::zeroed();
    let op_ptr = op.as_mut_ptr();
    unsafe {
        (*op_ptr).paramTypes = param_types;
        (*op_ptr).started = 0;
        for (i, value) in values.iter().enumerate() {
            match raw::TEEC_PARAM_TYPE_GET(param_types, i) {
                raw::TEEC_VALUE_INPUT | raw::TEEC_VALUE_OUTPUT | raw::TEEC_VALUE_INOUT => {
                    (*op_ptr).params[i].value.a = value.0;
                    (*op_ptr).params[i].value.b = value.1;
                }
                raw::TEEC_MEMREF_WHOLE
                | raw::TEEC_MEMREF_PARTIAL_INPUT
                | raw::TEEC_MEMREF_PARTIAL_OUTPUT
                | raw::TEEC_MEMREF_PARTIAL_INOUT => {
                    // 垃圾 parent 指针：库按登记表拒绝（Err），不再有 SEGV 风险。
                    (*op_ptr).params[i].value.a = value.0;
                    (*op_ptr).params[i].value.b = value.1;
                }
                // TEMP 类型保持 zeroed：buffer 为 null，走 null 防御路径。
                _ => {}
            }
        }
        op.assume_init()
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // SharedMemoryManager 标志位验证（复刻）
    let size: u64 = u.arbitrary().unwrap_or(0);
    let flags: u32 = u.arbitrary().unwrap_or(0);
    let valid = validate_shm_flags(size as usize, flags);

    if size == 0 {
        assert!(!valid);
    }
    if flags == 0 && size > 0 {
        assert!(!valid);
    }
    let legal_mask = raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT;
    if flags & !legal_mask != 0 && size > 0 {
        assert!(!valid);
    }
    for &legal_flag in &[raw::TEEC_MEM_INPUT, raw::TEEC_MEM_OUTPUT, legal_mask] {
        assert!(validate_shm_flags(1, legal_flag));
    }

    // build_parameters_from_operation（实际库函数）
    // 构造任意 paramTypes 组合
    let p0 = u.arbitrary::<u32>().unwrap_or(0) & 0xF;
    let p1 = u.arbitrary::<u32>().unwrap_or(0) & 0xF;
    let p2 = u.arbitrary::<u32>().unwrap_or(0) & 0xF;
    let p3 = u.arbitrary::<u32>().unwrap_or(0) & 0xF;
    let param_types = raw::TEEC_PARAM_TYPES(p0, p1, p2, p3);

    let values = [
        (
            u.arbitrary::<u32>().unwrap_or(0),
            u.arbitrary::<u32>().unwrap_or(0),
        ),
        (
            u.arbitrary::<u32>().unwrap_or(0),
            u.arbitrary::<u32>().unwrap_or(0),
        ),
        (
            u.arbitrary::<u32>().unwrap_or(0),
            u.arbitrary::<u32>().unwrap_or(0),
        ),
        (
            u.arbitrary::<u32>().unwrap_or(0),
            u.arbitrary::<u32>().unwrap_or(0),
        ),
    ];

    let mut op = make_operation(param_types, &values);
    let result = build_parameters_from_operation(&mut op as *mut _);
    // Ok/Err 均可接受，不 panic 即为通过
    let _ = result;

    // 空指针必须返回 Err
    let null_result = build_parameters_from_operation(std::ptr::null_mut());
    assert!(null_result.is_err(), "空指针必须返回错误");

    // 遍历全部合法参数类型组合，覆盖每个 match 分支
    for &pt in &[
        raw::TEEC_NONE,
        raw::TEEC_VALUE_INPUT,
        raw::TEEC_VALUE_OUTPUT,
        raw::TEEC_VALUE_INOUT,
        raw::TEEC_MEMREF_TEMP_INPUT,
        raw::TEEC_MEMREF_TEMP_OUTPUT,
        raw::TEEC_MEMREF_TEMP_INOUT,
        raw::TEEC_MEMREF_WHOLE,
        raw::TEEC_MEMREF_PARTIAL_INPUT,
        raw::TEEC_MEMREF_PARTIAL_OUTPUT,
        raw::TEEC_MEMREF_PARTIAL_INOUT,
    ] {
        let pt_all = raw::TEEC_PARAM_TYPES(pt, pt, pt, pt);
        let mut op2 = make_operation(pt_all, &values);
        let _ = build_parameters_from_operation(&mut op2 as *mut _);
    }
});
