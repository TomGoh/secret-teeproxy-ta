// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Fuzz target: `TEEC_Operation` 参数编解码全路径（调用真实实现，非复刻）。
//!
//! 覆盖 `src/teec/operation.rs`：
//! * `OperationParams` 的全部访问器与 `build_parameters_from_operation` 的
//!   12 分支 match（含未支持类型的拒绝分支）；
//! * `update_operation_from_parameters` 的 12 分支 match —— 即
//!   `TEEC_InvokeCommand` 成功路径上的写回，其数据来自 TA 响应，属不可信输入；
//! * 「索引 ≥ 4 必须被拒绝且不触碰任何槽位」这一契约；
//! * memref 读写的权威边界是库内部 `ShmEntry.size`（CA 无法篡改），
//!   CA 声明的 `size`/`offset` 不得越过它；tmpref 按声明大小读写前必须
//!   通过 `vmem` 区间校验。
//!
//! 指针纪律：传给库的指针只能来自本 harness 自己的对象（栈上结构体、harness
//! 的 `Vec` 缓冲区），fuzz 字节只能决定数值字段与「安装哪一个已知合法指针」。
//! 无泄漏纪律：注册成功的共享内存必然在本轮释放。
//! 关键约束：非空 tmpref 声明的 size 绝不超过其缓冲区的真实长度，否则 ASAN
//! 会把「库按 CA 声明长度读写」报成堆越界假阳性——该场景属 CA 违反 API
//! 契约，不是库缺陷。
//!
//! 检验属性：
//! * 任意参数类型组合下，访问器与两个方向的编解码均不 panic；
//! * 索引 ≥ 4 时所有访问器必须返回错误；
//! * 节点类型与访问器匹配时，`set_*` → `get_*` 必须往返一致；
//! * 未登记为 parent 的指针（含 null）必须被所有 memref 路径拒绝；
//! * 超长的「TA 响应」必须被长度校验拦住，已登记区块始终完整可读。

#![no_main]

use std::hint::black_box;
use std::mem;
use std::ptr;

use arbitrary::Arbitrary;
use cc_teec::fuzz::{
    build_parameters_from_operation, op_get_memref_data_partial, op_get_memref_data_whole,
    op_get_memref_parent_flags, op_get_memref_size, op_get_tmpref_data, op_get_tmpref_size,
    op_get_value, op_param_types, op_set_memref_data_partial, op_set_memref_data_whole,
    op_set_tmpref_data, op_set_value, op_update_from_parameters, shm_allocate, shm_read_buffer,
    shm_release, shm_write_buffer,
};
use cc_teec::raw;
use libfuzzer_sys::fuzz_target;
use teec_protocol::{TEE_Parameters, TEE_Value};

/// harness 的 tmpref 缓冲区容量，同时是 tmpref 声明大小的上界。
const TMP_CAP: usize = 64;
/// 已登记共享内存的长度。
const REG_LEN: usize = 256;
/// 确定性往返中 partial memref 的偏移与长度。
const PART_OFF: usize = 64;
const PART_LEN: usize = 32;
/// 确定性往返中 tmpref 的声明长度。
const REQ_TMP_LEN: usize = 16;

/// 参数类型候选：11 个合法类型 + 1 个未支持类型。
const TYPES: [u32; 12] = [
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
    0x4,
];

#[derive(Debug, Arbitrary)]
struct Input {
    /// 每个参数槽的类型选择（索引进 `TYPES`）。
    picks: [u8; 4],
    /// VALUE 槽的 (a, b)。
    values: [(u32, u32); 4],
    /// tmpref 声明大小（非空缓冲时会夹到真实长度内）。
    tmp_sizes: [u16; 4],
    /// tmpref 缓冲选择：奇数 = harness 缓冲区，偶数 = null。
    tmp_mode: [u8; 4],
    /// memref parent 选择：0 = null，1 = 已登记，2 = 未登记。
    mem_parent: [u8; 4],
    /// memref 声明大小与偏移（可取到超出权威大小，用于命中越界分支）。
    mem_sizes: [u16; 4],
    mem_offsets: [u16; 4],
    /// 访问器探针索引（%6，4/5 为越界）。
    probe: u8,
    /// 模拟 TA 响应数据。
    payload: Vec<u8>,
}

/// 安装时确定的槽位事实，供断言语义化比对。
#[derive(Debug, Default, Clone, Copy)]
struct Slots {
    tmp_null: [bool; 4],
    tmp_size: [usize; 4],
    mem_kind: [u8; 4],
    mem_size: [usize; 4],
    mem_offset: [usize; 4],
}

fn slot_type(pick: u8) -> u32 {
    TYPES[(pick as usize) % TYPES.len()]
}

fn is_value(t: u32) -> bool {
    t == raw::TEEC_VALUE_INPUT || t == raw::TEEC_VALUE_OUTPUT || t == raw::TEEC_VALUE_INOUT
}

fn is_temp(t: u32) -> bool {
    t == raw::TEEC_MEMREF_TEMP_INPUT
        || t == raw::TEEC_MEMREF_TEMP_OUTPUT
        || t == raw::TEEC_MEMREF_TEMP_INOUT
}

fn is_memref(t: u32) -> bool {
    t == raw::TEEC_MEMREF_WHOLE
        || t == raw::TEEC_MEMREF_PARTIAL_INPUT
        || t == raw::TEEC_MEMREF_PARTIAL_OUTPUT
        || t == raw::TEEC_MEMREF_PARTIAL_INOUT
}

/// 按 fuzz 输入安装 4 个参数槽；只写入与类型匹配的 union 成员。
fn install(
    op: &mut raw::TEEC_Operation,
    input: &Input,
    reg: &mut raw::TEEC_SharedMemory,
    unreg: &mut raw::TEEC_SharedMemory,
    tmp: &mut [u8],
) -> Slots {
    let types = [
        slot_type(input.picks[0]),
        slot_type(input.picks[1]),
        slot_type(input.picks[2]),
        slot_type(input.picks[3]),
    ];
    op.paramTypes = raw::TEEC_PARAM_TYPES(types[0], types[1], types[2], types[3]);

    let mut slots = Slots::default();
    for (i, &ty) in types.iter().enumerate() {
        if is_value(ty) {
            op.params[i].value.a = input.values[i].0;
            op.params[i].value.b = input.values[i].1;
        } else if is_temp(ty) {
            let null = input.tmp_mode[i].is_multiple_of(2);
            op.params[i].tmpref.buffer = if null {
                ptr::null_mut()
            } else {
                tmp.as_mut_ptr().cast()
            };
            // 非空缓冲时声明大小不得超出真实分配，否则库「按 CA 声明长度读写」
            // 会被 ASAN 报成堆越界（属 CA 违反契约，不是库缺陷）。
            slots.tmp_size[i] = if null {
                input.tmp_sizes[i] as usize
            } else {
                (input.tmp_sizes[i] as usize) % (tmp.len() + 1)
            };
            slots.tmp_null[i] = null;
            op.params[i].tmpref.size = slots.tmp_size[i];
        } else if is_memref(types[i]) {
            slots.mem_kind[i] = input.mem_parent[i] % 3;
            op.params[i].memref.parent = match slots.mem_kind[i] {
                0 => ptr::null_mut(),
                1 => ptr::from_mut(reg),
                _ => ptr::from_mut(unreg),
            };
            slots.mem_size[i] = (input.mem_sizes[i] as usize) % (REG_LEN + 8);
            slots.mem_offset[i] = (input.mem_offsets[i] as usize) % (REG_LEN + 8);
            op.params[i].memref.size = slots.mem_size[i];
            op.params[i].memref.offset = slots.mem_offset[i];
        }
    }
    slots
}

/// 索引 ≥ 4：所有访问器必须拒绝，且不得改动任何槽位。
fn probe_out_of_range(op: &mut raw::TEEC_Operation, idx: usize, payload: &[u8]) {
    assert!(op_get_value(op, idx).is_err());
    assert!(op_set_value(op, idx, 1, 2).is_err());
    assert!(op_get_tmpref_data(op, idx).is_err());
    assert!(op_set_tmpref_data(op, idx, payload).is_err());
    assert!(op_get_tmpref_size(op, idx).is_err());
    assert!(op_get_memref_size(op, idx).is_err());
    assert!(op_get_memref_parent_flags(op, idx).is_err());
    assert!(op_get_memref_data_whole(op, idx).is_err());
    assert!(op_set_memref_data_whole(op, idx, payload).is_err());
    assert!(op_get_memref_data_partial(op, idx, raw::TEEC_MEM_INPUT).is_err());
    assert!(op_set_memref_data_partial(op, idx, payload).is_err());
}

/// 已登记 parent 的 memref 槽：边界由库内部权威大小决定。
fn probe_memref(op: &mut raw::TEEC_Operation, idx: usize, s: &Slots, payload: &[u8]) {
    let inout = raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT;
    if s.mem_kind[idx] != 1 {
        // null 或未登记：全部 memref 路径必须拒绝（不得解引用垃圾指针）。
        assert!(op_get_memref_parent_flags(op, idx).is_err());
        assert!(op_get_memref_data_whole(op, idx).is_err());
        assert!(op_set_memref_data_whole(op, idx, payload).is_err());
        assert!(op_get_memref_data_partial(op, idx, inout).is_err());
        assert!(op_set_memref_data_partial(op, idx, payload).is_err());
        return;
    }
    // 已登记且方向为 INPUT|OUTPUT（注册时设定），方向检查恒满足。
    assert_eq!(op_get_memref_parent_flags(op, idx).ok(), Some(inout));
    assert_eq!(op_get_memref_size(op, idx).ok(), Some(s.mem_size[idx]));

    let size = s.mem_size[idx];
    assert_eq!(op_get_memref_data_whole(op, idx).is_ok(), size <= REG_LEN);
    let whole = op_get_memref_data_whole(op, idx).unwrap_or_default();
    assert_eq!(whole.len(), if size <= REG_LEN { size } else { 0 });
    assert_eq!(
        op_set_memref_data_whole(op, idx, payload).is_ok(),
        payload.len() <= REG_LEN
    );

    let fits = s.mem_offset[idx] + size <= REG_LEN;
    assert_eq!(op_get_memref_data_partial(op, idx, inout).is_ok(), fits);
    assert_eq!(
        op_set_memref_data_partial(op, idx, payload).is_ok(),
        s.mem_offset[idx] + payload.len() <= REG_LEN
    );
}

/// TEMP 槽：空 buffer 或区间校验失败必须拒绝；写入被截断到声明大小。
fn probe_temp(op: &mut raw::TEEC_Operation, idx: usize, s: &Slots, payload: &[u8]) {
    // 声明大小以库内当前值为准：此前的阶段可能已按截断语义更新过 size。
    let declared = op_get_tmpref_size(op, idx).ok().unwrap_or(0);
    if !s.tmp_null[idx] {
        assert!(
            declared <= TMP_CAP,
            "非空 tmpref 的声明大小不得超出 harness 缓冲区真实长度"
        );
        assert!(declared <= s.tmp_size[idx]);
    }
    let readable = !(s.tmp_null[idx] && declared > 0);
    let data = op_get_tmpref_data(op, idx);
    assert_eq!(data.is_ok(), readable);
    let expected = if s.tmp_null[idx] { 0 } else { declared };
    assert_eq!(data.unwrap_or_default().len(), expected);

    assert_eq!(
        op_set_tmpref_data(op, idx, payload).is_ok(),
        !s.tmp_null[idx]
    );
    if !s.tmp_null[idx] {
        // 写回后 size 被更新为实际写入长度（截断语义）。
        assert_eq!(
            op_get_tmpref_size(op, idx).ok(),
            Some(payload.len().min(declared))
        );
    }
}

fn probe_value(op: &mut raw::TEEC_Operation, idx: usize, input: &Input) {
    assert!(op_get_value(op, idx).is_ok());
    let (a, b) = input.values[idx];
    assert!(op_set_value(op, idx, a.wrapping_add(1), b.wrapping_add(1)).is_ok());
    assert_eq!(
        op_get_value(op, idx).ok(),
        Some((a.wrapping_add(1), b.wrapping_add(1)))
    );
}

/// 按槽位真实类型选择访问器。错配会构成 harness 自造的 union 混淆：例如对
/// memref 槽调用 tmpref 写回，会把 `parent` 指针当成 CA 缓冲区去写。库自身的
/// 两条编解码路径都按 `paramTypes` 分派，不存在这种混淆。
fn probe_accessors(op: &mut raw::TEEC_Operation, input: &Input, s: &Slots) {
    let idx = (input.probe as usize) % 6;
    let payload = black_box(input.payload.as_slice());
    assert!(op_param_types(op).is_ok());
    if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
        probe_out_of_range(op, idx, payload);
        return;
    }
    let t = raw::TEEC_PARAM_TYPE_GET(op.paramTypes, idx);
    if is_value(t) {
        probe_value(op, idx, input);
    } else if is_temp(t) {
        probe_temp(op, idx, s, payload);
    } else if is_memref(t) {
        probe_memref(op, idx, s, payload);
    } else {
        // NONE：不得改动槽位，但尺寸读取仍可用。
        assert!(op_get_tmpref_size(op, idx).is_ok());
        assert!(op_get_memref_size(op, idx).is_ok());
    }
}

/// 模拟 TA 响应：把每个参数的数据换成任意长度（可能超长）后写回。
/// 这是 `TEEC_InvokeCommand` 成功路径的真实数据来源（不可信）。
fn simulated_ta_response(
    op: &mut raw::TEEC_Operation,
    input: &Input,
    slots: &Slots,
    reg: &raw::TEEC_SharedMemory,
) {
    let Ok(mut params) = build_parameters_from_operation(op) else {
        return;
    };
    for param in [&mut params.0, &mut params.1, &mut params.2, &mut params.3] {
        param.param.data = input.payload.clone();
        param.param.values = TEE_Value {
            a: input.values[0].0,
            b: input.values[0].1,
        };
    }
    let payload_len = input.payload.len();
    let applied = black_box(op_update_from_parameters(op, params)).is_ok();

    for i in 0..4 {
        let t = raw::TEEC_PARAM_TYPE_GET(op.paramTypes, i);
        if !is_temp(t) || slots.tmp_null[i] {
            continue;
        }
        let now = op_get_tmpref_size(op, i).ok();
        // 无论成功与否，声明大小只能缩小，绝不能超过写入前的声明值。
        assert!(now <= Some(slots.tmp_size[i]));
        let is_out = t == raw::TEEC_MEMREF_TEMP_OUTPUT || t == raw::TEEC_MEMREF_TEMP_INOUT;
        if applied && is_out {
            // 截断语义：写回长度 = min(响应数据长度, 声明大小)。
            assert_eq!(now, Some(payload_len.min(slots.tmp_size[i])));
        }
    }
    // 权威区块必须仍然完整可读（无越界写、无 UAF）。
    assert_eq!(shm_read_buffer(reg, 0, REG_LEN).unwrap().len(), REG_LEN);
}

/// 未支持的类型位必须让两个方向的编解码整体失败
/// （CA 与 TA 的类型位图必须一致，不接受未定义类型）。
fn unsupported_type_rejected(op: &mut raw::TEEC_Operation) {
    let saved = op.paramTypes;
    op.paramTypes = raw::TEEC_PARAM_TYPES(0x4, raw::TEEC_NONE, raw::TEEC_NONE, raw::TEEC_NONE);
    assert!(build_parameters_from_operation(op).is_err());
    assert!(op_update_from_parameters(op, TEE_Parameters::default()).is_err());
    op.paramTypes = saved;
}

/// 确定性往返：build 读取 → 篡改响应 → update 写回 → 在缓冲区里观察结果。
fn round_trip(op: &mut raw::TEEC_Operation, reg: &mut raw::TEEC_SharedMemory, tmp: &mut [u8]) {
    let pattern: Vec<u8> = (0..REG_LEN).map(|i| (i % 251) as u8).collect();
    tmp.fill(0xE7);
    assert!(shm_write_buffer(reg, 0, &pattern).is_ok());

    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_MEMREF_PARTIAL_INOUT,
        raw::TEEC_MEMREF_TEMP_INOUT,
        raw::TEEC_VALUE_INOUT,
        raw::TEEC_MEMREF_WHOLE,
    );
    op.params[0].memref.parent = ptr::from_mut(reg);
    op.params[0].memref.offset = PART_OFF;
    op.params[0].memref.size = PART_LEN;
    op.params[1].tmpref.buffer = tmp.as_mut_ptr().cast();
    op.params[1].tmpref.size = REQ_TMP_LEN;
    op.params[2].value.a = 0x0A0B_0C0D;
    op.params[2].value.b = 0x0102_0304;
    op.params[3].memref.parent = ptr::from_mut(reg);
    op.params[3].memref.offset = 0;
    op.params[3].memref.size = REG_LEN;

    let Ok(mut params) = build_parameters_from_operation(op) else {
        panic!("确定性往返的 build 不应失败");
    };
    assert_eq!(params.0.param.data, pattern[PART_OFF..PART_OFF + PART_LEN]);
    assert_eq!(params.1.param.data, vec![0xE7u8; REQ_TMP_LEN]);
    assert_eq!(params.2.param.values.a, 0x0A0B_0C0D);
    assert_eq!(params.2.param.values.b, 0x0102_0304);
    assert_eq!(params.3.param.data, pattern);

    // 模拟 TA 回填的响应数据，并在缓冲区里观察写回结果。
    params.0.param.data = vec![0x5A; PART_LEN];
    params.1.param.data = vec![0x3C; REQ_TMP_LEN];
    params.2.param.values = TEE_Value {
        a: 0xDEAD_BEEF,
        b: 0xFEED_FACE,
    };
    params.3.param.data = vec![0x11; 8];
    assert!(op_update_from_parameters(op, params).is_ok());

    assert_eq!(
        shm_read_buffer(reg, PART_OFF, PART_LEN).ok(),
        Some(vec![0x5A; PART_LEN])
    );
    assert_eq!(&tmp[..REQ_TMP_LEN], &[0x3Cu8; REQ_TMP_LEN]);
    assert_eq!(op_get_tmpref_size(op, 1).ok(), Some(REQ_TMP_LEN));
    assert_eq!(op_get_value(op, 2).ok(), Some((0xDEAD_BEEF, 0xFEED_FACE)));
    assert_eq!(shm_read_buffer(reg, 0, 8).ok(), Some(vec![0x11; 8]));
}

fuzz_target!(|input: Input| {
    let mut tmp = vec![0u8; TMP_CAP];
    let mut backing: Vec<u8> = (0..REG_LEN).map(|i| (i % 251) as u8).collect();
    let mut ctx: raw::TEEC_Context = unsafe { mem::zeroed() };
    ctx.imp.fd = 7;

    let mut reg: raw::TEEC_SharedMemory = unsafe { mem::zeroed() };
    reg.buffer = backing.as_mut_ptr().cast();
    reg.size = REG_LEN;
    reg.flags = raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT;
    reg.imp.id = -1; // SHM_ID_NONE
    if shm_allocate(&mut ctx, &mut reg, true).is_err() {
        return;
    }

    // 未登记的同型结构体：同一缓冲区指针，但不在库的登记表里。
    let mut unreg: raw::TEEC_SharedMemory = unsafe { mem::zeroed() };
    unreg.buffer = backing.as_mut_ptr().cast();
    unreg.size = REG_LEN;
    unreg.flags = raw::TEEC_MEM_INPUT;
    unreg.imp.id = -1;

    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    let slots = install(&mut op, &input, &mut reg, &mut unreg, &mut tmp);
    // 写回阶段在前：其截断不变式依赖「写入前的声明大小」。
    simulated_ta_response(&mut op, &input, &slots, &reg);
    probe_accessors(&mut op, &input, &slots);
    unsupported_type_rejected(&mut op);
    round_trip(&mut op, &mut reg, &mut tmp);
    shm_release(&mut reg);
});
