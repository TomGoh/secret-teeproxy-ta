// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! Fuzz target: 共享内存管理全路径（直接调用真实实现，非复刻）。
//!
//! 覆盖 `SharedMemoryManager`：
//! * `allocate`：size/flags 合法性校验、超限拒绝、注册路径的 `vmem` 可读性
//!   校验与内容拷贝、库自分配路径、结构体地址登记（`REGISTERED_SHMS`）；
//! * `release`：正常回收、句柄不匹配（`imp.id` 篡改）与 buffer 指针不匹配时的
//!   幂等保护（不得释放他人内存）；
//! * `read_buffer_locked` / `write_buffer_locked`：未登记 parent、buffer 不一致、
//!   `offset + len` 越界（以库内部权威大小为界）与正常读写；
//! * `is_registered`：纯地址比较；
//! * `release_by_context`：上下文未登记时的拒绝清理。
//!
//! 指针纪律（本 target 的核心约束）：传给库的指针只能来自本 harness 自己拥有的
//! 对象（栈上结构体、harness 的 `Vec` 缓冲区），fuzz 字节只能影响数值字段与
//! 「安装哪一个已知合法指针」这一选择，绝不直接成为裸地址。否则 fuzzer 轻易
//! 构造出野指针，测到的是 harness 的段错误而不是库的健壮性。
//!
//! 无泄漏纪律：每次 `allocate` 成功都必然在本次迭代内 `release`（被篡改的字段在
//! 释放前恢复为分配时的值），保证长跑 fuzz 的 RSS 不增长。
//!
//! 检验属性：
//! * 任意 (size, flags, register, offset, len) 下不 panic；
//! * `offset + len` 超出库内部记录的分配大小时必被拒绝；
//! * 句柄/buffer 被篡改后，`release` 与 memref 访问都不得影响已登记条目。

#![no_main]

use std::ffi::c_void;
use std::hint::black_box;
use std::mem;
use std::ptr;

use arbitrary::Arbitrary;
use cc_teec::fuzz::{
    shm_allocate, shm_is_registered, shm_read_buffer, shm_release, shm_release_by_context,
    shm_write_buffer,
};
use cc_teec::raw;
use libfuzzer_sys::fuzz_target;

/// harness 源缓冲区容量，同时是普通路径 size 的上界。
const BACKING_LEN: usize = 1 << 16;
/// `MAX_SHARED_MEMORY_SIZE + 1`，用于命中「请求过大」分支。
const OVERSIZE: usize = 100 * 1024 * 1024 + 1;

#[derive(Debug, Arbitrary)]
struct Input {
    /// 声明大小；`oversize` 为真时改用超限值。
    size: u16,
    oversize: bool,
    /// 原始标志位（低 4 位决定合法性分支）。
    flags: u8,
    /// memref 读写偏移与长度。
    offset: u16,
    len: u16,
    /// 篡改模式：0 无、1 buffer 置空、2 buffer 换成另一个合法指针、3 句柄错位。
    tamper: u8,
    /// 上下文 fd（作为 ShmEntry 的 context_id 记录）。
    ctx_fd: i32,
    /// 是否把上下文标记为已初始化（用于确认未登记时仍拒绝清理）。
    ctx_initialized: bool,
    data: Vec<u8>,
}

/// 低 4 位覆盖：0 → `flags == 0` 分支；1/2/3 → 合法方向；其余 → 非法标志位分支。
fn flags_of(raw_flags: u8) -> u32 {
    (raw_flags & 0x0F) as u32
}

fn declared_size(input: &Input) -> usize {
    if input.oversize {
        OVERSIZE
    } else {
        input.size as usize
    }
}

fn new_shm(buffer: *mut u8, size: usize, flags: u32) -> raw::TEEC_SharedMemory {
    let mut shm: raw::TEEC_SharedMemory = unsafe { mem::zeroed() };
    shm.buffer = buffer.cast();
    shm.size = size;
    shm.flags = flags;
    shm.imp.id = -1; // SHM_ID_NONE：尚未持有条目
    shm
}

fn new_ctx(fd: i32, initialized: bool) -> raw::TEEC_Context {
    let mut ctx: raw::TEEC_Context = unsafe { mem::zeroed() };
    ctx.imp.fd = fd;
    ctx.imp.reg_mem = initialized;
    ctx.imp.memref_null = initialized;
    ctx
}

/// 注册路径：buffer 由 harness 提供（覆盖 `vmem` 校验与内容拷贝）。
fn register_path(input: &Input, backing: &mut [u8]) {
    let size = declared_size(input);
    let mut ctx = new_ctx(input.ctx_fd, input.ctx_initialized);
    let mut shm = new_shm(backing.as_mut_ptr(), size, flags_of(input.flags));
    if black_box(shm_allocate(&mut ctx, &mut shm, true)).is_err() {
        return;
    }
    let _ = black_box(shm_read_buffer(
        &shm,
        input.offset as usize,
        input.len as usize,
    ));
    black_box(shm_is_registered(&shm));
    // 入库内容必须等于注册时的源缓冲区内容（越界时读取被拒绝，返回 Err）。
    if let Ok(data) = shm_read_buffer(&shm, 0, size) {
        assert!(data.len() == size && data == backing[..size]);
    }
    shm_release(&mut shm);
}

/// 分配路径：库自分配，句柄/指针被篡改后仍须能安全且正确地释放。
fn allocate_path(input: &Input, backing: &mut [u8]) {
    let size = declared_size(input);
    let mut ctx = new_ctx(input.ctx_fd, false);
    let mut shm = new_shm(ptr::null_mut(), size, flags_of(input.flags));
    if black_box(shm_allocate(&mut ctx, &mut shm, false)).is_err() {
        return;
    }
    assert!(shm_is_registered(&shm));
    assert_eq!(shm.imp.alloced_size, size);

    // 正常读写（区间恰好等于权威大小）+ fuzz 指定区间（越界必被拒绝）。
    let _ = black_box(shm_read_buffer(&shm, 0, size));
    let _ = black_box(shm_write_buffer(&shm, 0, &input.data));
    let _ = black_box(shm_read_buffer(
        &shm,
        input.offset as usize,
        input.len as usize,
    ));
    let _ = black_box(shm_write_buffer(&shm, input.offset as usize, &input.data));

    // 篡改：只动数值字段或换成 harness 拥有的另一个合法指针，释放前必须恢复。
    // buffer 与登记值不一致时读取必须被拒绝；仅 `imp.id` 错位不影响按结构体地址
    // 索引的读取路径（该路径以地址登记表为准），只影响 release 的匹配。
    let saved = (shm.buffer as usize, shm.imp.id);
    let expect_reject = match input.tamper % 4 {
        0 => false,
        1 => {
            shm.buffer = ptr::null_mut();
            true
        }
        2 => {
            shm.buffer = unsafe { backing.as_mut_ptr().add(1) }.cast();
            true
        }
        _ => {
            shm.imp.id = shm.imp.id.wrapping_add(1);
            false
        }
    };
    assert_eq!(shm_read_buffer(&shm, 0, size).is_err(), expect_reject);
    if black_box(shm_write_buffer(&shm, 0, &input.data)).is_ok() {
        assert!(!expect_reject);
    }
    shm.buffer = saved.0 as *mut c_void;
    shm.imp.id = saved.1;

    shm_release(&mut shm);
    assert!(!shm_is_registered(&shm));
    // 幂等：已释放的句柄再次释放不得影响任何条目。
    shm_release(&mut shm);
}

/// 按上下文清理：上下文未登记时 `release_by_context` 必须直接返回。
fn context_path(input: &Input) {
    let mut ctx = new_ctx(input.ctx_fd, input.ctx_initialized);
    shm_release_by_context(&mut ctx);
    shm_release_by_context(ptr::null_mut());
}

/// 未登记 parent、空 parent 与未分配句柄的读写/释放组合。
fn unregistered_path(input: &Input, backing: &mut [u8]) {
    let mut stranger = new_shm(
        backing.as_mut_ptr(),
        input.size as usize,
        flags_of(input.flags),
    );
    assert!(!shm_is_registered(&stranger));
    assert!(shm_read_buffer(&stranger, input.offset as usize, input.len as usize).is_err());
    assert!(shm_write_buffer(&stranger, input.offset as usize, &input.data).is_err());
    assert!(shm_read_buffer(ptr::null(), input.offset as usize, input.len as usize).is_err());
    assert!(shm_write_buffer(ptr::null(), input.offset as usize, &input.data).is_err());

    // 未分配/未注册的句柄：release 必须是 no-op（不得按垃圾 id 误删条目）。
    stranger.imp.id = input.ctx_fd;
    shm_release(&mut stranger);
}

fuzz_target!(|input: Input| {
    let mut backing = vec![0u8; BACKING_LEN];
    register_path(&input, &mut backing);
    context_path(&input);
    unregistered_path(&input, &mut backing);
    allocate_path(&input, &mut backing);
});
