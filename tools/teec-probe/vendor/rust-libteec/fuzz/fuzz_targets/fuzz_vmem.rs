// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 KylinSoft Co., Ltd.

//! 虚拟内存区间校验（`/proc/self/maps` 解析 + 权限判定）的 fuzz。
//!
//! 覆盖 `src/teec/vmem.rs` 的三条判定链：
//! - `check_range_in_maps` 纯函数（经 `fuzz::vmem_check_range` 转发）：逐行解析
//!   地址/权限、单 VMA 完整包含、跨 VMA 与表外区间返回 `None`、畸形行跳过。
//! - `vma_perm_ok`：读需求看权限串第 0 字节、写需求看第 1 字节。
//! - `range_in_perm_vma` / `range_readable` / `range_writable` 的真实指针路径：
//!   长度 0 视为有效、地址区间溢出必须拒绝、堆可读写、代码段可读不可写、
//!   未映射地址不得放行。
//!
//! 检验属性：
//! 1. 无法识别的权限串（空串、缺字段、非法地址）绝不能放行。
//! 2. 区间跨越两个 VMA（即使权限都满足）必须拒绝——非 `Some(true)`。
//! 3. 权限判定结果与「所属 VMA 的权限字符串」一致（独立 oracle 校验）。
//! 4. `start + len` 溢出必须拒绝，且不得因此读取任何内存。
//! 5. 畸形 maps 文本（任意字节）不得 panic。

#![no_main]

use std::ptr;

use arbitrary::Arbitrary;
use cc_teec::fuzz::{vmem_check_range, vmem_range_readable, vmem_range_writable};
use libfuzzer_sys::fuzz_target;

/// 固定四段 VMA：只读、读写、无权限、可执行只读。
const VMA_MAPS: &str = concat!(
    "0000-1000 r--p 00000000 00:00 0 \n",
    "1000-2000 rw-p 00000000 00:00 0 \n",
    "2000-3000 ---p 00000000 00:00 0 \n",
    "3000-4000 r-xp 00000000 00:00 0 \n",
);

/// 权限串样本：可读/可写/可执行/无权限/空串/单字符（触发 `get(1) == None`）。
const PERMS: [&str; 8] = ["r--p", "rw-p", "r-xp", "--xp", "---p", "rwxp", "", "r"];

/// 代码段探针：`.text` 必为可读不可写，用于负向权限判定。
fn text_probe() {}

#[derive(Debug, Arbitrary)]
struct Input {
    /// 任意字节构造的畸形 maps 文本。
    maps: Vec<u8>,
    /// 畸形文本的探针区间下界。
    start: u32,
    /// 畸形文本的探针长度（`end - start`）。
    end: u32,
    /// 权限需求方向。
    writable: bool,
    /// 权限串样本选择。
    perm_pick: u8,
    /// 单行 maps 的地址基址（页号）。
    base: u16,
    /// 单行 VMA 的两个端点偏移（会被规范化成 `a < b`）。
    span_a: u16,
    span_b: u16,
}

fuzz_target!(|input: Input| {
    // 1) 固定 maps 表：文档化语义
    assert_eq!(
        vmem_check_range(VMA_MAPS, 0x0000, 0x1000, false),
        Some(true),
        "只读 VMA 应满足读需求"
    );
    assert_eq!(
        vmem_check_range(VMA_MAPS, 0x0000, 0x1000, true),
        Some(false),
        "只读 VMA 不得满足写需求"
    );
    assert_eq!(
        vmem_check_range(VMA_MAPS, 0x1000, 0x2000, true),
        Some(true),
        "读写 VMA 应满足写需求"
    );
    assert_eq!(
        vmem_check_range(VMA_MAPS, 0x1000, 0x2000, false),
        Some(true)
    );
    assert_eq!(
        vmem_check_range(VMA_MAPS, 0x2000, 0x3000, false),
        Some(false),
        "无权限 VMA 不得放行"
    );
    assert_eq!(
        vmem_check_range(VMA_MAPS, 0x2000, 0x3000, true),
        Some(false)
    );
    assert_eq!(
        vmem_check_range(VMA_MAPS, 0x3000, 0x4000, false),
        Some(true),
        "可执行段应满足读需求"
    );
    assert_eq!(
        vmem_check_range(VMA_MAPS, 0x3000, 0x4000, true),
        Some(false),
        "可执行段不得满足写需求"
    );
    assert_eq!(
        vmem_check_range(VMA_MAPS, 0x1800, 0x1fff, true),
        Some(true),
        "子区间按所属 VMA 判定"
    );
    assert_eq!(
        vmem_check_range(VMA_MAPS, 0x0500, 0x1500, false),
        None,
        "跨 VMA 的区间不得放行"
    );
    assert_eq!(
        vmem_check_range(VMA_MAPS, 0x4000, 0x5000, false),
        None,
        "表外区间不得放行"
    );

    // 畸形/退化输入：一律不得放行为可读/可写。
    assert_eq!(
        vmem_check_range("", 0, 0x1000, false),
        None,
        "空 maps 不得放行"
    );
    assert_eq!(
        vmem_check_range("0000-1000\n", 0, 0x1000, false),
        None,
        "缺权限字段的行应被跳过"
    );
    assert_eq!(
        vmem_check_range("zzzz-yyyy r--p\n", 0, 0x1000, false),
        None,
        "非法地址应被跳过"
    );
    assert_eq!(
        vmem_check_range("0000-1000  r--p\n", 0, 0x1000, false),
        Some(false),
        "多余空格会把权限串切空，不得放行"
    );

    // 2) 真实指针路径
    let heap = vec![0u8; 4096];
    assert!(
        vmem_range_readable(heap.as_ptr(), heap.len()),
        "堆缓冲区必须可读"
    );
    assert!(
        vmem_range_writable(heap.as_ptr(), heap.len()),
        "堆缓冲区必须可写"
    );
    assert!(
        vmem_range_readable(text_probe as *const () as *const u8, 1),
        "代码段必须可读"
    );
    assert!(
        !vmem_range_writable(text_probe as *const () as *const u8, 1),
        "代码段不得可写"
    );
    // 长度 0 视为有效：不得触碰指针（空指针也不得崩溃）。
    assert!(vmem_range_readable(ptr::null(), 0), "长度 0 视为有效");
    assert!(vmem_range_writable(ptr::null(), 0), "长度 0 视为有效");
    // 未映射低地址（`ptr::dangling::<u8>()` 即地址 1，任何进程都不会映射）：不得放行。
    assert!(
        !vmem_range_readable(ptr::dangling::<u8>(), 1),
        "未映射地址不得放行"
    );
    assert!(
        !vmem_range_writable(ptr::dangling::<u8>(), 1),
        "未映射地址不得放行"
    );
    // 区间溢出：必须拒绝（`start.checked_add(len)` 失败）。
    assert!(
        !vmem_range_readable(usize::MAX as *const u8, 2),
        "区间溢出必须拒绝"
    );
    assert!(
        !vmem_range_writable(usize::MAX as *const u8, 2),
        "区间溢出必须拒绝"
    );

    // 3) 单行 maps：独立 oracle 校验权限判定
    let perms = PERMS[(input.perm_pick as usize) % PERMS.len()];
    let base = (input.base as usize) << 12;
    let a = (input.span_a as usize) % 0x800;
    let b = (input.span_b as usize) % 0x800;
    let (l_start, l_end) = if a < b {
        (base + a, base + b)
    } else {
        (base + b, base + a)
    };
    if l_start < l_end {
        let line = format!("{l_start:x}-{l_end:x} {perms} 00000000 00:00 0\n");
        let span = l_end - l_start;
        let off = (input.start as usize) % span;
        let len = (input.end as usize) % (span - off + 1);
        // 独立期望：读需求看权限串第 0 字节，写需求看第 1 字节；缺字节即不满足。
        let want = if input.writable {
            perms.as_bytes().get(1) == Some(&b'w')
        } else {
            perms.as_bytes().first() == Some(&b'r')
        };
        let got = vmem_check_range(&line, l_start + off, l_start + off + len, input.writable);
        assert_eq!(
            got,
            Some(want),
            "单行 maps 判定不符：line={line:?} off={off} len={len} writable={}",
            input.writable
        );
        // 紧随该行之后的 1 字节不在任何 VMA 内 → 必须为 None。
        assert_eq!(
            vmem_check_range(&line, l_end, l_end + 1, input.writable),
            None,
            "行外区间不得被接纳：line={line:?}"
        );
    }

    // 4) 任意畸形文本：只要求不 panic
    let text = String::from_utf8_lossy(&input.maps).into_owned();
    let got = vmem_check_range(
        &text,
        input.start as usize,
        input.start as usize + input.end as usize,
        input.writable,
    );
    if text.is_empty() {
        assert_eq!(got, None, "空 maps 不得放行");
    }
});
