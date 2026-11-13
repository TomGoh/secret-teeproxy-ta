// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 KylinSoft Co., Ltd.

//! CA 身份认证（`src/teec/ca_auth.rs`）的 fuzz。
//!
//! 这块逻辑的特点是：**输入不完全由 fuzzer 控制**——CA 验签读取的是
//! `/proc/self/exe` 自身。因此本 target 的价值不在「喂新输入」，
//! 而在**持续断言安全不变量**：
//!
//! 1. **fail-closed**：未被麒麟根证书签名的可执行文件永远不得被判为
//!    `verified == true`（宿主的 fuzz 二进制正是这种情况）。
//! 2. **稳定性**：清空缓存前后 CA 认证结论必须完全一致——缓存只能是
//!    性能优化，不得改变安全判定。
//! 3. **身份格式**：CA UUID 必须是可被标准解析器解析的 UUID v5（基于
//!    调用者路径的确定性标识），且与进程生命周期内保持稳定。

#![no_main]

use arbitrary::Arbitrary;
use cc_teec::fuzz::{ca_auth_clear_cache, ca_auth_info};

use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    /// 是否在两次 CA 认证之间清空缓存（取模降低频率：重新验签需重读 ELF）。
    clear: u8,
}

/// CA 认证不变量检查（含清缓存前后的稳定性）。
fn check_ca_auth(clear_between: bool) {
    let (uuid_before, verified_before) = ca_auth_info();

    if clear_between {
        ca_auth_clear_cache();
    }

    let (uuid_after, verified_after) = ca_auth_info();

    assert_eq!(
        (uuid_before.as_str(), verified_before),
        (uuid_after.as_str(), verified_after),
        "清空缓存不得改变 CA 认证结论（缓存只能是性能优化）"
    );
    assert!(
        !verified_before,
        "未签名的可执行文件不得被判为已验签（fail-closed 被破坏）"
    );
    assert_eq!(uuid_before.len(), 36, "CA UUID 必须是 36 字符的 UUID 文本");
    let parsed = uuid::Uuid::parse_str(&uuid_before)
        .unwrap_or_else(|e| panic!("CA UUID 必须可被标准解析器解析: {uuid_before} ({e})"));
    assert_eq!(
        parsed.get_version_num(),
        5,
        "CA UUID 必须是基于路径的 UUID v5: {uuid_before}"
    );
}

fuzz_target!(|input: Input| {
    // 清缓存约 1/16 的迭代执行：重新验签需重读自身 ELF，全量清缓存会显著压低 exec/s。
    check_ca_auth(input.clear.is_multiple_of(16));
});
