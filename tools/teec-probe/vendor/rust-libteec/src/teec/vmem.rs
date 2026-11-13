// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! CA 进程地址空间区间校验（defense-in-depth）。
//!
//! GP TEE Client API 的契约要求 CA 保证 TMPREF 缓冲区与注册内存的
//! `buffer`/`size` 真实有效；但 CA 传入错误 size（大于实际分配）时，
//! 库会按声明 size 越界读写 CA 自身进程内存。此模块在每次读写前解析
//! `/proc/self/maps`，要求目标区间由连续且具备相应权限的 VMA 完整覆盖，
//! 将越界访问转化为 `BadParameters` 错误而非内存破坏。

use std::cell::Cell;
use std::fs;
use std::sync::{LazyLock, RwLock};

#[derive(Clone, Copy)]
enum Perm {
    Readable,
    Writable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VmaFailure {
    None,
    Overflow,
    Unmapped,
    Gap,
    PermissionDenied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RejectedRange {
    reason: VmaFailure,
    covered: u16,
}

std::thread_local! {
    static LAST_VMA_FAILURE: Cell<RejectedRange> = const { Cell::new(RejectedRange {
        reason: VmaFailure::None,
        covered: 0,
    }) };
}

pub(super) fn clear_last_vma_failure() {
    LAST_VMA_FAILURE.with(|current| {
        current.set(RejectedRange {
            reason: VmaFailure::None,
            covered: 0,
        })
    });
}

pub(crate) fn get_last_vma_failure() -> (&'static str, u16) {
    LAST_VMA_FAILURE.with(|current| {
        let result = current.get();
        let reason = match result.reason {
            VmaFailure::None => "none",
            VmaFailure::Overflow => "overflow",
            VmaFailure::Unmapped => "unmapped",
            VmaFailure::Gap => "gap",
            VmaFailure::PermissionDenied => "permission_denied",
        };
        (reason, result.covered)
    })
}

fn record_rejection(result: RejectedRange) {
    LAST_VMA_FAILURE.with(|current| current.set(result));
}

/// 校验 `[start, start+len)` 由连续可读 VMA 完整覆盖。
pub(super) fn range_readable(start: *const u8, len: usize) -> bool {
    range_in_perm_vma(start as usize, len, Perm::Readable)
}

/// 校验 `[start, start+len)` 由连续可写 VMA 完整覆盖。
pub(super) fn range_writable(start: *const u8, len: usize) -> bool {
    range_in_perm_vma(start as usize, len, Perm::Writable)
}

/// `/proc/self/maps` 最近一次解析结果缓存，避免每次校验都重读该伪文件。
///
/// 缓存仅在「区间未命中」时重读刷新：合法缓冲区即便在缓存构建之后才
/// mmap，未命中也会回退到实时读取，不会误拒。残余局限是 CA 在校验间隙
/// munmap 掉仍在缓存中的区域时，快速路径可能短暂放行（随后访问未映射内存
/// 即崩溃）——这与本模块「maps 不可读时放行」的纵深防御定位一致：CA 拥有
/// 自身进程，本校验只防库侧越界，不构成对抗恶意 CA 的硬边界。
static MAPS_CACHE: LazyLock<RwLock<Option<String>>> = LazyLock::new(|| RwLock::new(None));

/// 遍历 `/proc/self/maps`，检查整个区间的连续权限覆盖。
///
/// `len == 0` 视为有效。相邻 VMA 的交界可以位于一个有效缓冲区内部，
/// 每一段均需满足相应权限。maps 读取失败时沿用原有放行和告警行为。
/// 该校验是纵深防御，保留 `/proc` 不可用环境中的既有兼容行为。
fn range_in_perm_vma(start: usize, len: usize, need: Perm) -> bool {
    clear_last_vma_failure();
    // Bionic heap pointers on Android/AArch64 may carry a TBI/MTE tag in
    // the top byte. /proc/self/maps describes virtual addresses without it.
    // Normalize only the integer used for VMA lookup. Keep the original
    // tagged pointer for all memory accesses and deallocation.
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    let start = aarch64_vma_address(start);
    if len == 0 {
        return true;
    }
    let Some(end) = start.checked_add(len) else {
        record_rejection(RejectedRange {
            reason: VmaFailure::Overflow,
            covered: 0,
        });
        return false;
    };

    // 快速路径只接受缓存确认具有完整连续权限覆盖的区间，
    // 省去重复读取。缓存未覆盖区间或缓存权限不满足时均重新读取，
    // 根据最新结果判定。`/proc/self/maps` 快照会随 mmap/mprotect/munmap 失效，
    // 若把缓存中的权限拒绝直接当作最终结果，会永久误拒后续落在同一
    // 地址区间的合法缓冲区（表现为概率性、且进程重启前持续失败）。
    if let Some(Ok(_)) = MAPS_CACHE.read().ok().and_then(|guard| {
        guard
            .as_deref()
            .map(|maps| check_continuous_range(maps, start, end, need))
    }) {
        return true;
    }

    // 慢路径：读取并缓存最新 maps 后再判定。
    let maps = match fs::read_to_string("/proc/self/maps") {
        Ok(maps) => maps,
        Err(e) => {
            log::warn!("vmem: 读取 /proc/self/maps 失败（{e}），跳过区间校验");
            return true;
        }
    };
    let result = check_continuous_range(&maps, start, end, need);
    if let Err(rejected) = result {
        record_rejection(rejected);
        let (reason, covered) = get_last_vma_failure();
        log::warn!("vmem: range rejected reason={reason} covered_vmas={covered} len={len}");
    }
    if let Ok(mut guard) = MAPS_CACHE.write() {
        *guard = Some(maps);
    }
    result.is_ok()
}

#[cfg(any(test, all(target_os = "android", target_arch = "aarch64")))]
fn aarch64_vma_address(address: usize) -> usize {
    address & 0x00ff_ffff_ffff_ffff
}

/// 按地址顺序检查完整区间。每次前进都要求当前 VMA 覆盖 cursor，
/// 且具有所需权限。缺失页面、空隙和权限不足均拒绝。
fn check_continuous_range(
    maps: &str,
    start: usize,
    end: usize,
    need: Perm,
) -> Result<u16, RejectedRange> {
    if end < start {
        return Err(RejectedRange {
            reason: VmaFailure::Overflow,
            covered: 0,
        });
    }
    if start == end {
        return Ok(0);
    }
    let mut cursor = start;
    let mut covered = 0u16;
    for line in maps.lines() {
        let Some((addr, rest)) = line.split_once(' ') else {
            continue;
        };
        let Some((vma_start, vma_end)) = addr.split_once('-') else {
            continue;
        };
        let (Ok(vma_start), Ok(vma_end)) = (
            usize::from_str_radix(vma_start, 16),
            usize::from_str_radix(vma_end, 16),
        ) else {
            continue;
        };
        if vma_start >= vma_end || vma_end <= cursor {
            continue;
        }
        if vma_start > cursor {
            let reason = if covered == 0 {
                VmaFailure::Unmapped
            } else {
                VmaFailure::Gap
            };
            return Err(RejectedRange { reason, covered });
        }
        let perms = rest.split(' ').next().unwrap_or("");
        if !vma_perm_ok(perms, need) {
            return Err(RejectedRange {
                reason: VmaFailure::PermissionDenied,
                covered,
            });
        }
        cursor = end.min(vma_end);
        covered = covered.saturating_add(1);
        if cursor == end {
            return Ok(covered);
        }
    }
    let reason = if covered == 0 {
        VmaFailure::Unmapped
    } else {
        VmaFailure::Gap
    };
    Err(RejectedRange { reason, covered })
}

/// 保留现有模糊测试的 Option<bool> 接口。
#[cfg(any(test, feature = "fuzz"))]
fn check_range_in_maps(maps: &str, start: usize, end: usize, need: Perm) -> Option<bool> {
    match check_continuous_range(maps, start, end, need) {
        Ok(_) => Some(true),
        Err(RejectedRange {
            reason: VmaFailure::PermissionDenied,
            ..
        }) => Some(false),
        Err(_) => None,
    }
}

/// 模糊测试专用：把纯函数形式的区间校验暴露给 fuzzer。
///
/// `check_range_in_maps` 是私有 fn 且以私有 `Perm` 为参数，fuzzer 无法直接
/// 构造 maps 文本与区间；此包装以 `writable: bool` 替代表达权限需求，
/// 使解析、权限判定、跨 VMA、溢出等分支可被直接覆盖。
#[cfg(feature = "fuzz")]
pub(super) fn check_range_in_maps_for_fuzz(
    maps: &str,
    start: usize,
    end: usize,
    writable: bool,
) -> Option<bool> {
    let need = if writable {
        Perm::Writable
    } else {
        Perm::Readable
    };
    check_range_in_maps(maps, start, end, need)
}

/// 解析 VMA 权限字符串（如 `rw-p`）是否满足所需权限。
fn vma_perm_ok(perms: &str, need: Perm) -> bool {
    let b = perms.as_bytes();
    match need {
        Perm::Readable => b.first() == Some(&b'r'),
        Perm::Writable => b.get(1) == Some(&b'w'),
    }
}

#[cfg(test)]
mod vmem_tests {
    use super::*;

    #[test]
    fn contiguous_vmas_cover_complete_ranges_with_android_tags() {
        let maps = "10000000-10001000 rw-p 00000000 00:00 0 [anon:first]\n10001000-10002000 rw-p 00000000 00:00 0 [anon:second]\n";
        let start = aarch64_vma_address(0xb400_0000_1000_0ff0);
        assert_eq!(
            check_continuous_range(maps, start, start + 32, Perm::Readable),
            Ok(2)
        );
        assert_eq!(
            check_continuous_range(maps, start, start + 32, Perm::Writable),
            Ok(2)
        );
        assert_eq!(
            check_range_in_maps(maps, start, start + 32, Perm::Readable),
            Some(true)
        );
    }

    #[test]
    fn multivma_gap_missing_permissions_and_overflow_are_rejected() {
        let readonly =
            "1000-2000 rw-p 0 00:00 0\n2000-3000 r--p 0 00:00 0\n3000-4000 rw-p 0 00:00 0\n";
        assert_eq!(
            check_continuous_range(readonly, 0x1800, 0x3800, Perm::Readable),
            Ok(3)
        );
        assert_eq!(
            check_continuous_range(readonly, 0x1800, 0x3800, Perm::Writable),
            Err(RejectedRange {
                reason: VmaFailure::PermissionDenied,
                covered: 1
            })
        );
        let gap = "1000-2000 rw-p 0 00:00 0\n3000-4000 rw-p 0 00:00 0\n";
        assert_eq!(
            check_continuous_range(gap, 0x1800, 0x3800, Perm::Readable),
            Err(RejectedRange {
                reason: VmaFailure::Gap,
                covered: 1
            })
        );
        assert_eq!(
            check_continuous_range(gap, 0x0800, 0x1800, Perm::Readable),
            Err(RejectedRange {
                reason: VmaFailure::Unmapped,
                covered: 0
            })
        );
        assert_eq!(
            check_continuous_range(gap, usize::MAX, 0, Perm::Readable),
            Err(RejectedRange {
                reason: VmaFailure::Overflow,
                covered: 0
            })
        );
        assert_eq!(
            check_continuous_range(readonly, 0x2800, 0x1800, Perm::Readable),
            Err(RejectedRange {
                reason: VmaFailure::Overflow,
                covered: 0
            })
        );
    }

    #[test]
    fn cached_missing_or_readonly_maps_refresh_before_rejection() {
        let mut buffer = [0u8; 64];
        let start = buffer.as_mut_ptr() as usize;
        *MAPS_CACHE.write().unwrap() = Some(String::new());
        assert!(range_readable(buffer.as_ptr(), buffer.len()));
        *MAPS_CACHE.write().unwrap() = Some(format!(
            "{start:x}-{:x} r--p 0 00:00 0\n",
            start + buffer.len()
        ));
        assert!(range_writable(buffer.as_mut_ptr(), buffer.len()));
        assert_eq!(get_last_vma_failure(), ("none", 0));
    }

    #[test]
    fn vma_failure_reason_is_reset_and_thread_local() {
        record_rejection(RejectedRange {
            reason: VmaFailure::Gap,
            covered: 3,
        });
        std::thread::spawn(|| {
            assert_eq!(get_last_vma_failure(), ("none", 0));
            record_rejection(RejectedRange {
                reason: VmaFailure::PermissionDenied,
                covered: 1,
            });
            assert_eq!(get_last_vma_failure(), ("permission_denied", 1));
        })
        .join()
        .unwrap();
        assert_eq!(get_last_vma_failure(), ("gap", 3));
        assert!(range_readable(std::ptr::null(), 0));
        assert_eq!(get_last_vma_failure(), ("none", 0));
        let buffer = [0u8; 8];
        assert!(!range_readable(buffer.as_ptr(), usize::MAX));
        assert_eq!(get_last_vma_failure(), ("overflow", 0));
    }

    #[test]
    fn coverage_count_remains_bounded_for_large_maps() {
        let mut maps = String::new();
        for index in 0..=u16::MAX as usize {
            maps.push_str(&format!(
                "{:x}-{:x} rw-p 0 00:00 0\n",
                0x1000 + index,
                0x1001 + index
            ));
        }
        assert_eq!(
            check_continuous_range(&maps, 0x1000, 0x1001 + u16::MAX as usize, Perm::Readable),
            Ok(u16::MAX)
        );
    }

    #[test]
    fn android_tagged_heap_pointer_matches_untagged_vma_with_permissions() {
        let maps = "0000000010000000-0000000010010000 rw-p 00000000 00:00 0 [anon:scudo]\n";
        let tagged = 0xb400_0000_1000_0100usize;
        assert_eq!(
            check_range_in_maps(maps, tagged, tagged + 64, Perm::Readable),
            None
        );
        let address = aarch64_vma_address(tagged);
        assert_eq!(
            check_range_in_maps(maps, address, address + 64, Perm::Readable),
            Some(true)
        );
        assert_eq!(
            check_range_in_maps(maps, address, address + 64, Perm::Writable),
            Some(true)
        );
        assert_eq!(
            check_range_in_maps(maps, address, address + 0x20000, Perm::Readable),
            None
        );
        let readonly = maps.replace("rw-p", "r--p");
        assert_eq!(
            check_range_in_maps(&readonly, address, address + 64, Perm::Writable),
            Some(false)
        );
    }

    #[test]
    fn test_stack_range_readable_writable() {
        let buf = [0u8; 8];
        assert!(range_readable(buf.as_ptr(), buf.len()));
        assert!(range_writable(buf.as_ptr(), buf.len()));
    }

    #[test]
    fn test_heap_range_readable_writable() {
        // 100KB 缓冲区必然来自堆分配（mmap 的 anonymous VMA）
        let buf = vec![0u8; 100 * 1024];
        assert!(range_readable(buf.as_ptr(), buf.len()));
        assert!(range_writable(buf.as_ptr(), buf.len()));
    }

    #[test]
    fn test_code_range_readable_not_writable() {
        // 代码段映射为 r-x：可读但不可写
        let p = test_code_range_readable_not_writable as *const u8;
        assert!(range_readable(p, 1));
        assert!(!range_writable(p, 1));
    }

    #[test]
    fn test_zero_len_valid() {
        assert!(range_readable(std::ptr::null(), 0));
        assert!(range_writable(std::ptr::null(), 0));
    }

    #[test]
    fn test_len_overflow_rejected() {
        let buf = [0u8; 8];
        assert!(!range_readable(buf.as_ptr(), usize::MAX));
        assert!(!range_writable(buf.as_ptr(), usize::MAX));
    }

    #[test]
    fn test_cross_vma_rejected() {
        // 该 512MB 测试范围包含未映射区间，应被拒绝
        let buf = [0u8; 8];
        let len = 512 * 1024 * 1024;
        assert!(!range_readable(buf.as_ptr(), len));
    }
}
