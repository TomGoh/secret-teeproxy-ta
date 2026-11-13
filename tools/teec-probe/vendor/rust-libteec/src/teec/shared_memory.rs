// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! 共享内存管理模块
//!
//! 负责 TEEC_SharedMemory 的分配、释放和访问。
//!
//! ## 重要说明
//!
//! 这里的“共享内存”是 GlobalPlatform TEE Client API 的概念，用于管理 MEMREF 类型参数的缓冲区。
//! 实际上，CA 与 TA 之间并不存在真正的共享内存映射，所有数据都通过机密通信通道（TLS + VSOCK）传输。
//! 此模块仅负责在 CA 端管理本地缓冲区，这些缓冲区的内容会被序列化后通过网络发送给 TA。

use std::{
    alloc::{self, Layout},
    ptr,
    sync::{
        LazyLock,
        atomic::{AtomicU32, Ordering},
    },
};

use dashmap::DashMap;
use log::warn;

use super::{context::ContextManager, safe_ptr, vmem};
use crate::{Error, ErrorKind, Result, raw};

/// 共享内存 ID 无效标记，表示已释放
const SHM_ID_NONE: i32 = -1;

/// 共享内存标志位：缓冲区已通过 alloc::alloc 分配
const SHM_FLAG_BUFFER_ALLOCED: u32 = 1 << 0;

/// 共享内存最大大小限制（100MB），防止过度分配
const MAX_SHARED_MEMORY_SIZE: usize = 100 * 1024 * 1024;

/// 共享内存条目，存储分配的原始内存及其关联的 context
///
/// 使用 `std::alloc` 直接分配内存，而非 `Vec<u8>`，确保 `shm_ref.buffer` 指针
/// 不依赖任何 Rust 容器的所有权语义，避免容器 move 时指针失效的问题。
struct ShmEntry {
    /// 关联的 TEE context id（用于 TEEC_FinalizeContext 时按 context 清理）
    context_id: i32,
    /// 由 alloc::alloc 返回的原始内存指针
    ptr: *mut u8,
    /// 分配的内存大小（字节），用于 Drop 时构造 Layout 释放内存
    size: usize,
}

// SAFETY: ShmEntry 的 ptr 指向由 alloc::alloc 分配的内存，访问通过 DashMap 的锁保护。
// ptr 本身是普通堆内存地址，不涉及线程局部存储或内部可变性，可安全跨线程传递和共享。
unsafe impl Send for ShmEntry {}
unsafe impl Sync for ShmEntry {}

impl Drop for ShmEntry {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.size > 0 {
            // SAFETY: ptr 由 allocate() 中的 alloc::alloc() 返回，layout 与分配时一致。
            // Drop 只调用一次，不会 double-free。
            unsafe {
                alloc::dealloc(self.ptr, Layout::from_size_align(self.size, 1).unwrap());
            }
            self.ptr = ptr::null_mut();
        }
    }
}

/// 全局共享内存映射表：shm_id -> ShmEntry
type SharedMemoryMap = DashMap<i32, ShmEntry>;

/// 全局共享内存注册表，以唯一 shm_id 为 key 索引所有已分配的共享内存
static SHMS: LazyLock<SharedMemoryMap> = LazyLock::new(DashMap::new);

/// 已登记共享内存结构体地址表：TEEC_SharedMemory 结构体地址 -> shm_id。
///
/// memref.parent 指向的是调用方的 `TEEC_SharedMemory` 结构体本身，而不是内部
/// 缓冲区。此表按结构体地址登记（纯地址比较、不解引用），供 memref 访问路径
/// 在解引用 parent 前校验其确为本库分配/注册过的对象，避免非法非空指针
/// 引发解引用崩溃；同时通过 shm_id 关联库内部的 `ShmEntry`，为 memref 边界
/// 校验提供 CA 无法篡改的权威分配大小。
///
/// 定位为防垃圾/未初始化指针崩溃的健壮性加固，非对抗恶意 CA 的硬边界：
/// CA 拥有自身进程，真正的访问控制由 TA 侧 ACL 与 x-kernel exec 层 TA
/// 验签负责。
type RegisteredAddrMap = DashMap<usize, i32>;

/// 已登记结构体地址集合，与 SHMS 同步维护：allocate 时登记、release 时移除。
static REGISTERED_SHMS: LazyLock<RegisteredAddrMap> = LazyLock::new(DashMap::new);

/// 全局共享内存 id 计数器，从 0 开始递增，每个新分配的共享内存获得唯一 id
/// （与 context id 独立，避免同一 context 下多次分配互相覆盖）
static SHM_ID_COUNTER: LazyLock<AtomicU32> = LazyLock::new(|| AtomicU32::new(0));

/// 共享内存管理器，提供线程安全的共享内存操作
pub struct SharedMemoryManager;

impl SharedMemoryManager {
    /// 分配共享内存并注册到指定上下文
    pub fn allocate(
        ctx: *mut raw::TEEC_Context,
        shm: *mut raw::TEEC_SharedMemory,
        register: bool,
    ) -> Result<()> {
        let mut shm_nn = safe_ptr::deref_mut(shm)?;
        let ctx_nn = safe_ptr::deref(ctx)?;
        // SAFETY: `shm_nn` 已由 `deref_mut` 检查为非空。调用 `as_mut()` 安全，
        // 并可对 `TEEC_SharedMemory` 结构进行可变访问。
        let shm_ref = unsafe { shm_nn.as_mut() };
        // SAFETY: `ctx_nn` 已由 `deref` 检查为非空。调用 `as_ref()` 安全，
        let ctx_ref = unsafe { ctx_nn.as_ref() };
        let context_id = ctx_ref.imp.fd;
        let flags = shm_ref.flags;
        let size = shm_ref.size;

        if size == 0 || flags == 0 || flags & !(raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT) != 0 {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        if size > MAX_SHARED_MEMORY_SIZE {
            warn!(
                "共享内存请求过大: {} bytes (最大允许: {} bytes)",
                size, MAX_SHARED_MEMORY_SIZE
            );
            return Err(Error::new(ErrorKind::OutOfMemory));
        }

        Self::allocate_cc(ctx, shm_ref, context_id, size, register)?;

        Ok(())
    }

    fn allocate_cc(
        _ctx: *mut raw::TEEC_Context,
        shm_ref: &mut raw::TEEC_SharedMemory,
        context_id: i32,
        size: usize,
        register: bool,
    ) -> Result<()> {
        // SAFETY: size > 0 已验证，align = 1 满足 Layout 要求。
        let layout =
            Layout::from_size_align(size, 1).map_err(|_| Error::new(ErrorKind::BadParameters))?;
        // SAFETY: layout.size() > 0，alloc_zeroed 返回的指针有效或 null。
        let buf_ptr = unsafe { alloc::alloc_zeroed(layout) };
        if buf_ptr.is_null() {
            return Err(Error::new(ErrorKind::OutOfMemory));
        }

        if register {
            if shm_ref.buffer.is_null() {
                // SAFETY: 分配的内存需要释放，在 ShmEntry::Drop 中处理。
                unsafe { alloc::dealloc(buf_ptr, layout) };
                return Err(Error::new(ErrorKind::BadParameters));
            }
            // 注册路径按 CA 声明的 size 拷贝其 buffer 内容：先校验
            // [buffer, buffer+size) 完整位于单个可读 VMA 内，防止 size
            // 大于实际分配导致越界读 CA 进程内存。
            if !vmem::range_readable(shm_ref.buffer as *const u8, size) {
                // SAFETY: 分配的内存需要释放，在 ShmEntry::Drop 中处理。
                unsafe { alloc::dealloc(buf_ptr, layout) };
                return Err(Error::new(ErrorKind::BadParameters));
            }
            // SAFETY: buf_ptr 有效且 size 字节可写；shm_ref.buffer 已通过
            // vmem 可读性校验，指向的内存至少 size 字节可读。
            unsafe { ptr::copy_nonoverlapping(shm_ref.buffer as *const u8, buf_ptr, size) };
        }

        // Ordering::Relaxed 即足够：fetch_add 本身是原子操作，
        // 保证每个分配获得唯一 ID 即可，不需要与其他内存操作的全序同步。
        let shm_id = SHM_ID_COUNTER.fetch_add(1, Ordering::Relaxed) as i32;

        shm_ref.buffer = buf_ptr as *mut std::ffi::c_void;
        shm_ref.imp.id = shm_id;
        shm_ref.imp.registered_fd = -1;
        shm_ref.imp.shadow_buffer = ptr::null_mut();
        shm_ref.imp.alloced_size = size;
        shm_ref.imp.flags = SHM_FLAG_BUFFER_ALLOCED;

        SHMS.insert(
            shm_id,
            ShmEntry {
                context_id,
                ptr: buf_ptr,
                size,
            },
        );
        // 同时按结构体地址登记 shm_id，供 memref 路径校验 parent 是否为本库
        // 分配的对象，并据此查询库内部的权威分配大小。
        REGISTERED_SHMS.insert(shm_ref as *const raw::TEEC_SharedMemory as usize, shm_id);

        Ok(())
    }

    /// 释放共享内存
    pub fn release(shm: *mut raw::TEEC_SharedMemory) {
        if let Ok(mut shm_nn) = safe_ptr::deref_mut(shm) {
            // SAFETY: `shm_nn` 已验证非空；`as_mut()` 返回的可变引用在此作用域中有效。
            let shm_ref = unsafe { shm_nn.as_mut() };
            if shm_ref.imp.id == SHM_ID_NONE {
                return;
            }

            let id = shm_ref.imp.id;

            // SAFETY: 验证 id 对应条目与当前 buffer 指针匹配，防止未初始化内存的
            // 垃圾 id 误删他人条目。
            let should_release = SHMS
                .get(&id)
                .is_some_and(|entry| std::ptr::eq(entry.ptr, shm_ref.buffer as *mut u8));
            if !should_release {
                return;
            }

            shm_ref.imp.id = SHM_ID_NONE;
            shm_ref.size = 0;
            shm_ref.flags = 0;
            shm_ref.buffer = ptr::null_mut();

            SHMS.remove(&id);
            REGISTERED_SHMS.remove(&(shm as *const raw::TEEC_SharedMemory as usize));
        }
    }

    /// 校验结构体指针是否为本库登记过的共享内存（纯地址比较，不解引用）。
    ///
    /// memref.parent 指向调用方的 `TEEC_SharedMemory` 结构体，必须是此前通过
    /// allocate 分配/注册的对象；对任意垃圾指针可直接安全地返回 false。
    pub fn is_registered(shm: *const raw::TEEC_SharedMemory) -> bool {
        !shm.is_null() && REGISTERED_SHMS.contains_key(&(shm as usize))
    }

    /// 在持有 SHMS 读锁期间读取共享内存缓冲区，消除释放竞态（UAF）。
    ///
    /// 校验条件：parent 地址已通过 `allocate` 登记、其 shm_id 对应的
    /// `ShmEntry` 仍存在于 SHMS、`parent.buffer` 与登记时的缓冲区指针一致
    /// （防止 CA 将 buffer 改指向其他缓冲区后绕过边界校验），并增加读取
    /// 区间边界检查（`offset..offset+size` 不得超出库内部记录的权威分配
    /// 大小）。
    ///
    /// `ShmEntry` 完全位于库内部内存，CA 无法篡改其 `size` 字段；相比之下，
    /// `TEEC_SharedMemory` 中的 `size` 与 `imp.alloced_size` 均位于 CA 可写
    /// 内存，可被恶意/缺陷 CA 放大以绕过 memref 边界校验，造成堆越界读写。
    ///
    /// `ShmEntry` 读锁守卫在数据拷贝完成前持续持有，期间并发的 `release`
    /// （其 `SHMS.remove` 需要写锁）会被阻塞，底层内存不会在读取中途被释放。
    pub fn read_buffer_locked(
        parent: *const raw::TEEC_SharedMemory,
        offset: usize,
        size: usize,
    ) -> Result<Vec<u8>> {
        let bad_params = || Error::new(ErrorKind::BadParameters);
        if parent.is_null() {
            return Err(bad_params());
        }
        let shm_id = *REGISTERED_SHMS
            .get(&(parent as usize))
            .ok_or_else(bad_params)?;
        // `entry` 守卫在函数返回前持续持有 SHMS 分片读锁：
        // 并发 release 的 SHMS.remove（写锁）在此期间阻塞。
        let entry = SHMS.get(&shm_id).ok_or_else(bad_params)?;
        // SAFETY: `parent` 非空且已通过地址登记校验，为调用方提供的
        // `TEEC_SharedMemory` 结构体；仅读取其 buffer 字段用于一致性比对。
        let parent_ref = unsafe { &*parent };
        let buf_ptr = parent_ref.buffer as *const u8;
        if buf_ptr.is_null() || !std::ptr::eq(buf_ptr, entry.value().ptr) {
            warn!(
                "[HOST] read_buffer_locked: parent={:p} buffer 指针与登记不一致 entry_ptr={:p}，拒绝读取",
                parent,
                entry.value().ptr
            );
            return Err(bad_params());
        }
        if offset.saturating_add(size) > entry.value().size {
            warn!(
                "[HOST] read_buffer_locked: parent={:p} 越界读取 offset={} size={} 权威大小={}，拒绝读取",
                parent,
                offset,
                size,
                entry.value().size
            );
            return Err(bad_params());
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        // SAFETY: `buf_ptr` 非空且 `offset..offset+size` 已验证在权威大小内；
        // 读锁持有期间底层内存不会被释放，读取是内存安全的。
        let start = unsafe { buf_ptr.add(offset) };
        Ok(unsafe { std::slice::from_raw_parts(start, size) }.to_vec())
    }

    /// 在持有 SHMS 读锁期间写入共享内存缓冲区，消除释放竞态（UAF）。
    ///
    /// 校验条件与 [`read_buffer_locked`] 相同；写入区间
    /// （`offset..offset+data.len()`）不得超出库内部记录的权威分配大小。
    /// `ShmEntry` 读锁守卫在写入完成前持续持有，期间并发的 `release`
    /// 会被阻塞，底层内存不会在写入中途被释放。
    pub fn write_buffer_locked(
        parent: *const raw::TEEC_SharedMemory,
        offset: usize,
        data: &[u8],
    ) -> Result<()> {
        let bad_params = || Error::new(ErrorKind::BadParameters);
        if parent.is_null() {
            return Err(bad_params());
        }
        let shm_id = *REGISTERED_SHMS
            .get(&(parent as usize))
            .ok_or_else(bad_params)?;
        // `entry` 守卫在写入完成前持续持有 SHMS 分片读锁。
        let entry = SHMS.get(&shm_id).ok_or_else(bad_params)?;
        // SAFETY: `parent` 非空且已通过地址登记校验，为调用方提供的
        // `TEEC_SharedMemory` 结构体；仅读取其 buffer 字段用于一致性比对。
        let parent_ref = unsafe { &*parent };
        let buf_ptr = parent_ref.buffer as *mut u8;
        if buf_ptr.is_null() || !std::ptr::eq(buf_ptr, entry.value().ptr) {
            warn!(
                "[HOST] write_buffer_locked: parent={:p} buffer 指针与登记不一致 entry_ptr={:p}，拒绝写入",
                parent,
                entry.value().ptr
            );
            return Err(bad_params());
        }
        if offset.saturating_add(data.len()) > entry.value().size {
            warn!(
                "[HOST] write_buffer_locked: parent={:p} 越界写入 offset={} len={} 权威大小={}，拒绝写入",
                parent,
                offset,
                data.len(),
                entry.value().size
            );
            return Err(bad_params());
        }
        if data.is_empty() {
            return Ok(());
        }
        // SAFETY: `buf_ptr` 非空且 `offset..offset+data.len()` 已验证在权威
        // 大小内；读锁持有期间底层内存不会被释放，写入是内存安全的。
        let dst = unsafe { buf_ptr.add(offset) };
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };
        Ok(())
    }

    /// 从缓存中获取共享内存数据（按 ID 查找）
    ///
    /// 仅测试使用：生产路径中 memref 读写经由 `read_buffer_locked` /
    /// `write_buffer_locked` 在锁保护下完成，不再走此回退查询。
    #[cfg(test)]
    pub fn get_buffer(shm: *const raw::TEEC_SharedMemory) -> Option<Vec<u8>> {
        if shm.is_null() {
            return None;
        }

        // SAFETY: `shm` 已由上面的 null 检查验证为非空指针。
        // 获取引用以便多次检查字段一致性。
        let shm_ref = unsafe { &*shm };
        let id = shm_ref.imp.id;

        if id == SHM_ID_NONE || shm_ref.buffer.is_null() {
            return None;
        }

        SHMS.get(&id).and_then(|entry| {
            // SAFETY: entry.ptr 由 alloc::alloc 返回，entry.size 字节可读。
            let entry_ptr = entry.value().ptr;
            let entry_size = entry.value().size;

            if entry_ptr.is_null() || entry_size == 0 {
                return None;
            }

            // 仅当共享内存表中的 ptr 与传入的 shm.buffer 匹配时才返回数据，
            // 避免单纯通过 id 误匹配（例如测试间静态表污染）。
            if !std::ptr::eq(entry_ptr, shm_ref.buffer as *mut u8) {
                return None;
            }

            Some(unsafe { std::slice::from_raw_parts(entry_ptr, entry_size).to_vec() })
        })
    }

    /// 按上下文释放所有关联的共享内存。
    ///
    /// 在 `TEEC_FinalizeContext` 中调用，遍历全局共享内存表，
    /// 删除所有属于指定 context_id 的条目。被删除的 `ShmEntry`
    /// 在 Drop 时自动调用 `alloc::dealloc` 释放底层内存。
    pub fn release_by_context(ctx: *mut raw::TEEC_Context) {
        // 按地址登记表校验，并核对 imp.fd 与登记 id 一致：未登记指针或
        // fd 被篡改时不清理，防止误删其他上下文的共享内存条目。
        let Some(registered_id) = ContextManager::registered_id(ctx) else {
            return;
        };
        if let Ok(ctx_nn) = safe_ptr::deref(ctx) {
            // SAFETY: `ctx_nn` 已由 `deref` 验证非空，且该地址已通过登记表
            // 校验为本库初始化过的上下文。
            let ctx_ref = unsafe { ctx_nn.as_ref() };
            let context_id = ctx_ref.imp.fd;
            if context_id != registered_id {
                return;
            }
            SHMS.retain(|_, entry| entry.context_id != context_id);
            // REGISTERED_SHMS 的值为 shm_id（而非 context_id）：同步清理其
            // shm 条目已随 SHMS 移除的地址登记，保持两表一致。
            REGISTERED_SHMS.retain(|_, shm_id| SHMS.contains_key(shm_id));
        }
    }
}

#[cfg(test)]
mod shared_memory_tests {
    use super::*;

    fn create_test_context(id: i32) -> raw::TEEC_Context {
        raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: id,
                memref_null: false,
                reg_mem: false,
            },
        }
    }

    fn create_test_shm() -> raw::TEEC_SharedMemory {
        raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 0,
            flags: 0,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                registered_fd: -1,
                shadow_buffer: ptr::null_mut(),
                alloced_size: 0,
                flags: 0,
            },
        }
    }

    #[test]
    fn test_allocate_valid_memory() {
        // 测试正常分配共享内存
        let mut ctx = create_test_context(100);
        let mut shm = create_test_shm();

        shm.size = 64;
        shm.flags = raw::TEEC_MEM_INPUT;

        let result = SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        );

        assert!(result.is_ok(), "应该成功分配共享内存");
        assert!(!shm.buffer.is_null(), "缓冲区指针应该非空");
        assert!(shm.imp.id >= 0, "ID 应该为非负的唯一共享内存 id");
        assert_eq!(shm.imp.alloced_size, 64, "分配大小应该正确");

        SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);
    }

    #[test]
    fn test_allocate_with_registration() {
        // 测试带注册的共享内存分配
        let mut ctx = create_test_context(101);
        let mut data = vec![1u8, 2, 3, 4, 5];
        let mut shm = create_test_shm();

        shm.size = data.len();
        shm.flags = raw::TEEC_MEM_INPUT;
        shm.buffer = data.as_mut_ptr() as *mut std::ffi::c_void;

        let result = SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            true,
        );

        assert!(result.is_ok(), "应该成功注册共享内存");

        // 验证数据被正确复制
        if let Some(buffer) = SharedMemoryManager::get_buffer(&shm) {
            assert_eq!(buffer, data, "数据应该被正确复制");
        }

        SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);
    }

    #[test]
    fn test_allocate_zero_size() {
        // 测试零大小分配（应该失败）
        let mut ctx = create_test_context(102);
        let mut shm = create_test_shm();

        shm.size = 0;
        shm.flags = raw::TEEC_MEM_INPUT;

        let result = SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        );

        assert!(result.is_err(), "零大小分配应该失败");
    }

    #[test]
    fn test_allocate_invalid_flags() {
        // 测试无效标志位（应该失败）
        let mut ctx = create_test_context(103);
        let mut shm = create_test_shm();

        shm.size = 64;
        shm.flags = 0; // 无效标志

        let result = SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        );

        assert!(result.is_err(), "无效标志位应该导致失败");
    }

    #[test]
    fn test_allocate_excessive_size() {
        // 测试过大的内存分配（应该失败）
        let mut ctx = create_test_context(104);
        let mut shm = create_test_shm();

        shm.size = MAX_SHARED_MEMORY_SIZE + 1;
        shm.flags = raw::TEEC_MEM_INPUT;

        let result = SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        );

        assert!(result.is_err(), "过大的分配应该失败");
    }

    #[test]
    fn test_allocate_null_context() {
        // 测试空上下文指针（应该失败）
        let mut shm = create_test_shm();

        shm.size = 64;
        shm.flags = raw::TEEC_MEM_INPUT;

        let result = SharedMemoryManager::allocate(
            ptr::null_mut(),
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        );

        assert!(result.is_err(), "空上下文应该导致失败");
    }

    #[test]
    fn test_allocate_null_shm() {
        // 测试空共享内存指针（应该失败）
        let mut ctx = create_test_context(105);

        let result = SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            ptr::null_mut(),
            false,
        );

        assert!(result.is_err(), "空共享内存指针应该导致失败");
    }

    #[test]
    fn test_release_valid_memory() {
        // 测试正常释放共享内存
        let mut ctx = create_test_context(106);
        let mut shm = create_test_shm();

        shm.size = 64;
        shm.flags = raw::TEEC_MEM_INPUT;

        SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        )
        .unwrap();

        // 验证内存已分配
        assert!(SharedMemoryManager::get_buffer(&shm).is_some());

        SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);

        assert_eq!(shm.imp.id, -1, "ID 应该被重置为 -1");
        assert_eq!(shm.size, 0, "大小应该被重置为 0");
        assert!(shm.buffer.is_null(), "缓冲区指针应该为空");
        assert!(
            SharedMemoryManager::get_buffer(&shm).is_none(),
            "缓存应该被清除"
        );
    }

    #[test]
    fn test_release_null_shm() {
        // 测试释放空指针（应该安全，不 panic）
        SharedMemoryManager::release(ptr::null_mut());
        // 不应该 panic
    }

    #[test]
    fn test_release_already_released() {
        // 测试重复释放（应该安全）
        let mut ctx = create_test_context(107);
        let mut shm = create_test_shm();

        shm.size = 64;
        shm.flags = raw::TEEC_MEM_INPUT;

        SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        )
        .unwrap();

        // 第一次释放
        SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);

        // 第二次释放（应该安全）
        SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);
    }

    #[test]
    fn test_get_buffer_null_shm() {
        // 测试从空指针获取缓冲区
        let result = SharedMemoryManager::get_buffer(ptr::null());
        assert!(result.is_none(), "空指针应该返回 None");
    }

    #[test]
    fn test_get_buffer_unregistered() {
        // 测试从未注册的共享内存获取缓冲区
        let shm = create_test_shm();
        let result = SharedMemoryManager::get_buffer(&shm);
        assert!(result.is_none(), "未注册的共享内存应该返回 None");
    }

    #[test]
    fn test_multiple_allocations() {
        // 测试多次分配和释放
        let mut contexts = vec![];
        let mut shms = vec![];

        for i in 200..205 {
            let mut ctx = create_test_context(i);
            let mut shm = create_test_shm();
            shm.size = 32;
            shm.flags = raw::TEEC_MEM_INPUT;

            SharedMemoryManager::allocate(
                &mut ctx as *mut raw::TEEC_Context,
                &mut shm as *mut raw::TEEC_SharedMemory,
                false,
            )
            .unwrap();

            contexts.push(ctx);
            shms.push(shm);
        }

        // 验证所有分配都成功
        for shm in &shms {
            assert!(SharedMemoryManager::get_buffer(shm).is_some());
        }

        // 释放所有
        for shm in &mut shms {
            SharedMemoryManager::release(shm as *mut raw::TEEC_SharedMemory);
        }

        // 验证所有都已释放
        for shm in &shms {
            assert!(SharedMemoryManager::get_buffer(shm).is_none());
        }
    }

    #[test]
    fn test_allocate_both_flags() {
        // 测试同时设置 INPUT 和 OUTPUT 标志
        let mut ctx = create_test_context(300);
        let mut shm = create_test_shm();

        shm.size = 64;
        shm.flags = raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT;

        let result = SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        );

        assert!(result.is_ok(), "同时设置 INPUT 和 OUTPUT 应该成功");

        SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);
    }

    #[test]
    fn test_allocate_exactly_max_size() {
        // 测试分配正好等于最大大小的内存
        let mut ctx = create_test_context(301);
        let mut shm = create_test_shm();

        shm.size = MAX_SHARED_MEMORY_SIZE;
        shm.flags = raw::TEEC_MEM_INPUT;

        let result = SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        );

        assert!(result.is_ok(), "正好等于最大大小应该成功");

        SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);
    }

    #[test]
    fn test_allocate_invalid_flag_combinations() {
        // 测试各种无效的标志位组合
        let mut ctx = create_test_context(303);

        // 测试 1: 只有 OUTPUT 没有 INPUT（某些实现可能不允许）
        let mut shm = create_test_shm();
        shm.size = 64;
        shm.flags = raw::TEEC_MEM_OUTPUT;

        let result = SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        );
        // 这个可能成功或失败，取决于实现
        // 我们只确保不会 panic
        drop(result);

        // 测试 2: 随机无效标志
        shm.flags = 0x12345678;
        let result = SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        );
        assert!(result.is_err(), "无效标志位应该失败");
    }

    #[test]
    fn test_release_with_different_states() {
        // 测试在不同状态下释放共享内存

        // 测试 1: 从未分配的共享内存
        let mut shm1 = create_test_shm();
        SharedMemoryManager::release(&mut shm1 as *mut raw::TEEC_SharedMemory);
        assert_eq!(shm1.imp.id, -1);

        // 测试 2: 已分配但未注册的共享内存
        let mut ctx = create_test_context(304);
        let mut shm2 = create_test_shm();

        shm2.size = 32;
        shm2.flags = raw::TEEC_MEM_INPUT;

        SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm2 as *mut raw::TEEC_SharedMemory,
            false,
        )
        .unwrap();

        SharedMemoryManager::release(&mut shm2 as *mut raw::TEEC_SharedMemory);
        assert_eq!(shm2.imp.id, -1);
        assert_eq!(shm2.size, 0);
    }

    #[test]
    fn test_get_buffer_edge_cases() {
        let mut shm = create_test_shm();
        shm.imp.id = 0;
        let result = SharedMemoryManager::get_buffer(&shm);
        assert!(result.is_none());
    }

    #[test]
    fn test_stress_multiple_rapid_allocations() {
        let mut ctx = create_test_context(400);

        for i in 0..100 {
            let mut shm = create_test_shm();
            shm.size = 16;
            shm.flags = raw::TEEC_MEM_INPUT;

            let result = SharedMemoryManager::allocate(
                &mut ctx as *mut raw::TEEC_Context,
                &mut shm as *mut raw::TEEC_SharedMemory,
                false,
            );

            assert!(result.is_ok(), "第 {} 次分配应该成功", i);

            SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);
        }
    }

    #[test]
    fn test_multiple_allocations_same_context() {
        let mut ctx = create_test_context(500);
        let mut shm1 = create_test_shm();
        shm1.size = 32;
        shm1.flags = raw::TEEC_MEM_INPUT;

        let mut shm2 = create_test_shm();
        shm2.size = 64;
        shm2.flags = raw::TEEC_MEM_INPUT;

        SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm1 as *mut raw::TEEC_SharedMemory,
            false,
        )
        .unwrap();

        SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm2 as *mut raw::TEEC_SharedMemory,
            false,
        )
        .unwrap();

        assert_ne!(
            shm1.imp.id, shm2.imp.id,
            "同一 context 下多次分配应该有不同的 shm id"
        );
        assert!(SharedMemoryManager::get_buffer(&shm1).is_some());
        assert!(SharedMemoryManager::get_buffer(&shm2).is_some());

        SharedMemoryManager::release(&mut shm1 as *mut raw::TEEC_SharedMemory);
        assert!(SharedMemoryManager::get_buffer(&shm1).is_none());
        assert!(
            SharedMemoryManager::get_buffer(&shm2).is_some(),
            "释放 shm1 不应影响 shm2"
        );

        SharedMemoryManager::release(&mut shm2 as *mut raw::TEEC_SharedMemory);
        assert!(SharedMemoryManager::get_buffer(&shm2).is_none());
    }

    #[test]
    fn test_read_write_buffer_locked_basic() {
        // 回归测试：锁内读写的基本功能与往返一致性
        let mut ctx = create_test_context(600);
        let mut shm = create_test_shm();
        shm.size = 32;
        shm.flags = raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT;

        SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        )
        .unwrap();

        let parent = &shm as *const raw::TEEC_SharedMemory;

        // 整段写入后读回
        SharedMemoryManager::write_buffer_locked(parent, 0, &[1, 2, 3, 4]).unwrap();
        let data = SharedMemoryManager::read_buffer_locked(parent, 0, 4).unwrap();
        assert_eq!(data, vec![1, 2, 3, 4]);

        // 带 offset 的部分读写（模拟 PARTIAL memref）
        SharedMemoryManager::write_buffer_locked(parent, 16, &[9, 8, 7]).unwrap();
        let data = SharedMemoryManager::read_buffer_locked(parent, 16, 3).unwrap();
        assert_eq!(data, vec![9, 8, 7]);

        // 空读 / 空写边界
        assert!(
            SharedMemoryManager::read_buffer_locked(parent, 0, 0)
                .unwrap()
                .is_empty()
        );
        SharedMemoryManager::write_buffer_locked(parent, 0, &[]).unwrap();

        SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);
    }

    #[test]
    fn test_locked_access_boundary_checks() {
        // 边界校验基于库内部权威大小，而非 CA 可写的 shm.size 字段
        let mut ctx = create_test_context(601);
        let mut shm = create_test_shm();
        shm.size = 16;
        shm.flags = raw::TEEC_MEM_INPUT;

        SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        )
        .unwrap();

        let parent = &shm as *const raw::TEEC_SharedMemory;

        // 越界读取：offset+size 超出权威大小
        assert!(SharedMemoryManager::read_buffer_locked(parent, 0, 17).is_err());
        assert!(SharedMemoryManager::read_buffer_locked(parent, 16, 1).is_err());
        // 越界写入
        assert!(SharedMemoryManager::write_buffer_locked(parent, 8, &[0u8; 9]).is_err());
        // 恰好在边界内应成功
        assert!(SharedMemoryManager::read_buffer_locked(parent, 0, 16).is_ok());
        assert!(SharedMemoryManager::write_buffer_locked(parent, 16, &[]).is_ok());

        // CA 篡改 shm.size 字段不能绕过校验（权威大小来自 ShmEntry）
        shm.size = 1024;
        assert!(SharedMemoryManager::read_buffer_locked(parent, 0, 512).is_err());
        assert!(SharedMemoryManager::write_buffer_locked(parent, 0, &[0u8; 512]).is_err());

        shm.size = 16;
        SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);
    }

    #[test]
    fn test_locked_access_rejects_tampered_buffer_ptr() {
        // CA 将 parent.buffer 改指向其他缓冲区：一致性比对失败，拒绝访问
        let mut ctx = create_test_context(602);
        let mut shm = create_test_shm();
        shm.size = 16;
        shm.flags = raw::TEEC_MEM_INPUT;

        SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        )
        .unwrap();

        let parent = &shm as *const raw::TEEC_SharedMemory;

        let mut fake = [0u8; 8];
        shm.buffer = fake.as_mut_ptr() as *mut std::ffi::c_void;

        assert!(SharedMemoryManager::read_buffer_locked(parent, 0, 4).is_err());
        assert!(SharedMemoryManager::write_buffer_locked(parent, 0, &[1, 2, 3, 4]).is_err());

        SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);
    }

    #[test]
    fn test_locked_access_rejects_unregistered_parent() {
        // 未登记地址 / null：返回 BadParameters 而非解引用崩溃
        let shm = create_test_shm();
        let parent = &shm as *const raw::TEEC_SharedMemory;

        assert!(SharedMemoryManager::read_buffer_locked(parent, 0, 4).is_err());
        assert!(SharedMemoryManager::write_buffer_locked(parent, 0, &[1]).is_err());

        let null_parent = ptr::null::<raw::TEEC_SharedMemory>();
        assert!(SharedMemoryManager::read_buffer_locked(null_parent, 0, 4).is_err());
        assert!(SharedMemoryManager::write_buffer_locked(null_parent, 0, &[1]).is_err());
    }

    #[test]
    fn test_concurrent_release_during_locked_read() {
        // UAF 竞态回归测试：read_buffer_locked 持读锁期间并发的
        // release 需要写锁，二者串行化。无论调度顺序如何，读取要么拿到完整
        // 数据（读锁先获取，release 被阻塞至拷贝完成），要么安全地返回
        // BadParameters（release 先完成、条目已移除）；不存在读取中途内存
        // 被释放的窗口。
        let mut ctx = create_test_context(603);
        let mut shm = create_test_shm();
        shm.size = 4096;
        shm.flags = raw::TEEC_MEM_INPUT;

        SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        )
        .unwrap();

        let parent = &shm as *const raw::TEEC_SharedMemory;
        SharedMemoryManager::write_buffer_locked(parent, 0, &[0xAA; 4096]).unwrap();

        let shm_addr = &mut shm as *mut raw::TEEC_SharedMemory as usize;
        let parent_addr = parent as usize;

        let releaser = std::thread::spawn(move || {
            SharedMemoryManager::release(shm_addr as *mut raw::TEEC_SharedMemory);
        });

        match SharedMemoryManager::read_buffer_locked(
            parent_addr as *const raw::TEEC_SharedMemory,
            0,
            4096,
        ) {
            Ok(data) => assert_eq!(data, vec![0xAA; 4096]),
            Err(_) => {
                // release 先完成：地址登记已移除，安全拒绝
            }
        }

        releaser.join().unwrap();
    }

    #[test]
    fn test_concurrent_locked_reads() {
        // 多线程并发锁内读取同一共享内存：均应得到完整一致的数据
        let mut ctx = create_test_context(604);
        let mut shm = create_test_shm();
        shm.size = 1024;
        shm.flags = raw::TEEC_MEM_INPUT;

        SharedMemoryManager::allocate(
            &mut ctx as *mut raw::TEEC_Context,
            &mut shm as *mut raw::TEEC_SharedMemory,
            false,
        )
        .unwrap();

        let parent = &shm as *const raw::TEEC_SharedMemory;
        SharedMemoryManager::write_buffer_locked(parent, 0, &[0x5A; 1024]).unwrap();

        let parent_addr = parent as usize;
        let readers: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(move || {
                    SharedMemoryManager::read_buffer_locked(
                        parent_addr as *const raw::TEEC_SharedMemory,
                        0,
                        1024,
                    )
                })
            })
            .collect();

        for reader in readers {
            let data = reader.join().unwrap().unwrap();
            assert_eq!(data, vec![0x5A; 1024]);
        }

        SharedMemoryManager::release(&mut shm as *mut raw::TEEC_SharedMemory);
    }
}
