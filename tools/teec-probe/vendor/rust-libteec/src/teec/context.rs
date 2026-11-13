// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! TEE 上下文管理模块
//!
//! 负责管理 TEE 上下文的生命周期和客户端连接

use std::sync::{
    Arc, LazyLock, Mutex,
    atomic::{AtomicI32, Ordering},
};

use dashmap::DashMap;

use super::safe_ptr;
use crate::{Error, ErrorKind, ErrorOrigin, Result, cc_client::client::CcClient, raw};

/// 全局上下文映射表：fd -> Arc<Mutex<CcClient>>
type ContextMap = DashMap<i32, Arc<Mutex<CcClient>>>;

/// 全局上下文管理器
static CONTEXTS: LazyLock<ContextMap> = LazyLock::new(DashMap::new);

/// 已登记上下文结构体地址表：TEEC_Context 结构体地址 -> context_id。
///
/// `get_client` 等路径在解引用 ctx 前按地址校验（纯地址比较、不解引用），
/// 拒绝从未通过 `TEEC_InitializeContext` 登记的垃圾/未初始化指针，避免
/// 解引用任意内存。取消请求（RequestCancellation）等路径中
/// session.imp.ctx 可能来自未成功打开的会话（CA 未初始化内存），该登记表
/// 是最后一道防线。
///
/// 定位为防垃圾/未初始化指针崩溃的健壮性加固，非对抗恶意 CA 的硬边界：
/// CA 拥有自身进程，真正的访问控制由 TA 侧 ACL 与 x-kernel exec 层 TA
/// 验签负责。
type RegisteredCtxMap = DashMap<usize, i32>;

/// 已登记上下文结构体地址集合，与 CONTEXTS 同步维护：
/// add_context 时登记、remove_context 时移除。
static REGISTERED_CTXS: LazyLock<RegisteredCtxMap> = LazyLock::new(DashMap::new);

/// 上下文管理器，提供线程安全的上下文操作
pub struct ContextManager;

impl ContextManager {
    /// 添加新的 TEE 上下文到全局管理
    pub fn add_context(ctx: *mut raw::TEEC_Context, client: CcClient) -> Result<()> {
        let mut ctx_nn = safe_ptr::deref_mut(ctx)?;
        // SAFETY: `ctx_nn` 是由 `deref_mut` 返回的 `NonNull`，已验证指针为非空。
        // 调用 `as_mut()` 可获得指向底层 `raw::TEEC_Context` 的可变引用，
        // 该引用在此借用期间有效。
        let ctx_ref = unsafe { ctx_nn.as_mut() };
        let ctx_id: i32 = ctx_ref.imp.fd;
        let client_arc = Arc::new(Mutex::new(client));

        if CONTEXTS.contains_key(&ctx_id) {
            log::warn!(
                "ContextManager: context {} already exists, rejecting duplicate",
                ctx_id
            );
            return Err(Error::new(ErrorKind::BadState).with_origin(ErrorOrigin::API));
        }

        CONTEXTS.insert(ctx_id, client_arc);
        // 同时按结构体地址登记，供 get_client 在解引用前校验 ctx 指针
        // 为本库初始化过的对象。
        REGISTERED_CTXS.insert(ctx as usize, ctx_id);

        Ok(())
    }

    /// 按结构体地址查询登记的 context_id（纯地址比较，不解引用）。
    pub fn registered_id(ctx: *mut raw::TEEC_Context) -> Option<i32> {
        REGISTERED_CTXS
            .get(&(ctx as usize))
            .map(|entry| *entry.value())
    }

    /// 校验结构体指针是否为本库登记过的上下文（纯地址比较，不解引用）。
    pub fn is_registered(ctx: *mut raw::TEEC_Context) -> bool {
        !ctx.is_null() && REGISTERED_CTXS.contains_key(&(ctx as usize))
    }

    /// 从全局管理中移除 TEE 上下文。
    ///
    /// 移除前按地址登记表校验 ctx，并核对 `imp.fd` 与登记 id 一致：
    /// 未登记的指针（垃圾/未初始化内存）或 `imp.fd` 被篡改的上下文
    /// 直接拒绝清理，不触碰任何全局状态，防止关闭其他上下文的连接。
    pub fn remove_context(ctx: *mut raw::TEEC_Context) {
        let Some(registered_id) = Self::registered_id(ctx) else {
            log::warn!("ContextManager: remove_context: ctx 未登记，忽略");
            return;
        };

        if let Ok(mut ctx_nn) = safe_ptr::deref_mut(ctx) {
            // SAFETY: `ctx_nn` 为 `deref_mut` 返回的 `NonNull`，已验证非空，
            // 且该地址已通过登记表校验为本库初始化过的上下文。
            let ctx_ref = unsafe { ctx_nn.as_mut() };
            let ctx_id = ctx_ref.imp.fd;
            if ctx_id != registered_id {
                log::warn!(
                    "ContextManager: remove_context: imp.fd {ctx_id} 与登记 id {registered_id} 不一致，忽略"
                );
                return;
            }
            // 先关闭 TLS 连接，再从全局管理器中移除
            if let Some((_, client_arc)) = CONTEXTS.remove(&ctx_id)
                && let Ok(mut client) = client_arc.lock()
            {
                client.close();
            }
            ctx_ref.imp.fd = -1;
            REGISTERED_CTXS.remove(&(ctx as usize));
        }
    }

    /// 查找上下文对应的 CcClient 连接
    pub fn get_client(ctx: *mut raw::TEEC_Context) -> Result<Arc<Mutex<CcClient>>> {
        // 先按地址校验 ctx 为本库登记过的上下文（纯地址比较、不解引用），
        // 拒绝未通过 TEEC_InitializeContext 登记的垃圾/未初始化指针，
        // 避免解引用任意内存。
        let registered_id = REGISTERED_CTXS
            .get(&(ctx as usize))
            .map(|entry| *entry.value())
            .ok_or_else(|| Error::new(ErrorKind::BadParameters).with_origin(ErrorOrigin::API))?;

        let ctx_nn = safe_ptr::deref(ctx)?;
        // SAFETY: `ctx_nn` 已由 `deref` 验证为非空；`as_ref()` 返回的不可变引用
        // 在此作用域内有效。
        let ctx_ref = unsafe { ctx_nn.as_ref() };
        let ctx_id = ctx_ref.imp.fd;

        // 地址登记的 id 必须与结构体中当前 id 一致，防止 CA 篡改 imp.fd
        // 后借用其他上下文的连接。
        if ctx_id != registered_id {
            return Err(Error::new(ErrorKind::BadParameters).with_origin(ErrorOrigin::API));
        }

        CONTEXTS
            .get(&ctx_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| Error::new(ErrorKind::Generic).with_origin(ErrorOrigin::API))
    }
}

/// 全局上下文 ID 计数器，每次 `TEEC_InitializeContext` 调用递增。
static CONTEXT_ID_COUNTER: LazyLock<AtomicI32> = LazyLock::new(|| AtomicI32::new(0));

pub(crate) fn initialize_context_impl(ctx: *mut raw::TEEC_Context) -> Result<()> {
    let mut ctx_nn = safe_ptr::deref_mut(ctx)?;
    // SAFETY: `ctx_nn` 已由 `deref_mut` 验证为非空。`as_mut()` 返回指向
    // 上下文的可变引用，该引用在此作用域中有效。
    let ctx_ref = unsafe { ctx_nn.as_mut() };

    let client = CcClient::init().map_err(|e| {
        log::warn!("TEEC_InitializeContext：初始化机密通信上下文失败：{e}");
        Error::new(ErrorKind::Communication)
    })?;

    let id = CONTEXT_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

    ctx_ref.imp.fd = id;
    ctx_ref.imp.reg_mem = true;
    ctx_ref.imp.memref_null = true;

    ContextManager::add_context(ctx, client)
}

#[cfg(test)]
mod context_tests {
    use super::*;
    use std::ptr;

    fn create_test_context(id: i32) -> raw::TEEC_Context {
        raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: id,
                memref_null: false,
                reg_mem: false,
            },
        }
    }

    // 注意：由于 CcClient 需要实际的 TLS 连接，我们只能测试上下文管理的逻辑部分
    // 完整的 CcClient 测试应该在集成测试中进行

    #[test]
    fn test_remove_context_null_ptr() {
        // 测试移除空指针上下文（应该安全，不 panic）
        ContextManager::remove_context(ptr::null_mut());
        // 不应该 panic
    }

    #[test]
    fn test_get_client_null_ptr() {
        // 测试获取空指针上下文的客户端（应该失败）
        let result = ContextManager::get_client(ptr::null_mut());
        assert!(result.is_err(), "空指针应该导致失败");
    }

    #[test]
    fn test_get_client_unregistered() {
        // 测试获取未注册上下文的客户端（应该失败）
        let mut ctx = create_test_context(999);
        let result = ContextManager::get_client(&mut ctx as *mut raw::TEEC_Context);
        assert!(result.is_err(), "未注册的上下文应该导致失败");
    }

    #[test]
    fn test_context_lifecycle() {
        // 测试上下文的生命周期管理：登记后移除应重置 fd 并清除登记
        let mut ctx = create_test_context(1000);
        let ctx_addr = &mut ctx as *mut raw::TEEC_Context as usize;
        REGISTERED_CTXS.insert(ctx_addr, 1000);

        // 验证初始状态
        assert_eq!(ctx.imp.fd, 1000);

        // 模拟移除
        ContextManager::remove_context(&mut ctx as *mut raw::TEEC_Context);
        assert_eq!(ctx.imp.fd, -1, "移除后 ID 应该被重置为 -1");
        assert!(
            !REGISTERED_CTXS.contains_key(&ctx_addr),
            "移除后应清除地址登记"
        );
    }

    #[test]
    fn test_remove_context_unregistered_noop() {
        // 未登记地址（从未 InitializeContext）的上下文：移除必须是 no-op，
        // 不得解引用读取内容或修改任何状态。
        let mut ctx = create_test_context(1001);
        ContextManager::remove_context(&mut ctx as *mut raw::TEEC_Context);
        assert_eq!(ctx.imp.fd, 1001, "未登记的上下文不应被修改");
    }

    #[test]
    fn test_remove_context_fd_tamper_rejected() {
        // 地址已登记但 imp.fd 被篡改：必须拒绝清理，防止通过篡改后的
        // fd 关闭其他上下文的连接。
        let mut ctx = create_test_context(2002);
        let ctx_addr = &mut ctx as *mut raw::TEEC_Context as usize;
        REGISTERED_CTXS.insert(ctx_addr, 2002);

        // 模拟 CA 篡改 imp.fd
        ctx.imp.fd = 1337;
        ContextManager::remove_context(&mut ctx as *mut raw::TEEC_Context);

        assert_eq!(ctx.imp.fd, 1337, "fd 篡改时不应写入结构体");
        assert!(
            REGISTERED_CTXS.contains_key(&ctx_addr),
            "fd 篡改时不应清除登记"
        );

        // 清理登记，避免污染其他测试
        REGISTERED_CTXS.remove(&ctx_addr);
    }

    #[test]
    fn test_get_client_registered_addr_fd_mismatch_rejected() {
        // 地址已登记但 CA 篡改 imp.fd 指向其他 id：必须拒绝，防止借用
        // 其他上下文的 TLS 连接。
        // 说明：add_context 需要真实 CcClient（TLS 连接），此处直接操作
        // 内部登记表模拟已登记状态。
        let mut ctx = create_test_context(2000);
        let ctx_addr = &mut ctx as *mut raw::TEEC_Context as usize;
        REGISTERED_CTXS.insert(ctx_addr, 2000);

        // 模拟 CA 篡改 imp.fd
        ctx.imp.fd = 1999;
        let result = ContextManager::get_client(&mut ctx as *mut raw::TEEC_Context);
        assert!(
            result.is_err(),
            "imp.fd 与地址登记的 context_id 不一致应被拒绝"
        );

        // 清理登记，避免污染其他测试
        REGISTERED_CTXS.remove(&ctx_addr);
    }

    #[test]
    fn test_remove_context_clears_addr_registration() {
        // remove_context 必须同步清除地址登记，防止后续通过已 Finalize
        // 的 ctx 地址继续获取连接。
        let mut ctx = create_test_context(2001);
        let ctx_addr = &mut ctx as *mut raw::TEEC_Context as usize;
        REGISTERED_CTXS.insert(ctx_addr, 2001);

        ContextManager::remove_context(&mut ctx as *mut raw::TEEC_Context);

        assert!(
            !REGISTERED_CTXS.contains_key(&ctx_addr),
            "移除上下文后应清除地址登记"
        );
    }
}
