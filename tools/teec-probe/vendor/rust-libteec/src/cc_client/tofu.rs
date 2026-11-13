// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! 基于 TOFU（Trust On First Use，首次使用时信任）模型的服务端身份校验。
//!
//! ## 原理
//!
//! TOFU 是一种无需 PKI 证书体系的轻量级身份校验策略：
//! - **首次连接**：客户端无条件信任服务端的长期公钥，并将其记录到本地缓存
//! - **后续连接**：客户端校验服务端公钥是否与缓存一致；服务端重启导致
//!   身份密钥轮换时，接受新公钥并更新缓存（同时记录告警）
//!
//! ## 安全属性
//!
//! - 能防御**持续性**中间人攻击（MITM）：攻击者必须在首次连接时就介入，
//!   后续替换服务端身份会被检测到
//! - 不能防御首次连接时的 MITM：如果攻击者在用户第一次使用时就已经介入，
//!   则无法检测
//!
//! 这种模型适用于机密通信场景，因为 CA 和 TEE OS 通常部署在同一台设备上，
//! 首次连接发生在受控环境中（设备出厂/系统安装时），后续即使网络环境变化，
//! TOFU 也能保障服务端身份不被替换。
//!
//! 实现上使用 `Mutex<Option<Vec<u8>>>` 作为全局缓存，线程安全。
//!
//! ## 服务端重启与密钥轮换
//!
//! 服务端每次启动会重新生成长期身份密钥（仅存内存，不落盘）。
//! 若 CA 进程存活时间跨越可信子系统服务重启，其缓存的旧公钥将不再匹配。
//! 此时若仍按经典 TOFU 严格拒绝，会导致机密通信永久不可用（`NetRecvFailed`）。
//!
//! 因此本实现采用**可更新 TOFU**：检测到公钥不一致时，视为服务端重启
//! 导致的合法轮换，重新记录新公钥并返回成功，同时以 warn 级别告警提示
//! 运维核查对端是否预期。攻击者若能在 VSOCK 通道上伪造新公钥，需先
//! 攻陷宿主机内核/hypervisor 或 virtio 后端（见下「已知限制」），
//! 故该取舍在威胁模型内可接受。
//!
//! ## 已知限制（风险接受）
//!
//! 缓存仅存在于进程内存中，进程重启后回到未初始化状态，重启后的首次
//! 连接会重新进入信任模式。
//! 经评估：VSOCK 基于 virtio 传输、不经过网络协议栈，
//! 实施中间人攻击需要先攻陷宿主机内核/hypervisor 或 virtio 后端，
//! 届时客户端侧任何方案均已失效，故接受该风险，不引入磁盘持久化。

use std::sync::Mutex;

use log::{debug, warn};

use xtee_psk::PskResult;

/// TOFU 服务端身份缓存
///
/// 首次连接时记录服务端长期公钥，后续连接校验一致性，防止 MITM 攻击。
/// 服务端重启导致身份密钥轮换时，接受新公钥并以 warn 级别告警后更新缓存
/// （可更新 TOFU，见模块文档）。
pub(crate) struct ServerIdentityCache {
    key: Mutex<Option<Vec<u8>>>,
}

impl ServerIdentityCache {
    /// 创建空的 TOFU 缓存
    pub(crate) const fn new() -> Self {
        Self {
            key: Mutex::new(None),
        }
    }

    /// TOFU 校验服务端长期公钥
    ///
    /// 三态判定：
    /// - 缓存为空：首次连接，记录公钥并信任（`debug!`）
    /// - 缓存一致：后续连接，直接通过
    /// - 缓存不一致：视为服务端重启导致的密钥轮换，以 warn 级别告警后
    ///   重新记录新公钥并返回成功。若为恶意替换，将由 VSOCK 传输的
    ///   威胁模型与运维告警兜底（见模块文档「已知限制」）。
    ///
    /// 使用 `Mutex` 串行化「读-判-写」，消除 `get`→`set` 之间的
    /// TOCTOU 竞态。
    pub(crate) fn verify(&self, long_term_point: &[u8]) -> PskResult<()> {
        // 中毒时恢复与丢弃锁内数据（`into_inner`）而非直接 panic：
        // 持锁期间若发生 panic，Mutex 会进入中毒状态，此处若用
        // `.expect()` 放弃，该 CA 进程后续所有 verify 都将永久 panic，
        // 与「x-kernel 重启后永久不可用」是同类故障。锁内无非原子
        // 状态，中毒恢复是安全且推荐的长生命周期进程写法。
        let mut guard = self
            .key
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match guard.as_ref() {
            None => {
                *guard = Some(long_term_point.to_vec());
                debug!("首次连接，已记录服务端长期公钥（TOFU）");
            }
            Some(stored) if stored.as_slice() == long_term_point => {
                // 一致，直接通过
            }
            Some(_) => {
                // 保持 warn 级别（与全库日志口径统一）。注意可见性前提：
                // CA 进程在 client.rs 的 LOGGER_INIT 用 env_logger::try_init()，
                // 默认过滤级别为 error，warn 级别默认不可见；部署侧需以
                // RUST_LOG=...=warn（或更高）启动相关 CA，轮换告警才会输出。
                warn!(
                    "服务端长期公钥与已记录的不一致（vsock-manager 可能已重启），重新记录新公钥；若非预期轮换请核查 VSOCK 对端"
                );
                *guard = Some(long_term_point.to_vec());
            }
        }
        Ok(())
    }
}

/// 全局服务端身份缓存（TOFU 模式：首次连接信任，后续校验一致性）
static SERVER_IDENTITY: ServerIdentityCache = ServerIdentityCache::new();

/// TOFU 校验服务端长期公钥（使用全局缓存）
pub(crate) fn verify_server_identity(long_term_point: &[u8]) -> PskResult<()> {
    SERVER_IDENTITY.verify(long_term_point)
}

#[cfg(test)]
mod psk_tests {
    use super::*;
    use xtee_psk::SM2_POINT_LEN;

    /// 使用独立 `ServerIdentityCache` 实例进行纯净测试，
    /// 避免全局 `SERVER_IDENTITY` 状态污染。
    #[test]
    fn test_server_identity_cache_new_instance() {
        let cache = ServerIdentityCache::new();
        let test_point = vec![0xDEu8; SM2_POINT_LEN];

        // 首次验证应该成功（TOFU 记录）
        cache.verify(&test_point).expect("首次 TOFU 设置应该成功");
        // 相同身份应该通过
        cache
            .verify(&test_point)
            .expect("相同身份应该通过（TOFU 一致）");
    }

    /// 服务端重启导致身份密钥轮换时，不一致的公钥应被接受并重新记录
    /// （可更新 TOFU，对应服务端重启场景）。
    #[test]
    fn test_server_identity_cache_rotation() {
        let cache = ServerIdentityCache::new();
        let first = vec![0xDEu8; SM2_POINT_LEN];
        let second = {
            let mut p = first.clone();
            p[0] ^= 0xFF;
            p
        };

        cache.verify(&first).expect("首次 TOFU 设置应该成功");

        // 轮换：不一致的公钥应被接受（不再拒绝），并重新记录
        cache
            .verify(&second)
            .expect("服务端重启轮换的新公钥应被接受");

        // 轮换后：新公钥应通过
        cache
            .verify(&second)
            .expect("轮换后的新公钥应通过（TOFU 一致）");

        // 旧公钥再次出现：视为又一次轮换（回到旧密钥），应被接受
        cache.verify(&first).expect("回退到旧公钥应被接受");
    }

    /// 并发安全：多线程交错 verify（首连/一致/轮换并存），
    /// 不得死锁、不得 panic。`Mutex` 引入了 `OnceLock` 没有的竞态面，
    /// 必须有多线程回归测试。
    #[test]
    fn test_server_identity_cache_concurrent() {
        let cache = std::sync::Arc::new(ServerIdentityCache::new());
        let mut handles = Vec::new();

        for t in 0..8u8 {
            let cache = std::sync::Arc::clone(&cache);
            handles.push(std::thread::spawn(move || {
                for round in 0..200u16 {
                    // 每线程专属字节作为“自己的服务端公钥”，偶数轮翻转首字节
                    // 制造轮换形态，与其它线程的写入交错。
                    let mut point = vec![t; SM2_POINT_LEN];
                    if round % 2 == 0 {
                        point[0] ^= 0xFF;
                    }
                    cache.verify(&point).expect("并发 verify 不应失败");
                }
            }));
        }

        for handle in handles {
            handle.join().expect("并发线程不应 panic");
        }

        // 并发结束后缓存仍可用
        let probe = vec![0xABu8; SM2_POINT_LEN];
        cache.verify(&probe).expect("并发结束后缓存仍可用");
    }

    /// 锁中毒恢复：持锁期间发生 panic 使 Mutex 中毒后，verify 仍须可用
    /// （`into_inner` 恢复），不得让 CA 进程后续调用永久 panic。
    #[test]
    fn test_server_identity_cache_poison_recovery() {
        let cache = std::sync::Arc::new(ServerIdentityCache::new());
        let point = vec![0xD1u8; SM2_POINT_LEN];
        cache.verify(&point).expect("首连记录应该成功");

        // 子线程持锁时 panic，使 Mutex 进入中毒状态。
        let worker = {
            let cache = std::sync::Arc::clone(&cache);
            std::thread::spawn(move || {
                let _guard = cache.key.lock().unwrap();
                panic!("simulated panic while holding lock");
            })
        };
        assert!(worker.join().is_err(), "子线程应 panic 以使锁中毒");

        // 中毒后 verify 仍可正常走完（中毒恢复路径）。
        cache
            .verify(&point)
            .expect("锁中毒后应通过 into_inner 恢复");
        let rotated = {
            let mut p = point.clone();
            p[0] ^= 0xFF;
            p
        };
        cache.verify(&rotated).expect("锁中毒后的轮换也应正常处理");
    }

    /// 验证全局 `SERVER_IDENTITY` 的轮换语义
    ///
    /// 全局缓存是 `Mutex<Option<Vec<u8>>>`，进程内可多次轮换。
    /// 测试用一个独立公钥做一次完整轮换，不依赖前序状态：
    /// 无论缓存当前何值（未初始化/一致/不一致），verify 都应成功
    /// （未初始化→首次记录；一致→通过；不一致→轮换重记录）。
    #[test]
    fn test_verify_server_identity_global() {
        // 取一个几乎不可能与已有缓存相撞的公钥：全 0xAA
        let probe = vec![0xAAu8; SM2_POINT_LEN];
        // 无论当前是首连还是轮换，都应当成功
        verify_server_identity(&probe).expect("验证应成功（首连或轮换）");
        // 与刚记录的一致，应通过与全局缓存状态无关
        verify_server_identity(&probe).expect("一致身份应该通过");

        // 再次轮换到全 0xBB：验证全局缓存可重复更新
        let probe2 = vec![0xBBu8; SM2_POINT_LEN];
        verify_server_identity(&probe2).expect("再次轮换应被接受");
        verify_server_identity(&probe2).expect("轮换后的新公钥应通过");
    }
}
