// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! 机密通信 PSK（Pre-Shared Key）动态协商模块。
//!
//! ## 功能概述
//!
//! 本模块负责 CA（Client Application）与 TEE OS 之间的 ECDH 密钥协商和 PSK 派生，
//! 主要流程：
//!
//! 1. **ECDH 密钥交换**：基于 SM2P256R1 椭圆曲线，双方各生成临时密钥对，
//!    交换裸 EC point（65 字节未压缩格式）计算共享秘密
//! 2. **服务端身份验证**：服务端使用长期 SM2 DSA 密钥对 ECDH 交换签名，
//!    客户端验证签名防 MITM 攻击
//! 3. **PSK 派生**：通过 HKDF-SM3（RFC 5869）从共享秘密派生 32 字节 PSK，
//!    info 参数绑定双方公钥，防跨协议攻击和密钥替换
//! 4. **TOFU 信任**：客户端首次连接时缓存服务端长期公钥（TOFU 策略），
//!    后续连接校验公钥一致性
//!
//! ## 协议帧格式
//!
//! ECDH 响应帧：`server_point(65) + sig_len(4) + sig(N) + lt_point(65)`
//!
//! ## 安全特性
//!
//! - 临时密钥对（Ephemeral Keypair）用完即弃，每次协商生成新密钥
//! - 共享秘密使用 `Zeroizing<Vec<u8>>` 自动清零，防止残留内存
//! - 签名验证失败立即拒绝连接，不降级到不安全模式
//!
//! ## 代码组织
//!
//! 各功能分散在独立子模块中，`lib.rs` 仅负责模块声明和公共 API 重导出：
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`constants`] | 协议常量（点长度、签名字段大小、PSK 长度等） |
//! | [`error`] | `PskError` 错误类型和 `PskResult` 别名 |
//! | [`keygen`] | 随机数生成器创建、ECDH/DSA 密钥对生成 |
//! | [`ec_point`] | SEC1 未压缩格式 ↔ SM2 公钥点 / `PublicKeyComponents` 转换 |
//! | [`ecdh`] | ECDH 共享秘密计算 + HKDF-SM3 PSK 派生 |
//! | [`sign`] | SM2 DSA 签名/验签（防 MITM） |
//! | [`protocol`] | 协议帧构建/解析（`build_ecdh_response` / `parse_ecdh_response`） |
//! | [`negotiate`] | `PskTransport` trait + 协商主流程 + `ServerPskContext` |
//! | [`virga_transport`] | virga VSOCK 传输层的 `PskTransport` 实现 |

// --- 子模块声明 ----------------------------------------------------------------
pub mod constants;
pub mod ec_point;
pub mod ecdh;
pub mod error;
pub mod keygen;
pub mod negotiate;
pub mod protocol;
pub mod sign;

/// 为 `virga` 库的 VSOCK 传输层提供 `PskTransport` 实现。
pub mod virga_transport;

// --- 公共 API 重导出 -----------------------------------------------------------
//
// 按功能分组，保持原 `lib.rs` 的公共接口不变，确保下游调用方无感知。

// 常量
pub use constants::{
    MAX_SIG_LEN, PSK_LEN, SM2_COORDINATE_LEN, SM2_POINT_LEN, SM2_PUBLIC_KEY_LEN, get_psk_identity,
};

// 错误类型
pub use error::{PskError, PskResult};

// 密钥生成
pub use keygen::{CryptoRng, generate_dsa_keypair, generate_ecdh_keypair, new_crypto_rng};

// EC 点操作
pub use ec_point::extract_ec_point;

// ECDH / HKDF
pub use ecdh::{derive_psk, ecdh_compute_shared};

// 签名/验签
pub use sign::{sign_ecdh_exchange, verify_ecdh_signature};

// 协议帧
pub use protocol::{EcdhResponse, build_ecdh_response, parse_ecdh_response};

// 协商主流程
pub use negotiate::{
    ClientPskOutput, PskTransport, ServerPskContext, ServerPskOutput, client_ecdh_negotiate,
    server_ecdh_negotiate,
};

// SM2 密钥对类型（来自 tee_crypto，重导出方便调用方直接使用）
pub use tee_crypto::sm2::{Sm2DsaKeypair, Sm2KepKeypair};
