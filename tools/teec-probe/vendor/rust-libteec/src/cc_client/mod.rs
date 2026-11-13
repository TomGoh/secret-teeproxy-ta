// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! 机密通信（Confidential Communication）客户端模块。
//!
//! 负责 CA（Client Application）与 TEE OS 之间基于 TLS + VSOCK 的
//! 安全通信通道的建立与管理，包含三个子模块：
//!
//! - [`client`]：TLS 客户端连接管理，封装 mbedtls 的握手与数据传输
//! - [`tofu`]：服务端身份 TOFU 缓存，首次连接信任、后续校验一致性
//! - [`vsock_define`]：VSOCK 连接参数配置（CID / Port，支持环境变量覆盖）

pub(crate) mod client;
#[cfg(feature = "attack-test")]
pub(crate) mod tampering;
pub(crate) mod tofu;
pub(crate) mod vsock_define;
