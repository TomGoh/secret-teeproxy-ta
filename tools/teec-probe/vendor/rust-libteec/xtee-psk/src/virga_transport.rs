// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! 为 `virga` 库的 `VirgeClient` / `VirgeServer` 提供 `PskTransport` trait 实现。
//!
//! 通过 newtype 包装满足 Rust 孤儿规则（orphan rule），
//! 使 ECDH 协商函数可以直接在 VSOCK 连接上执行 send/recv 操作。

use virga::{client::VirgeClient, server::VirgeServer};

use super::{PskError, PskTransport};

/// 通过 `virga` 的内置 send/recv 方法为 `PskTransport` trait 提供标准实现。
///
/// 使用 newtype wrapper 满足孤儿规则（orphan rule），使 `VirgeClient` 和 `VirgeServer`
/// 均可复用相同的 `PskTransport` 实现逻辑。
macro_rules! impl_psk_transport {
    ($type:ty) => {
        impl PskTransport for $type {
            fn psk_send(&mut self, data: Vec<u8>) -> Result<(), PskError> {
                self.0
                    .send(data)
                    .map(|_| ())
                    .map_err(|e| PskError::InternalError(e.to_string()))
            }
            fn psk_recv(&mut self) -> Result<Vec<u8>, PskError> {
                self.0
                    .recv()
                    .map_err(|e| PskError::InternalError(e.to_string()))
            }
        }
    };
}

/// Newtype 包装 `VirgeClient`，实现 `PskTransport`。
///
/// 使用方法：
/// ```ignore
/// let mut transport = VirgeClientTransport(client);
/// let (psk, ...) = client_ecdh_negotiate(&mut transport, &mut rng)?;
/// let client = transport.0;
/// ```
pub struct VirgeClientTransport(pub VirgeClient);

impl_psk_transport!(VirgeClientTransport);

/// Newtype 包装 `VirgeServer`，实现 `PskTransport`。
///
/// 使用方法：
/// ```ignore
/// let mut transport = VirgeServerTransport(server);
/// let (psk, ...) = psk_ctx.negotiate(&mut transport, &mut rng)?;
/// let server = transport.0;
/// ```
pub struct VirgeServerTransport(pub VirgeServer);

impl_psk_transport!(VirgeServerTransport);
