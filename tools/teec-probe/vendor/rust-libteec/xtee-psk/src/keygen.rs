// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! 密钥生成函数与类型别名。
//!
//! 提供密码学安全随机数生成器、ECDH/DSA 密钥对生成，以及
//! 协商输出类型别名。

use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};
use tee_crypto::asymmetric::Keypair;

use crate::error::{PskError, PskResult};

pub use tee_crypto::sm2::{Sm2DsaKeypair, Sm2KepKeypair};

/// 密码学安全随机数生成器（ChaCha12Rng，从 OS 熵源播种）。
///
/// 通过 `rand` crate 的 `StdRng` 提供，自动实现 `tee_crypto::CryptoRng`。
pub type CryptoRng = StdRng;

/// 从操作系统熵源创建密码学安全随机数生成器。
pub fn new_crypto_rng() -> PskResult<StdRng> {
    StdRng::try_from_rng(&mut SysRng).map_err(|e| PskError::InternalError(e.to_string()))
}

/// 生成 ECDH 密钥交换用的 SM2 密钥对。
pub fn generate_ecdh_keypair(rng: &mut CryptoRng) -> PskResult<Sm2KepKeypair> {
    Sm2KepKeypair::generate(rng, 0).map_err(|e| PskError::InternalError(e.to_string()))
}

/// 生成 SM2 数字签名用的密钥对。
pub fn generate_dsa_keypair(rng: &mut CryptoRng) -> PskResult<Sm2DsaKeypair> {
    Sm2DsaKeypair::generate(rng, 0).map_err(|e| PskError::InternalError(e.to_string()))
}
