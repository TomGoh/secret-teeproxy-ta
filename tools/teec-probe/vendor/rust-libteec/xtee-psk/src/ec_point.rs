// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! EC 点格式转换（SEC1 未压缩格式 ↔ SM2 公钥点 / `PublicKeyComponents`）。

use tee_crypto::asymmetric::{Keypair, PublicKeyComponents, Sm2PublicPoint};

use crate::{
    constants::{SM2_COORDINATE_LEN, SM2_POINT_LEN, SM2_X_START, SM2_Y_START},
    error::{PskError, PskResult},
};

/// 将 `PublicKeyComponents` 转换为 65 字节未压缩 EC point（SEC1 格式）。
///
/// 仅支持 SM2 类型的公钥组件。
fn public_components_to_sec1(components: &PublicKeyComponents) -> PskResult<Vec<u8>> {
    match components {
        PublicKeyComponents::Sm2(point) => {
            let x = point.x();
            let y = point.y();

            if x.len() != SM2_COORDINATE_LEN || y.len() != SM2_COORDINATE_LEN {
                return Err(PskError::InvalidPoint);
            }

            let mut buf = Vec::with_capacity(SM2_POINT_LEN);

            buf.push(0x04);
            buf.extend_from_slice(x);
            buf.extend_from_slice(y);
            Ok(buf)
        }
        _ => Err(PskError::InvalidPoint),
    }
}

/// 将 65 字节未压缩 EC point（SEC1 格式）解析为 SM2 公钥点。
///
/// 仅支持 0x04 前缀的未压缩格式。返回值直接是 [`Sm2PublicPoint`] 而不是
/// [`PublicKeyComponents`] 枚举：本函数按定义只可能产出 SM2 点，因此不把
/// 「非 SM2 曲线」这种不可达情形外抛给调用方处理。
pub(crate) fn sec1_to_sm2_point(peer_point: &[u8]) -> PskResult<Sm2PublicPoint> {
    if peer_point.len() != SM2_POINT_LEN {
        return Err(PskError::InvalidPoint);
    }

    if peer_point[0] != 0x04 {
        return Err(PskError::InvalidPoint);
    }

    let x = peer_point[SM2_X_START..SM2_Y_START].to_vec();
    let y = peer_point[SM2_Y_START..SM2_POINT_LEN].to_vec();

    Ok(Sm2PublicPoint::from_be_bytes(x, y))
}

/// 从密钥对中提取裸 EC point（未压缩格式，65 字节）
///
/// 用于 ECDH 交换中发送/接收公钥，替代 DER 格式以简化解析。
pub fn extract_ec_point(keypair: &impl Keypair) -> PskResult<Vec<u8>> {
    let components = keypair
        .to_public_components()
        .map_err(|e| PskError::InternalError(e.to_string()))?;
    public_components_to_sec1(&components)
}
