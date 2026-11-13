// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! ECDH 密钥协商与 HKDF-SM3 密钥派生。
//!
//! 核心流程：
//! 1. 通过 SM2 ECDH 计算共享秘密（`ecdh_compute_shared`）
//! 2. 通过 HKDF-SM3 从共享秘密派生 PSK（`derive_psk`）

use tee_crypto::{
    CryptoError,
    asymmetric::EccCurve,
    hash::{Digest, Sm3},
    mac::HmacSm3,
    tee_ops::ecc::ecc_shared_secret,
};
use zeroize::Zeroizing;

use crate::{
    constants::{ECDH_DATA_LEN, INFO_LEN, KDF_LABEL, KDF_SALT, PSK_LEN, SM2_POINT_LEN},
    ec_point::sec1_to_sm2_point,
    error::{PskError, PskResult},
    keygen::Sm2KepKeypair,
};

/// HKDF-SM3 密钥派生（RFC 5869），委托 `tee_crypto::hkdf::hkdf` 实现。
///
/// # 参数
/// - `salt`：可选 salt（HMAC 密钥），当前使用非空常量 `KDF_SALT`
/// - `ikm`：输入密钥材料（Input Keying Material）
/// - `info`：上下文绑定信息（绑定协议标识、双方公钥等）
/// - `length`：期望的输出密钥长度（字节）
pub(crate) fn hkdf_sm3(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> PskResult<Vec<u8>> {
    tee_crypto::hkdf::hkdf::<HmacSm3>(salt, ikm, info, length)
        .map_err(|e| PskError::InternalError(e.to_string()))
}

/// 从 ECDH 共享秘密派生 32 字节 PSK（HKDF-SM3）
///
/// 使用 HKDF-SM3 替代简单 SM3 哈希，将双方临时公钥绑定到 info 参数中，
/// 防止跨协议攻击和密钥替换。
///
/// # 参数
/// * `shared` - ECDH 协商出的共享秘密
/// * `client_point` - 客户端临时公钥（裸 65 字节 EC point）
/// * `server_point` - 服务端临时公钥（裸 65 字节 EC point）
pub fn derive_psk(
    shared: &[u8],
    client_point: &[u8],
    server_point: &[u8],
) -> PskResult<[u8; PSK_LEN]> {
    // info = client_point || server_point || KDF_LABEL（栈分配，避免堆分配热路径）
    let mut info = [0u8; INFO_LEN];
    info[..SM2_POINT_LEN].copy_from_slice(client_point);
    info[SM2_POINT_LEN..SM2_POINT_LEN * 2].copy_from_slice(server_point);
    info[SM2_POINT_LEN * 2..].copy_from_slice(KDF_LABEL);

    // 使用 Zeroizing 包装中间密钥材料，离开作用域自动堆内存清零
    let okm = Zeroizing::new(hkdf_sm3(KDF_SALT, shared, &info, PSK_LEN)?);
    let mut psk = [0u8; PSK_LEN];

    psk.copy_from_slice(&okm);
    Ok(psk)
}

/// 计算 ECDH 共享秘密（自动清零）
///
/// 接收对端裸 EC point（65 字节未压缩格式），经
/// `tee_crypto::tee_ops::ecc::ecc_shared_secret` 计算 SM2 ECDH 的原始共享秘密
/// ——**32 字节，即共享点的 x 坐标，未哈希**（不是完整的 64 字节共享点），
/// 再对该 32 字节做一次 SM3（与 `tee_crypto` 0.1.4 及更早版本
/// `KeyAgreement::shared_secret` 的派生完全一致，保证与既有对端逐字节相同，
/// 不引入协议变更）。
///
/// 返回 `Zeroizing<Vec<u8>>`，在离开作用域时自动调用 `zeroize` 清理
/// 堆内存中的敏感密钥数据，避免残留在内存中。
///
/// # 参数
/// * `our_key` - 本地生成的 ECDH 密钥对
/// * `peer_point` - 对端裸 EC point（必须为 65 字节未压缩格式）
pub fn ecdh_compute_shared(
    our_key: &Sm2KepKeypair,
    peer_point: &[u8],
) -> PskResult<Zeroizing<Vec<u8>>> {
    // 解析结果直接是 SM2 点（`sec1_to_sm2_point` 只可能产出 SM2），无需再
    // 对曲线类型做分支判断。
    let peer = sec1_to_sm2_point(peer_point)?;
    let (peer_x, peer_y) = (peer.x(), peer.y());

    // `secret_key_bytes()` 返回的是栈上 `[u8; 32]` 私钥标量副本，用
    // `Zeroizing` 包裹使其离开作用域时被清零，避免私钥残留在栈内存中。
    let secret_key = Zeroizing::new(our_key.secret_key_bytes());

    // 错误分类：`peer_x`/`peer_y` 已由 `sec1_to_sm2_point` 保证是 32 字节，本地
    // 私钥由 `Sm2KepKeypair` 生成、恒为合法标量，故长度类错误不可达，`InvalidKey`
    // 只可能来自**对端点不在 SM2P256R1 曲线上**（或坐标越界）——属于对端输入非法，
    // 应归为 `InvalidPoint`；其余（后端错误、内部错误等）才是本机密码学故障。
    let raw =
        ecc_shared_secret(EccCurve::Sm2, &secret_key[..], peer_x, peer_y).map_err(|e| match e {
            CryptoError::InvalidKey | CryptoError::InvalidLength | CryptoError::InvalidInput => {
                PskError::InvalidPoint
            }
            other => PskError::InternalError(other.to_string()),
        })?;

    let mut hasher = Sm3::new();
    hasher.update(raw.expose_secret());

    // `raw` 由 `SharedSecretBytes` 内部的 `Zeroizing<Vec<u8>>` 在析构时清零；
    // 但 `finalize()` 返回的 `DigestBytes` 只有普通 `Vec<u8>`、没有 Drop 清零，
    // 其内容正是最终共享秘密。故用 `into_vec` 交出缓冲区所有权直接交给
    // `Zeroizing`，**减少**一份不会被清理的明文副本。
    //
    // 注意：这只减少了一份副本，并不等于内存中已无明文残留——`Sm3` 状态里仍
    // 保存着已吸收的输入块（`Sm3` 未实现 `Zeroize`/`Drop` 清零）。
    Ok(Zeroizing::new(hasher.finalize().into_vec()))
}

/// 拼接客户端公钥和服务端公钥用于签名/验签（栈分配，130 字节）。
pub(crate) fn concat_ecdh_data(client_point: &[u8], server_point: &[u8]) -> [u8; ECDH_DATA_LEN] {
    let mut data = [0u8; ECDH_DATA_LEN];
    data[..SM2_POINT_LEN].copy_from_slice(client_point);
    data[SM2_POINT_LEN..].copy_from_slice(server_point);
    data
}

#[cfg(test)]
mod ecdh_tests {
    use super::*;
    use crate::ec_point::extract_ec_point;
    use crate::keygen::{generate_ecdh_keypair, new_crypto_rng};
    use tee_crypto::sm2::Sm2KepKeypair;

    #[test]
    fn test_derive_psk() {
        let shared = [0xABu8; PSK_LEN];
        let client_point = [0u8; SM2_POINT_LEN];
        let server_point = [1u8; SM2_POINT_LEN];

        let psk = derive_psk(&shared, &client_point, &server_point).expect("派生 PSK 应该成功");
        assert_eq!(psk.len(), PSK_LEN, "PSK 长度应该为 {} 字节", PSK_LEN);
        assert!(psk.iter().any(|&b| b != 0), "PSK 不应该全为零");

        // 验证不同共享秘密产生不同 PSK
        let shared2 = [0xCDu8; PSK_LEN];
        let psk2 =
            derive_psk(&shared2, &client_point, &server_point).expect("第二次派生 PSK 应该成功");
        assert_ne!(psk, psk2, "不同共享秘密应该产生不同的 PSK");

        // 验证不同公钥绑定产生不同 PSK
        let server_point2 = [2u8; SM2_POINT_LEN];
        let psk3 =
            derive_psk(&shared, &client_point, &server_point2).expect("第三次派生 PSK 应该成功");
        assert_ne!(
            psk, psk3,
            "不同服务端公钥应该产生不同的 PSK（HKDF info 绑定）"
        );
    }

    #[test]
    fn test_ecdh_consistency() {
        let mut rng = new_crypto_rng().expect("create rng");

        let key1 = generate_ecdh_keypair(&mut rng).expect("generate key1");
        let key2 = generate_ecdh_keypair(&mut rng).expect("generate key2");

        let pub1 = extract_ec_point(&key1).expect("extract pub1");
        let pub2 = extract_ec_point(&key2).expect("extract pub2");

        let secret1 = ecdh_compute_shared(&key1, &pub2).expect("compute secret1");
        let secret2 = ecdh_compute_shared(&key2, &pub1).expect("compute secret2");

        assert_eq!(secret1, secret2, "双方 ECDH 共享秘密必须一致");

        // 验证 HKDF 派生结果一致
        let psk1 = derive_psk(&secret1, &pub1, &pub2).expect("derive psk1");
        let psk2 = derive_psk(&secret2, &pub1, &pub2).expect("derive psk2");
        assert_eq!(psk1, psk2, "双方派生的 PSK 必须一致");
    }

    #[test]
    fn test_ecdh_rejects_invalid_point() {
        let mut rng = new_crypto_rng().expect("create rng");
        let key = generate_ecdh_keypair(&mut rng).expect("generate key");

        // 长度不足
        let short_point = [0u8; 10];
        let result = ecdh_compute_shared(&key, &short_point);
        assert!(result.is_err(), "ECDH 应拒绝长度不等于 65 的点");

        // 首字节非 0x04（非未压缩格式）
        let bad_prefix = {
            let mut p = [0u8; SM2_POINT_LEN];
            p[0] = 0x02; // compressed prefix
            p
        };
        let result = ecdh_compute_shared(&key, &bad_prefix);
        assert!(result.is_err(), "ECDH 应拒绝非未压缩格式的点");

        // 65 字节、前缀合法，但点不在 SM2P256R1 曲线上：(0,0) 不满足
        // y² = x³ + ax + b（b ≠ 0）。这类错误来自对端输入，应归为
        // `InvalidPoint`，而不是 `InternalError`。
        let off_curve = {
            let mut p = [0u8; SM2_POINT_LEN];
            p[0] = 0x04;
            p
        };
        let result = ecdh_compute_shared(&key, &off_curve);
        assert!(
            matches!(result, Err(PskError::InvalidPoint)),
            "曲线外的点应被归为 InvalidPoint（对端输入非法），实际为 {result:?}"
        );
    }

    /// 固定向量（Known-Answer Test）——锁死「共享秘密 = SM3(32 字节 x 坐标)」这一
    /// `tee_crypto 0.1.4` 时代 `KeyAgreement::shared_secret` 的语义。
    ///
    /// 互通性完全依赖这个字节串：若有人把实现"修正"成对 `x || y`（64 字节完整共享点）
    /// 做哈希、或干脆去掉最后的 SM3，与旧版对端的 PSK 派生就会静默错位（握手失败但
    /// 没有任何编译或类型层面的提示）。下面的期望值即 0.1.4 的真实输出。
    ///
    /// 向量取自标准参数，便于独立复核：
    /// - 本地私钥 `d = 0x0102…20`（32 字节递增）；
    /// - 对端点 = SM2 曲线基点 `G`（SM2P256R1 标准值，SEC1 未压缩 65 字节）；
    /// - 原始共享秘密为 `d·G` 的 x 坐标 `46D1…F28A`（未哈希，仅用于对照）；
    /// - 期望输出 = `SM3(46D1…F28A)`，可用 `openssl dgst -sm3` 独立验算。
    #[test]
    fn test_shared_secret_known_answer() {
        /// SM2 曲线基点 G 的 SEC1 未压缩表示（0x04 || x || y）。
        const SEC1_G: [u8; SM2_POINT_LEN] = [
            0x04, 0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A,
            0x39, 0xC9, 0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45,
            0x89, 0x33, 0x4C, 0x74, 0xC7, 0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59,
            0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47,
            0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
        ];
        /// `SM3(x 坐标)`，即 `ecdh_compute_shared` 必须返回的 32 字节。
        const EXPECTED: [u8; PSK_LEN] = [
            0xF0, 0x70, 0x33, 0x5C, 0x61, 0xB5, 0xBC, 0x08, 0xF2, 0xE9, 0x86, 0xE5, 0x05, 0x15,
            0x3E, 0xC4, 0x0F, 0x0F, 0x86, 0x55, 0x29, 0xB1, 0x2C, 0x76, 0x61, 0x76, 0xEB, 0x38,
            0xCF, 0x18, 0x7E, 0x3B,
        ];

        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }

        let key = Sm2KepKeypair::from_secret_bytes(&secret).expect("加载固定私钥应该成功");
        let shared = ecdh_compute_shared(&key, &SEC1_G).expect("与基点做 ECDH 应该成功");

        assert_eq!(
            &shared[..],
            &EXPECTED[..],
            "共享秘密必须与 0.1.4 固定向量逐字节一致（SM3 的输入是 32 字节 x 坐标，不是 x||y）"
        );
    }
}
