// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! ECDH 交换签名与验签（防 MITM 攻击）。
//!
//! 服务端使用长期 SM2 DSA 密钥对 `client_point || server_point` 签名，
//! 客户端使用服务端长期公钥验证，确保 ECDH 交换未被中间人篡改。

use tee_crypto::{
    material::{SignatureAlgorithm, SignatureBytes, SignatureEncoding},
    sm2::{sm2_compute_sign_digest, sm2_dsa_verify},
};

use crate::{
    constants::{SM2_POINT_LEN, SM2_PUBLIC_KEY_LEN, SM2_X_START, SM2_Y_START},
    ecdh::concat_ecdh_data,
    error::{PskError, PskResult},
    keygen::{CryptoRng, Sm2DsaKeypair},
};

/// 对 ECDH 交换签名（防 MITM，服务端侧）
///
/// 服务端用长期 SM2 私钥对 `client_point || server_point` 做标准 SM2 签名
/// （包含 ZA 预处理），客户端用服务端长期公钥验证，确保 ECDH 交换未被篡改。
///
/// # 参数
/// * `long_term_key` - 服务端长期 SM2 DSA 密钥对
/// * `client_point` - 客户端临时公钥（65 字节）
/// * `server_point` - 服务端临时公钥（65 字节）
/// * `rng` - 随机数生成器（SM2 DSA 签名为确定性，实际忽略此参数；
///   由 `Signer` trait 要求传入，RSA 等算法会实际使用）
///
/// # 返回
/// * `Ok(Vec<u8>)` - SM2 签名（Raw 64 字节 r||s）
pub fn sign_ecdh_exchange(
    long_term_key: &Sm2DsaKeypair,
    client_point: &[u8],
    server_point: &[u8],
    rng: &mut CryptoRng,
) -> PskResult<Vec<u8>> {
    use tee_crypto::asymmetric::Signer;

    // 签名数据 = client_point || server_point（栈分配）
    let data = concat_ecdh_data(client_point, server_point);

    // 使用 SM2 DSA 标准签名（含 ZA 预处理）
    let sig = long_term_key
        .sign(&data, rng)
        .map_err(|e| PskError::InternalError(e.to_string()))?;

    Ok(sig.as_bytes().to_vec())
}

/// 验证 ECDH 签名（防 MITM）
///
/// 使用服务端长期公钥验证签名，确保 ECDH 交换未被篡改。
///
/// # 参数
/// * `server_long_term_point` - 服务端长期公钥（裸 65 字节 EC point）
/// * `client_point` - 客户端临时公钥（65 字节）
/// * `server_point` - 服务端临时公钥（65 字节）
/// * `signature` - 服务端签名（Raw 64 字节 r||s）
pub fn verify_ecdh_signature(
    server_long_term_point: &[u8],
    client_point: &[u8],
    server_point: &[u8],
    signature: &[u8],
) -> PskResult<()> {
    if server_long_term_point.len() != SM2_POINT_LEN || server_long_term_point[0] != 0x04 {
        return Err(PskError::InvalidPoint);
    }

    let public_x = &server_long_term_point[SM2_X_START..SM2_Y_START];
    let public_y = &server_long_term_point[SM2_Y_START..SM2_POINT_LEN];

    let data = concat_ecdh_data(client_point, server_point);

    // 计算 SM2 签名摘要 e = SM3(ZA || M)
    let mut public_key_64 = [0u8; SM2_PUBLIC_KEY_LEN];
    public_key_64.copy_from_slice(&server_long_term_point[SM2_X_START..]);
    let digest = sm2_compute_sign_digest(None, &data, &public_key_64)
        .map_err(|e| PskError::InternalError(e.to_string()))?;

    let sig = SignatureBytes::new(
        signature.to_vec(),
        SignatureAlgorithm::Sm2Dsa,
        SignatureEncoding::Raw,
    );
    sm2_dsa_verify(public_x, public_y, &digest, &sig).map_err(|_| PskError::VerificationFailed)
}

#[cfg(test)]
mod sign_tests {
    use super::*;
    use crate::ec_point::extract_ec_point;
    use crate::keygen::{generate_dsa_keypair, new_crypto_rng};

    #[test]
    fn test_ecdh_signature_roundtrip() {
        let mut rng = new_crypto_rng().expect("create rng");

        // 生成长期密钥对
        let long_term_key = generate_dsa_keypair(&mut rng).expect("generate long-term key");
        let long_term_point = extract_ec_point(&long_term_key).expect("extract long-term pub");

        let client_point = [0xAAu8; SM2_POINT_LEN];
        let server_point = [0xBBu8; SM2_POINT_LEN];

        // 签名
        let sig = sign_ecdh_exchange(&long_term_key, &client_point, &server_point, &mut rng)
            .expect("sign");

        // 验签成功
        let result = verify_ecdh_signature(&long_term_point, &client_point, &server_point, &sig);
        assert!(result.is_ok(), "合法签名应该验签通过");

        // 篡改数据后验签失败
        let tampered_point = [0xCCu8; SM2_POINT_LEN];
        let result = verify_ecdh_signature(&long_term_point, &tampered_point, &server_point, &sig);
        assert!(result.is_err(), "篡改数据后验签应该失败");
    }
}
