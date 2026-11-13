// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! ECDH 协议帧的构建与解析。
//!
//! 协议帧格式：`server_point(65) + sig_len(4) + sig(N) + lt_point(65)`

use crate::{
    constants::{MAX_SIG_LEN, SIG_LEN_FIELD_SIZE, SM2_POINT_LEN},
    error::{PskError, PskResult},
};

/// 服务端 ECDH 响应解析结果
pub struct EcdhResponse<'a> {
    /// 服务端临时公钥（65 字节）
    pub server_point: &'a [u8],
    /// 服务端签名（变长）
    pub signature: &'a [u8],
    /// 服务端长期公钥（65 字节）
    pub long_term_point: &'a [u8],
}

/// 解析服务端 ECDH 响应
///
/// 响应格式：server_point(65) + sig_len(4) + sig(N) + lt_point(65)
pub fn parse_ecdh_response(recv_data: &[u8]) -> PskResult<EcdhResponse<'_>> {
    let min_len = SM2_POINT_LEN + SIG_LEN_FIELD_SIZE + SM2_POINT_LEN;

    if recv_data.len() < min_len {
        return Err(PskError::InvalidInput);
    }

    let server_point = &recv_data[..SM2_POINT_LEN];
    let sig_len = u32::from_be_bytes(
        recv_data[SM2_POINT_LEN..SM2_POINT_LEN + 4]
            .try_into()
            .expect("4-byte slice"),
    ) as usize;

    if sig_len > MAX_SIG_LEN {
        return Err(PskError::InvalidInput);
    }

    let sig_end = SM2_POINT_LEN + SIG_LEN_FIELD_SIZE + sig_len;

    if recv_data.len() < sig_end + SM2_POINT_LEN {
        return Err(PskError::InvalidInput);
    }

    Ok(EcdhResponse {
        server_point,
        signature: &recv_data[SM2_POINT_LEN + SIG_LEN_FIELD_SIZE..sig_end],
        long_term_point: &recv_data[sig_end..sig_end + SM2_POINT_LEN],
    })
}

/// 构建 ECDH 响应消息（服务端侧使用）
///
/// 格式：server_point(65) + sig_len(4) + sig(N) + lt_point(65)
pub fn build_ecdh_response(
    server_point: &[u8],
    signature: &[u8],
    long_term_point: &[u8],
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(SM2_POINT_LEN + SIG_LEN_FIELD_SIZE + signature.len() + SM2_POINT_LEN);

    buf.extend_from_slice(server_point);
    buf.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    buf.extend_from_slice(signature);
    buf.extend_from_slice(long_term_point);
    buf
}

#[cfg(test)]
mod protocol_tests {
    use super::*;
    use crate::ec_point::extract_ec_point;
    use crate::keygen::{generate_dsa_keypair, generate_ecdh_keypair, new_crypto_rng};
    use crate::sign::sign_ecdh_exchange;

    #[test]
    fn test_ecdh_response_build_parse_roundtrip() {
        let mut rng = new_crypto_rng().expect("create rng");

        // 生成密钥
        let ecdh_key = generate_ecdh_keypair(&mut rng).expect("generate ecdh key");
        let lt_key = generate_dsa_keypair(&mut rng).expect("generate lt key");

        let server_point = extract_ec_point(&ecdh_key).expect("extract server point");
        let long_term_point = extract_ec_point(&lt_key).expect("extract lt point");
        let signature =
            sign_ecdh_exchange(&lt_key, &[0xAA; SM2_POINT_LEN], &server_point, &mut rng)
                .expect("sign");

        // 构建响应
        let resp_buf = build_ecdh_response(&server_point, &signature, &long_term_point);

        // 解析响应
        let resp = parse_ecdh_response(&resp_buf).expect("parse response");
        assert_eq!(resp.server_point, &server_point[..]);
        assert_eq!(resp.signature, &signature[..]);
        assert_eq!(resp.long_term_point, &long_term_point[..]);
    }

    #[test]
    fn test_parse_ecdh_response_error_cases() {
        let mut rng = new_crypto_rng().expect("create rng");
        let ecdh_key = generate_ecdh_keypair(&mut rng).expect("generate ecdh key");
        let lt_key = generate_dsa_keypair(&mut rng).expect("generate lt key");
        let server_point = extract_ec_point(&ecdh_key).expect("extract server point");
        let long_term_point = extract_ec_point(&lt_key).expect("extract lt point");
        let signature =
            sign_ecdh_exchange(&lt_key, &[0xAA; SM2_POINT_LEN], &server_point, &mut rng)
                .expect("sign");

        // 数据过短（小于最小长度）
        let too_short = vec![0u8; SM2_POINT_LEN + 2];
        assert!(
            parse_ecdh_response(&too_short).is_err(),
            "数据过短时解析应失败"
        );

        // sig_len 超过 MAX_SIG_LEN
        let mut bad_sig_len = Vec::new();
        bad_sig_len.extend_from_slice(&server_point);
        bad_sig_len.extend_from_slice(&((MAX_SIG_LEN + 1) as u32).to_be_bytes());
        bad_sig_len.extend_from_slice(&signature);
        bad_sig_len.extend_from_slice(&long_term_point);
        assert!(
            parse_ecdh_response(&bad_sig_len).is_err(),
            "sig_len 超过 MAX_SIG_LEN 时解析应失败"
        );

        // sig_len 声称的长度超出实际数据
        let mut mismatched_len = Vec::new();
        mismatched_len.extend_from_slice(&server_point);
        mismatched_len.extend_from_slice(&(signature.len() as u32 + 100).to_be_bytes());
        mismatched_len.extend_from_slice(&signature);
        mismatched_len.extend_from_slice(&long_term_point);
        assert!(
            parse_ecdh_response(&mismatched_len).is_err(),
            "sig_len 超出实际数据时解析应失败"
        );

        // 空输入
        assert!(parse_ecdh_response(&[]).is_err(), "空输入解析应失败");
    }
}
