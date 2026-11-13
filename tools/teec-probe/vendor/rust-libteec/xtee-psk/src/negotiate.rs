// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! ECDH PSK 协商主流程。
//!
//! 通过 [`PskTransport`] trait 将网络 I/O 与密码学逻辑解耦，
//! 提供 `server_ecdh_negotiate` / `client_ecdh_negotiate` 两个对称的协商函数，
//! 以及封装长期密钥的 [`ServerPskContext`]。

use zeroize::Zeroizing;

use crate::{
    constants::{PSK_LEN, get_psk_identity},
    ec_point::{extract_ec_point, sec1_to_sm2_point},
    ecdh::{derive_psk, ecdh_compute_shared},
    error::PskResult,
    keygen::{CryptoRng, Sm2DsaKeypair, generate_dsa_keypair, generate_ecdh_keypair},
    protocol::{build_ecdh_response, parse_ecdh_response},
    sign::{sign_ecdh_exchange, verify_ecdh_signature},
};

/// 服务端 PSK 协商输出：(PSK, PSK identity)。
///
/// PSK 以 [`Zeroizing`] 包装，离开作用域自动清零。
pub type ServerPskOutput = (Zeroizing<[u8; PSK_LEN]>, &'static str);

/// 客户端 PSK 协商输出：(PSK, 服务端长期公钥, PSK identity)。
///
/// PSK 以 [`Zeroizing`] 包装，离开作用域自动清零。
/// 调用方需对 `long_term_point` 执行 TOFU 校验。
pub type ClientPskOutput = (Zeroizing<[u8; PSK_LEN]>, Vec<u8>, &'static str);

/// ECDH PSK 协商的传输层抽象。
///
/// 将网络 I/O（VSOCK `send`/`recv`）与密码学逻辑解耦，
/// 调用方（服务端 `VirgeServer`、客户端 `VirgeClient`）实现此 trait 即可复用
/// [`server_ecdh_negotiate`] / [`client_ecdh_negotiate`] 的完整协商流程。
pub trait PskTransport {
    /// 发送数据
    fn psk_send(&mut self, data: Vec<u8>) -> PskResult<()>;
    /// 接收数据
    fn psk_recv(&mut self) -> PskResult<Vec<u8>>;
}

/// 服务端 ECDH PSK 协商。
///
/// 协议流程：
/// 1. 接收客户端临时 EC point（65 字节未压缩格式）
/// 2. 生成服务端临时 SM2 密钥对（每连接独立，保障前向安全性）
/// 3. 使用长期 DSA 密钥对交换数据签名，发送长期公钥给客户端
/// 4. 双方各自通过 ECDH + HKDF-SM3 派生相同的 32 字节 PSK
///
/// 返回 `(psk, psk_identity)`。PSK 以 [`Zeroizing`] 包装，离开作用域自动清零，
/// 调用方只需设置到 TLS config 即可。
pub fn server_ecdh_negotiate(
    transport: &mut impl PskTransport,
    rng: &mut CryptoRng,
    long_term_key: &Sm2DsaKeypair,
    long_term_point: &[u8],
) -> PskResult<ServerPskOutput> {
    // 接收客户端临时 EC point；此处只做廉价前置校验（65 字节未压缩形式 + 0x04
    // 前缀），用于尽早丢弃明显非法的输入。曲线成员校验（点是否在 SM2P256R1 上）
    // 延后到 `ecdh_compute_shared` 内部完成，因此解析结果本身在此无需使用。
    let client_point = transport.psk_recv()?;
    let _ = sec1_to_sm2_point(&client_point)?;

    let ecdh_key = generate_ecdh_keypair(rng)?;
    let server_point = extract_ec_point(&ecdh_key)?;

    // 使用持久化的长期密钥签名
    let signature = sign_ecdh_exchange(long_term_key, &client_point, &server_point, rng)?;
    let send_buf = build_ecdh_response(&server_point, &signature, long_term_point);

    transport.psk_send(send_buf)?;

    let shared = ecdh_compute_shared(&ecdh_key, &client_point)?;
    drop(ecdh_key);

    // 使用 HKDF-SM3 派生 PSK
    let psk = derive_psk(&shared, &client_point, &server_point)?;

    Ok((Zeroizing::new(psk), get_psk_identity()))
}

/// 客户端 ECDH PSK 协商。
///
/// 协议流程：
/// 1. 生成临时 ECDH 密钥对，发送裸 EC point（65 字节）
/// 2. 接收并解析服务端响应（含服务端临时公钥、签名、长期公钥）
/// 3. 验证服务端 ECDH 签名（防 MITM）
/// 4. 通过 ECDH + HKDF-SM3 派生 PSK
///
/// 返回 `(psk, long_term_point, psk_identity)`。PSK 以 [`Zeroizing`] 包装，
/// 离开作用域自动清零。调用方负责：
/// - 对返回的 `long_term_point` 执行 TOFU 校验（Trust On First Use）
/// - 将 PSK 设置到 TLS config
pub fn client_ecdh_negotiate(
    transport: &mut impl PskTransport,
    rng: &mut CryptoRng,
) -> PskResult<ClientPskOutput> {
    let ecdh_key = generate_ecdh_keypair(rng)?;
    let client_point = extract_ec_point(&ecdh_key)?;

    transport.psk_send(client_point.clone())?;

    let recv_data = transport.psk_recv()?;
    let resp = parse_ecdh_response(&recv_data)?;

    // 验证服务端 ECDH 签名
    verify_ecdh_signature(
        resp.long_term_point,
        &client_point,
        resp.server_point,
        resp.signature,
    )?;

    // 通过 ECDH 协商共享秘密
    let shared = ecdh_compute_shared(&ecdh_key, resp.server_point)?;

    drop(ecdh_key);

    // 使用 HKDF-SM3 派生 PSK
    let psk = derive_psk(&shared, &client_point, resp.server_point)?;

    Ok((
        Zeroizing::new(psk),
        resp.long_term_point.to_vec(),
        get_psk_identity(),
    ))
}

/// 服务端 PSK 上下文，封装长期 DSA 密钥对及其 EC 公钥点。
///
/// 启动时生成一次，跨连接共享。每个连接调用 [`negotiate`](ServerPskContext::negotiate)
/// 完成 ECDH PSK 协商。
///
/// # 使用示例
///
/// ```ignore
/// let ctx = Arc::new(ServerPskContext::generate(&mut new_crypto_rng()?)?);
///
/// // 每个连接
/// let (psk, identity) = ctx.negotiate(&mut stream, &mut rng)?;
/// ```
pub struct ServerPskContext {
    key: Sm2DsaKeypair,
    point: Vec<u8>,
}

impl ServerPskContext {
    /// 生成服务端长期密钥并提取公钥。
    ///
    /// 等价于 `generate_dsa_keypair` + `extract_ec_point` 的组合调用。
    pub fn generate(rng: &mut CryptoRng) -> PskResult<Self> {
        let key = generate_dsa_keypair(rng)?;
        let point = extract_ec_point(&key)?;
        Ok(Self { key, point })
    }

    /// 执行服务端 ECDH PSK 协商。
    ///
    /// 等同于 [`server_ecdh_negotiate`]，但无需手动传递长期密钥和公钥。
    pub fn negotiate<T: PskTransport>(
        &self,
        transport: &mut T,
        rng: &mut CryptoRng,
    ) -> PskResult<ServerPskOutput> {
        server_ecdh_negotiate(transport, rng, &self.key, &self.point)
    }
}

#[cfg(test)]
mod negotiate_tests {
    use super::*;
    use crate::constants::SM2_POINT_LEN;
    use crate::keygen::new_crypto_rng;

    #[test]
    fn test_server_psk_context_generate() {
        let mut rng = new_crypto_rng().expect("create rng");
        let ctx = ServerPskContext::generate(&mut rng).expect("generate context");

        // 验证公钥点格式正确：65 字节，0x04 未压缩前缀
        assert_eq!(ctx.point.len(), SM2_POINT_LEN);
        assert_eq!(ctx.point[0], 0x04);
    }
}
