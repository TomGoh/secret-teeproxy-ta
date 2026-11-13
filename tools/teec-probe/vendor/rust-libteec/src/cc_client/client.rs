// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! 机密通信客户端实现，基于 TLS 和 VSOCK 实现与 TEE OS 的安全通信通道。

use std::{
    io::{Read, Write},
    sync::{Arc, Once},
};

use log::{debug, warn};
use mbedtls::{
    Result as TlsResult,
    error::codes,
    rng::CtrDrbg,
    ssl::{
        CipherSuite::EcdhePskWithSm4128GcmSm3,
        Config, Context, Version,
        config::{Endpoint, Preset, Transport},
    },
};
use virga::client::{ClientConfig, VirgeClient};

use teec_protocol::{CHUNK_SIZE, PacketHeader, PacketType};
use xtee_psk::{
    PskError, client_ecdh_negotiate, new_crypto_rng, virga_transport::VirgeClientTransport,
};

use crate::cc_client::{
    tofu::verify_server_identity,
    vsock_define::{get_vsock_cid, get_vsock_port},
};

/// 机密通信客户端，封装基于 TLS + VSOCK 的安全通信通道。
///
/// 内部通过 `mbedtls::ssl::Context<VirgeClient>` 管理 TLS 连接，
/// 使用 ECDH 动态协商的 PSK 进行身份认证和加密通信。
pub(crate) struct CcClient {
    ctx: Context<VirgeClient>,
}

/// SAFETY: CcClient 可以安全地在线程间发送 (Send)
///
/// 理由：
/// 1. `Context<VirgeClient>` 内部使用 Arc 管理共享状态
/// 2. Virga 的 ClientConfig 和连接状态都有内部锁保护
/// 3. 所有对 ctx 的可变访问都通过 TEEC_InvokeCommand 等函数序列化
/// 4. 没有线程不安全的裸指针或可变静态变量
///
/// 注意：CcClient 不实现 Sync，因为 Context<VirgeClient> 的方法需要 &mut self，
/// 并发共享引用无意义。实际使用中 CcClient 被包裹在 Mutex<CcClient> 中，
/// Mutex<T>: Send 要求 T: Send，不需要 T: Sync。
unsafe impl Send for CcClient {}

/// 全局日志初始化守卫，确保 `env_logger::try_init()` 只调用一次。
static LOGGER_INIT: Once = Once::new();

impl CcClient {
    /// 初始化客户端并建立 TLS 连接
    ///
    /// 流程：
    /// 1. 建立 VSOCK 连接
    /// 2. 在 VSOCK 上通过 ECDH 协商动态 PSK（SM2P256R1 曲线）
    /// 3. 派生 PSK 后建立 TLS 握手
    ///
    /// 返回建立连接的客户端实例，失败返回TLS错误
    pub fn init() -> TlsResult<Self> {
        let (client, config) = connect_and_configure()?;
        let mut ctx = Context::new(config);

        // 进行 TLS 握手（使用协商出的动态 PSK）
        ctx.establish(client, None).map_err(|e| {
            warn!("与服务端握手失败：{e}");
            e
        })?;

        let ciphersuite = ctx.ciphersuite();
        debug!("[HOST] CcClient::init: 与服务端握手成功, ciphersuite={ciphersuite:4x?}");

        Ok(Self { ctx })
    }

    /// 发送带协议头的数据包
    /// packet_type: 数据包类型，用于服务端解析处理
    /// data: 要发送的原始数据
    pub fn send_data_with_header(
        &mut self,
        packet_type: PacketType,
        data: &[u8],
    ) -> std::io::Result<()> {
        let header = PacketHeader {
            data_type: u64::from(packet_type),
            data_size: data.len() as u64,
        };

        debug!(
            "[HOST] send_data_with_header: data_type={} data_len={} header={:x?}",
            header.data_type,
            data.len(),
            header.as_bytes()
        );

        // 先发送协议头
        self.ctx.write_all(header.as_bytes()).map_err(|e| {
            warn!("客户端：发送协议头失败：{e}");
            e
        })?;

        // 再发送数据体
        self.send_data(data)
    }

    /// 发送无协议头的原始数据（用于连续数据流）
    pub fn send_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.ctx.write_all(data)?;
        debug!("客户端：发送数据，大小：{}", data.len());
        Ok(())
    }

    /// 从服务器接收数据，支持分块接收
    pub fn recv_data(&mut self, data: &mut [u8]) -> std::io::Result<()> {
        self.ctx.read_exact(data)?;
        debug!("[HOST] recv_data: len={}", data.len());
        Ok(())
    }

    /// 关闭 TLS 连接，发送 close_notify 通知服务端连接即将关闭。
    ///
    /// 调用后连接资源被释放，后续操作将失败。
    pub fn close(&mut self) {
        self.ctx.close();
    }
}

/// Prepares the production VSOCK, ECDH/TOFU and TLS policy for either client.
/// The test-only client changes its I/O wrapper after this shared boundary.
pub(crate) fn connect_and_configure() -> TlsResult<(VirgeClient, Arc<Config>)> {
    // 使用 RUST_LOG 环境变量控制日志级别，如 RUST_LOG=debug
    LOGGER_INIT.call_once(|| {
        let _ = env_logger::try_init();
    });
    let entropy = Arc::new(mbedtls::rng::OsEntropy::new());
    let rng = CtrDrbg::new(entropy.clone(), None)?;
    let mut crypto_rng = new_crypto_rng().map_err(psk_to_mbedtls_error)?;

    // 从环境变量获取 VSOCK 配置，支持自定义 CID 和 Port
    let cid = get_vsock_cid();
    let port = get_vsock_port();
    debug!("[HOST] CcClient::init: vsock cid={cid} port={port}");
    let vconfig = ClientConfig::new(cid, port, CHUNK_SIZE as u32, false);
    let mut client = VirgeClient::new(vconfig);

    debug!("[HOST] CcClient::init: calling client.connect()");
    client.connect().map_err(|e| {
        warn!("VirgeClient 连接失败：{e}");
        mbedtls::Error::LowLevel(codes::NetConnectFailed)
    })?;
    debug!("[HOST] CcClient::init: connect done, starting TLS handshake");

    // ECDH 密钥协商（在 VSOCK 上）
    let mut transport = VirgeClientTransport(client);
    let (psk, long_term_point, psk_identity) =
        client_ecdh_negotiate(&mut transport, &mut crypto_rng).map_err(psk_to_mbedtls_error)?;
    let client = transport.0;

    // TOFU 校验服务端长期公钥
    verify_server_identity(&long_term_point).map_err(|e| {
        warn!("服务端身份校验失败：{e}");
        psk_to_mbedtls_error(e)
    })?;

    debug!("ECDH 密钥协商成功");

    let cipher_suites: Vec<i32> = vec![EcdhePskWithSm4128GcmSm3.into(), 0];
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

    config.set_min_version(Version::Tls1_2)?;
    config.set_max_version(Version::Tls1_2)?;
    config.set_ciphersuites(Arc::new(cipher_suites));
    config.set_read_timeout(5000); // 5 秒读取超时
    config.set_rng(Arc::new(rng));
    config.set_psk(&*psk, psk_identity)?;

    Ok((client, Arc::new(config)))
}

/// 将 PSK 协商错误（[`PskError`]）映射为 mbedtls 错误码，
/// 统一为 `PkBadInputData` 高层错误。
///
/// 此函数是内部转换辅助函数，便于在 TLS 初始化流程中
/// 以统一的 `TlsResult` 类型传播错误。
fn psk_to_mbedtls_error(e: PskError) -> mbedtls::Error {
    debug!("PSK 协商错误：{e}");
    mbedtls::Error::HighLevel(codes::PkBadInputData)
}

/// C 接口：检查机密通信功能是否可用。
///
/// 尝试建立一次完整的 TLS 连接（包括 ECDH PSK 协商），成功则立即关闭。
///
/// # 返回值
/// - 1：机密通信通道可用
/// - 0：连接失败，机密通信不可用
#[unsafe(no_mangle)]
pub extern "C" fn cc_check_enable() -> i32 {
    match CcClient::init() {
        Ok(mut client) => {
            client.close();
            1
        }
        Err(_) => 0,
    }
}

#[cfg(test)]
mod cc_client_tests {
    use super::*;
    use teec_protocol::PacketType;

    #[test]
    fn test_packet_header_serialization() {
        let header = PacketHeader {
            data_type: 1,
            data_size: 1024,
        };

        let bytes = header.as_bytes();
        assert_eq!(bytes.len(), 16); // u64 + u64 = 16 字节
    }

    #[test]
    fn test_all_packet_types() {
        assert_eq!(u64::from(PacketType::Unknown), 0);
        assert_eq!(PacketType::from(0), PacketType::Unknown);

        assert_eq!(u64::from(PacketType::OpenSession), 1);
        assert_eq!(PacketType::from(1), PacketType::OpenSession);

        assert_eq!(u64::from(PacketType::CloseSession), 2);
        assert_eq!(PacketType::from(2), PacketType::CloseSession);

        assert_eq!(u64::from(PacketType::InvokeCommand), 3);
        assert_eq!(PacketType::from(3), PacketType::InvokeCommand);

        assert_eq!(u64::from(PacketType::RequestCancellation), 4);
        assert_eq!(PacketType::from(4), PacketType::RequestCancellation);
    }

    #[test]
    fn test_packet_type_conversion_consistency() {
        // 测试 PacketType 转换的一致性
        // 这个测试验证双向转换的一致性
        for value in 0..=4 {
            let packet_type = PacketType::from(value);
            let converted_value = u64::from(packet_type);
            assert_eq!(
                value, converted_value,
                "双向转换不一致: 原始值={}, 转换后值={}",
                value, converted_value
            );
        }

        // 测试超出范围的值的转换
        let out_of_range_value = 99;
        let packet_type = PacketType::from(out_of_range_value);
        assert_eq!(
            packet_type,
            PacketType::Unknown,
            "超出范围的值 {} 应该转换为 PacketType::Unknown",
            out_of_range_value
        );
        assert_eq!(
            u64::from(packet_type),
            0,
            "PacketType::Unknown 应该转换为 0"
        );
    }
}
