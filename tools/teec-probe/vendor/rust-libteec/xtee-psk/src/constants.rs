// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! PSK 协商协议常量定义。

/// SM2P256R1 未压缩 EC 点长度：04 || x[32] || y[32]
pub const SM2_POINT_LEN: usize = 65;

/// SM2 曲线坐标长度（x 或 y 各 32 字节）
pub const SM2_COORDINATE_LEN: usize = 32;

/// SM2 公钥在 SEC1 未压缩格式中 X 坐标的起始偏移（跳过 0x04 前缀字节）
pub(crate) const SM2_X_START: usize = 1;

/// SM2 公钥在 SEC1 未压缩格式中 Y 坐标的起始偏移
pub(crate) const SM2_Y_START: usize = SM2_X_START + SM2_COORDINATE_LEN; // 33

/// SM2 公钥 X||Y 拼接长度（不含 0x04 前缀），用于 sm2_compute_sign_digest
pub const SM2_PUBLIC_KEY_LEN: usize = SM2_COORDINATE_LEN * 2; // 64

/// 协议帧中签名字段长度的字节数（u32 大端编码）
pub(crate) const SIG_LEN_FIELD_SIZE: usize = 4;

/// PSK 输出长度（32 字节，由 SM2 曲线安全强度决定）
pub const PSK_LEN: usize = SM2_COORDINATE_LEN;

/// SM2 签名最大长度（DER 编码，含 r/s 序列）
pub const MAX_SIG_LEN: usize = 256;

/// KDF 上下文标签，用于 HKDF info 参数绑定协议上下文
pub(crate) const KDF_LABEL: &[u8] = b"xtee-dynamic-psk";

/// PSK identity，用于 TLS PSK 握手中标识使用的 PSK
const PSK_IDENTITY: &str = "xtee-dynamic";

/// HKDF salt 常量，增强 HMAC 提取阶段的随机性保证
pub(crate) const KDF_SALT: &[u8] = b"xtee-psk-salt-v1";

/// HKDF info 拼接后总长度（栈分配）：client_point(65) + server_point(65) + KDF_LABEL
pub(crate) const INFO_LEN: usize = SM2_POINT_LEN * 2 + KDF_LABEL.len();

/// 拼接客户端公钥和服务端公钥用于签名/验签（栈分配，130 字节）。
pub(crate) const ECDH_DATA_LEN: usize = SM2_POINT_LEN * 2;

/// 返回 PSK identity 字符串（`"xtee-dynamic"`），用于 TLS PSK 握手中
/// 标识当前使用的预共享密钥。
///
/// 此函数为 `const fn`，可在编译期求值。
pub const fn get_psk_identity() -> &'static str {
    PSK_IDENTITY
}
