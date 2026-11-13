// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 KylinSoft Co., Ltd.

//! SM2 ECDH-PSK 密钥协商的 fuzz（`xtee-psk`）。
//!
//! 覆盖 `xtee-psk/src/negotiate.rs`（客户端/服务端两侧协商全流程）、
//! `sign.rs`（`sign_ecdh_exchange` / `verify_ecdh_signature`）、
//! `ec_point.rs`（SEC1 ↔ 公钥组件转换、`extract_ec_point`）、
//! `ecdh.rs`（`ecdh_compute_shared` 直接调用 + `derive_psk`）、
//! `keygen.rs`（密钥对生成）、`protocol.rs`（响应帧构建/解析）与 `error.rs`。
//!
//! 驱动方式：实现脚本化 `PskTransport`，客户端在 `psk_recv` 时**嵌套**驱动一次
//! 真实的服务端协商（用刚收到的客户端公钥签名），从而在单线程、无网络的前提下
//! 跑通完整握手（客户端临时密钥 → 服务端签名响应 → 客户端验签 → 双方派生 PSK），
//! 并比对两侧 PSK 与身份标识。
//!
//! 检验属性：
//! 1. 诚实传输下两侧协商必须成功，派生的 PSK 必须一致、非全零，身份标识一致。
//! 2. 响应被篡改（任意位置翻转 / 截断 / 替换长期公钥）后客户端**绝不能**成功
//!    ——不得出现「验签失败却仍派生 PSK」或「两侧 PSK 不同却双方都成功」。
//! 3. 对端无响应、空帧、任意字节帧一律失败，不得 panic。
//! 4. 服务端对畸形客户端公钥（长度 ≠ 65、前缀 ≠ 0x04）必须直接拒绝；若接受，
//!    响应帧必须可被 `parse_ecdh_response` 解析且字段长度合规。
//! 5. `psk_send` 失败必须向上传播为错误（带动服务端与客户端两侧都不成功）。
//! 6. 直接调用 `ecdh_compute_shared` 时，任何失败都必须是 `InvalidPoint`（对端点
//!    来自网络，属输入非法，不得归为 `InternalError`）；成功时共享秘密恰为 32
//!    字节（SM3 输出）且可被 `derive_psk` 消费。
//!
//! 全部随机数由输入种子播种（`CryptoRng::seed_from_u64`），保证输入可复现。

#![no_main]

use std::collections::VecDeque;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use xtee_psk::{
    CryptoRng, PSK_LEN, PskError, PskResult, PskTransport, SM2_POINT_LEN, ServerPskContext,
    client_ecdh_negotiate, derive_psk, ecdh_compute_shared, generate_ecdh_keypair,
    parse_ecdh_response,
};

/// SM2 DSA Raw 签名长度（r || s）。
const RAW_SIG_LEN: usize = 64;

/// 处理协商结果并顺带走通错误格式化路径。
///
/// 生产路径上协商失败会把 `PskError` 格式化成日志文本（`xtee-psk/src/error.rs`
/// 的 6 个 `Display` 分支与 `Error::source`）；只断言 `is_err()` 会让这块
/// 代码永远不被执行，因此这里对每个错误都真正格式化一次。
///
/// 返回 `true` 表示协商成功。
fn note_err<T>(res: &PskResult<T>, ctx: &str) -> bool {
    match res {
        Ok(_) => true,
        Err(e) => {
            let text = format!("{e}");
            assert!(!text.is_empty(), "{ctx}: 错误文本不得为空");
            assert!(
                std::error::Error::source(e).is_none(),
                "{ctx}: PskError 不应带底层错误源"
            );
            false
        }
    }
}

/// 脚本化传输：`psk_send` 记录出帧，`psk_recv` 按脚本回帧。
struct ScriptedTransport {
    /// 依次回给被驱动方的帧；`None` 表示「对端不再说话」（返回错误）。
    inbox: VecDeque<Option<Vec<u8>>>,
    /// 被驱动方发出的帧。
    sent: Vec<Vec<u8>>,
    /// 让 `psk_send` 直接失败（用于验证错误传播）。
    fail_send: bool,
}

impl ScriptedTransport {
    fn scripted(inbox: Vec<Option<Vec<u8>>>) -> Self {
        Self {
            inbox: inbox.into(),
            sent: Vec::new(),
            fail_send: false,
        }
    }
}

impl PskTransport for ScriptedTransport {
    fn psk_send(&mut self, data: Vec<u8>) -> PskResult<()> {
        if self.fail_send {
            return Err(PskError::InternalError("脚本化发送失败".to_owned()));
        }
        self.sent.push(data);
        Ok(())
    }

    fn psk_recv(&mut self) -> PskResult<Vec<u8>> {
        match self.inbox.pop_front() {
            Some(Some(data)) => Ok(data),
            _ => Err(PskError::InvalidInput),
        }
    }
}

/// 客户端侧传输：记录客户端公钥，并按策略返回服务端响应。
struct ClientTransport {
    /// 客户端发出的临时公钥（首次 `psk_send`）。
    client_point: Option<Vec<u8>>,
    /// 嵌套驱动的服务端协商结果 `(PSK, 身份标识)`，仅诚实/篡改模式会填充。
    server_output: Option<([u8; PSK_LEN], &'static str)>,
    /// 响应策略：0 无响应 / 1 原始字节 / 2 空帧 / 3 任意位翻转 /
    /// 4 截断 / 5 篡改长期公钥 / 6 诚实。
    mode: u8,
    /// 破坏位置或截断长度。
    salt: usize,
    /// 策略 1 直接注入的响应字节。
    raw: Vec<u8>,
    /// 嵌套服务端的 `psk_send` 是否失败。
    server_fail_send: bool,
    /// 嵌套服务端的随机源（独立播种）。
    rng: CryptoRng,
}

impl ClientTransport {
    /// 单线程内嵌套驱动一次真实服务端协商，返回其响应帧。
    fn run_server(&mut self) -> PskResult<Vec<u8>> {
        let client_point = self.client_point.clone().ok_or(PskError::InvalidInput)?;
        let server = ServerPskContext::generate(&mut self.rng)?;
        let mut inner = ScriptedTransport::scripted(vec![Some(client_point)]);
        inner.fail_send = self.server_fail_send;
        let (psk, identity) = server.negotiate(&mut inner, &mut self.rng)?;
        self.server_output = Some((*psk, identity));
        inner.sent.into_iter().next().ok_or(PskError::InvalidInput)
    }
}

impl PskTransport for ClientTransport {
    fn psk_send(&mut self, data: Vec<u8>) -> PskResult<()> {
        self.client_point = Some(data);
        Ok(())
    }

    fn psk_recv(&mut self) -> PskResult<Vec<u8>> {
        match self.mode {
            0 => Err(PskError::InvalidInput),
            1 => Ok(self.raw.clone()),
            2 => Ok(Vec::new()),
            mode => {
                let mut resp = self.run_server()?;
                if resp.is_empty() {
                    return Err(PskError::InvalidInput);
                }
                match mode {
                    // 任意位置翻转 1 个比特：解析成功也必然验签失败。
                    3 => {
                        let idx = self.salt % resp.len();
                        resp[idx] ^= 0x01;
                    }
                    // 截断尾部：字段缺失/错位。
                    4 => {
                        let keep = self.salt % resp.len();
                        resp.truncate(keep);
                    }
                    // 只篡改长期公钥：签名不再是「所声明长期密钥」的签名。
                    5 => {
                        let idx = resp.len() - 1 - (self.salt % SM2_POINT_LEN);
                        resp[idx] ^= 0x01;
                    }
                    // 诚实响应。
                    _ => {}
                }
                Ok(resp)
            }
        }
    }
}

#[derive(Debug, Arbitrary)]
struct Input {
    /// 两侧随机源的共同种子。
    seed: u64,
    /// 客户端响应策略选择。
    mode: u8,
    /// 破坏位置 / 截断长度。
    salt: usize,
    /// 策略 1 直接注入的响应字节。
    raw: Vec<u8>,
    /// 服务端侧探针：客户端公钥构造方式（0 长度不足 / 1 合法前缀 / 2 错误前缀）。
    point_mode: u8,
    /// 客户端公钥的 64 字节坐标。
    point_xy: [u8; 64],
    /// 嵌套服务端的 `psk_send` 是否失败。
    server_fail_send: bool,
}

fuzz_target!(|input: Input| {
    let mode = input.mode % 7;

    // OS 熵源必须可用：生产路径（`CcClient::init`）依赖它构造协商随机源，
    // 这里顺带走通 `keygen::new_crypto_rng` 的错误映射分支。
    let _os_rng = xtee_psk::new_crypto_rng().expect("OS 熵源必须可用");

    // 1) 客户端侧：诚实 / 篡改 / 无响应
    let mut transport = ClientTransport {
        client_point: None,
        server_output: None,
        mode,
        salt: input.salt,
        raw: input.raw.clone(),
        server_fail_send: input.server_fail_send,
        rng: CryptoRng::seed_from_u64(input.seed ^ 0x9E37_79B9_7F4A_7C15),
    };
    let mut client_rng = CryptoRng::seed_from_u64(input.seed);
    let result = client_ecdh_negotiate(&mut transport, &mut client_rng);

    // 协议第一步必须是「客户端临时公钥 + 合法 SEC1 前缀」。
    let sent_point = transport
        .client_point
        .as_ref()
        .expect("客户端必须先发送公钥");
    assert_eq!(
        sent_point.len(),
        SM2_POINT_LEN,
        "客户端公钥必须是 65 字节 SEC1 未压缩点"
    );
    assert_eq!(sent_point[0], 0x04, "客户端公钥前缀必须是 0x04");

    if mode == 6 && !input.server_fail_send {
        let (psk, _server_point, identity) = result.expect("诚实传输下客户端协商必须成功");
        assert_ne!(*psk, [0u8; PSK_LEN], "派生的 PSK 不得为全零");
        let (server_psk, server_identity) = transport
            .server_output
            .expect("诚实模式必须嵌套驱动过服务端");
        assert_eq!(*psk, server_psk, "两侧派生的 PSK 必须一致");
        assert_eq!(identity, server_identity, "两侧的身份标识必须一致");
    } else {
        assert!(
            !note_err(&result, "客户端协商"),
            "mode={mode}（server_fail_send={}）下客户端不得协商成功",
            input.server_fail_send
        );
    }

    // 2) 服务端侧：畸形客户端公钥与响应帧结构
    let point = match input.point_mode % 3 {
        // 长度不足 65 字节。
        0 => input.point_xy.to_vec(),
        // 合法的 0x04 未压缩点（坐标随机，通常不在曲线上）。
        1 => {
            let mut p = Vec::with_capacity(SM2_POINT_LEN);
            p.push(0x04);
            p.extend_from_slice(&input.point_xy);
            p
        }
        // 前缀非 0x04 的 65 字节点。
        _ => {
            let mut p = Vec::with_capacity(SM2_POINT_LEN);
            p.push(0x02);
            p.extend_from_slice(&input.point_xy);
            p
        }
    };

    let mut rng = CryptoRng::seed_from_u64(input.seed ^ 0x5DEE_CE66_D1C0_0000);
    let server = ServerPskContext::generate(&mut rng).expect("服务端长期密钥生成不得失败");
    // `point` 在步骤 3 还要再用一次，这里拷贝一份交给脚本化传输。
    let mut scripted = ScriptedTransport::scripted(vec![Some(point.clone())]);
    scripted.fail_send = input.server_fail_send;
    let server_out = server.negotiate(&mut scripted, &mut rng);

    match input.point_mode % 3 {
        // 长度或前缀非法：必须在解析阶段直接拒绝。
        0 | 2 => assert!(
            !note_err(&server_out, "服务端协商"),
            "长度/前缀非法的客户端公钥必须被拒绝"
        ),
        // 合法前缀但坐标随机：允许失败；一旦成功，响应帧必须结构完整。
        _ => {
            if note_err(&server_out, "服务端协商") {
                let (psk, _identity) = server_out.expect("note_err 判定为 Ok");
                let resp = scripted
                    .sent
                    .first()
                    .cloned()
                    .expect("协商成功必须发出响应帧");
                let parsed = parse_ecdh_response(&resp).expect("响应帧必须可被解析");
                assert_eq!(parsed.server_point.len(), SM2_POINT_LEN);
                assert_eq!(
                    parsed.server_point[0], 0x04,
                    "服务端临时公钥前缀必须是 0x04"
                );
                assert_eq!(parsed.long_term_point.len(), SM2_POINT_LEN);
                assert_eq!(parsed.long_term_point[0], 0x04, "长期公钥前缀必须是 0x04");
                assert_eq!(
                    parsed.signature.len(),
                    RAW_SIG_LEN,
                    "SM2 DSA Raw 签名为 64 字节"
                );
                assert_ne!(*psk, [0u8; PSK_LEN], "派生的 PSK 不得为全零");
            }
        }
    }
    // 3) 直接调用 ECDH 原语：绕过握手顺序，把同一份畸形/随机点喂给
    //    `ecdh_compute_shared`，锁两条性质：
    //    a) 任何失败都归为 `InvalidPoint`——对端点来自网络，属输入非法，
    //       不得被兜底成 `InternalError`（否则调用方无法区分「对端耍赖」与
    //       「本机密码学后端坏了」）；
    //    b) 成功时共享秘密恰为 SM3 输出（32 字节），能被 `derive_psk` 消费。
    let mut ecdh_rng = CryptoRng::seed_from_u64(input.seed ^ 0xA5A5_5A5A_1234_5678);
    let our_key = generate_ecdh_keypair(&mut ecdh_rng).expect("ECDH 密钥对生成不得失败");
    match ecdh_compute_shared(&our_key, &point) {
        Ok(secret) => {
            assert_eq!(secret.len(), 32, "共享秘密必须是 SM3 输出（32 字节）");
            assert!(secret.iter().any(|&b| b != 0), "共享秘密不得为全零");
            let psk = derive_psk(&secret, &point, &point).expect("derive_psk 不得失败");
            assert_ne!(psk, [0u8; PSK_LEN], "派生的 PSK 不得为全零");
        }
        Err(e) => assert!(
            matches!(e, PskError::InvalidPoint),
            "对端点非法必须归为 InvalidPoint，实际为 {e:?}"
        ),
    }
});
