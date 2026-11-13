// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! TEE Client-Application 通信协议定义
//!
//! 提供 CA（Client Application）与 TA（Trusted Application）之间通信的协议类型。
//! 这些类型用于序列化/反序列化请求和响应数据，通过机密通信通道（TLS + VSOCK）传输。

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use bytemuck::{Pod, Zeroable};
use serde::{Deserialize, Serialize};

/// 数据包分块大小：32KiB
pub const CHUNK_SIZE: u64 = 32 * 1024;

/// 最大消息大小限制（10MB），防止 OOM 攻击
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// 数据包类型枚举，定义协议支持的不同操作类型
#[derive(Debug, PartialEq, Eq, Default)]
pub enum PacketType {
    #[default]
    Unknown = 0,
    OpenSession = 1,
    CloseSession = 2,
    InvokeCommand = 3,
    RequestCancellation = 4,
}

impl From<u64> for PacketType {
    fn from(value: u64) -> Self {
        match value {
            0 => PacketType::Unknown,
            1 => PacketType::OpenSession,
            2 => PacketType::CloseSession,
            3 => PacketType::InvokeCommand,
            4 => PacketType::RequestCancellation,
            _ => PacketType::Unknown,
        }
    }
}

impl From<PacketType> for u64 {
    fn from(value: PacketType) -> Self {
        match value {
            PacketType::Unknown => 0,
            PacketType::OpenSession => 1,
            PacketType::CloseSession => 2,
            PacketType::InvokeCommand => 3,
            PacketType::RequestCancellation => 4,
        }
    }
}

/// 协议头结构，使用 #[repr(C)] 确保内存布局与 C 兼容
/// 满足 bytemuck::Pod 要求：所有字段必须为基本类型
#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
pub struct PacketHeader {
    /// 数据包类型标识，对应 PacketType 枚举的数值表示
    pub data_type: u64,
    /// 数据包负载大小
    pub data_size: u64,
}

impl PacketHeader {
    /// 协议头结构体的大小
    pub const SIZE: usize = size_of::<PacketHeader>();

    /// 将协议头序列化为字节切片
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    /// 从字节切片反序列化协议头
    pub fn from_bytes(buf: &[u8]) -> Self {
        *bytemuck::from_bytes(buf)
    }
}

/// TA 注册请求。
///
/// TA 启动后通过此消息向 TEE OS 注册自身，声明其 UUID 及实例属性。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TARequest {
    Register {
        uuid: String,
        instance_id: u32,
        socket_path: String,
        is_single_instance: bool,
        is_multi_session: bool,
        is_instance_keep_alive: bool,
    },
}

/// TEE 请求枚举，定义 CA 发送给 TA 的所有请求类型
///
/// 这些请求会被序列化并通过机密通信通道（TLS + VSOCK）发送给 TA。
#[derive(Serialize, Deserialize)]
pub enum TEE_Request {
    OpenSession {
        uuid: String,
        connection_method: u32,
        params: TEE_Parameters,
        #[serde(default)]
        ca_auth_info: Option<CaAuthInfo>,
    },
    CloseSession {
        session_id: u32,
    },
    InvokeCommand {
        session_id: u32,
        cmd_id: u32,
        params: TEE_Parameters,
    },
    RequestCancellation {
        session_id: u32,
    },
}

/// CA 认证信息（用于 TA 的 ACL 访问控制）
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CaAuthInfo {
    /// CA 的唯一标识（UUID v5，基于调用者路径生成）
    pub ca_uuid: String,
    /// 验签是否通过（包含签名验证和证书链验证）
    pub verified: bool,
}

/// TEE 响应枚举，定义 TA 返回给 CA 的所有响应类型
///
/// 这些响应会被序列化并通过机密通信通道（TLS + VSOCK）发送给 CA。
#[derive(Serialize, Deserialize)]
pub enum TEE_Response {
    OpenSession { session_id: u32, result: u32 },
    CloseSession { result: u32 },
    InvokeCommand { params: TEE_Parameters, result: u32 },
    RequestCancellation { result: u32 },
}

/// TEE 参数容器，包含最多 4 个参数
///
/// 这些参数会被序列化到请求/响应数据包中，通过网络传输。
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct TEE_Parameters(
    pub TEE_Parameter,
    pub TEE_Parameter,
    pub TEE_Parameter,
    pub TEE_Parameter,
);

/// 单个 TEE 参数，包含参数值/数据和参数类型标识。
///
/// `param` 携带实际数据（VALUE (a,b) 或 MEMREF buffer），
/// `param_type` 指示该参数的读写方向（输入/输出/双向）。
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct TEE_Parameter {
    pub param: TEE_Param,
    pub param_type: TEE_ParamType,
}

/// TEE 参数的联合数据载体。
///
/// - `data`：用于 MEMREF 类型参数的缓冲区数据
/// - `values`：用于 VALUE 类型参数的 (a, b) 对
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct TEE_Param {
    pub data: Vec<u8>,
    pub values: TEE_Value,
}

/// TEE VALUE 类型参数的值对。
///
/// 对应 GP TEE Client API 中的 `TEEC_Value`，
/// 包含两个 32 位无符号整数 `a` 和 `b`。
#[derive(Serialize, Deserialize, Clone, Copy, Default)]
pub struct TEE_Value {
    pub a: u32,
    pub b: u32,
}

/// TEE 参数类型枚举，指示参数的读写方向。
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone, Copy)]
pub enum TEE_ParamType {
    #[default]
    None = 0,
    ValueInput = 1,
    ValueOutput = 2,
    ValueInout = 3,
    MemrefInput = 5,
    MemrefOutput = 6,
    MemrefInout = 7,
}

impl From<u32> for TEE_ParamType {
    fn from(value: u32) -> Self {
        match value {
            0 => TEE_ParamType::None,
            1 => TEE_ParamType::ValueInput,
            2 => TEE_ParamType::ValueOutput,
            3 => TEE_ParamType::ValueInout,
            5 => TEE_ParamType::MemrefInput,
            6 => TEE_ParamType::MemrefOutput,
            7 => TEE_ParamType::MemrefInout,
            _ => TEE_ParamType::None,
        }
    }
}

impl From<TEE_ParamType> for u32 {
    fn from(value: TEE_ParamType) -> Self {
        match value {
            TEE_ParamType::None => 0,
            TEE_ParamType::ValueInput => 1,
            TEE_ParamType::ValueOutput => 2,
            TEE_ParamType::ValueInout => 3,
            TEE_ParamType::MemrefInput => 5,
            TEE_ParamType::MemrefOutput => 6,
            TEE_ParamType::MemrefInout => 7,
        }
    }
}

/// 将路径转换为 UUID v5（用于生成 CA 唯一标识符）
///
/// 使用 NIL UUID 作为命名空间，路径字符串作为名称，
/// 生成的 UUID 可用于 TEE_Request::OpenSession 的 ca_auth_info.ca_uuid 字段。
pub fn path_to_uuid(path: &str) -> String {
    use uuid::Uuid;
    let namespace = Uuid::nil();
    Uuid::new_v5(&namespace, path.as_bytes()).to_string()
}

/// 协议中使用的类型别名，为兼容 Teaclave TrustZone SDK。
pub use TEE_ParamType as ParamType;
/// 协议中使用的类型别名，为兼容 Teaclave TrustZone SDK。
pub use TEE_Parameter as Parameter;
/// 协议中使用的类型别名，为兼容 Teaclave TrustZone SDK。
pub use TEE_Parameters as Parameters;
/// 协议中使用的类型别名，为兼容 Teaclave TrustZone SDK。
pub use TEE_Value as Value;

#[cfg(test)]
mod protocol_tests {
    use super::*;

    #[test]
    fn test_tee_param_type_from_u32() {
        // 测试 TEE_ParamType 的 From<u32> 实现 - 覆盖所有分支
        assert_eq!(TEE_ParamType::from(0), TEE_ParamType::None);
        assert_eq!(TEE_ParamType::from(1), TEE_ParamType::ValueInput);
        assert_eq!(TEE_ParamType::from(2), TEE_ParamType::ValueOutput);
        assert_eq!(TEE_ParamType::from(3), TEE_ParamType::ValueInout);
        assert_eq!(TEE_ParamType::from(4), TEE_ParamType::None); // 未知值 -> None
        assert_eq!(TEE_ParamType::from(5), TEE_ParamType::MemrefInput);
        assert_eq!(TEE_ParamType::from(6), TEE_ParamType::MemrefOutput);
        assert_eq!(TEE_ParamType::from(7), TEE_ParamType::MemrefInout);
        assert_eq!(TEE_ParamType::from(8), TEE_ParamType::None); // 未知值 -> None
        assert_eq!(TEE_ParamType::from(99), TEE_ParamType::None); // 未知值 -> None
        assert_eq!(TEE_ParamType::from(255), TEE_ParamType::None); // 边界值
    }

    #[test]
    fn test_tee_param_type_into_u32() {
        // 测试 TEE_ParamType 的 Into<u32> 实现 - 覆盖所有变体
        assert_eq!(u32::from(TEE_ParamType::None), 0);
        assert_eq!(u32::from(TEE_ParamType::ValueInput), 1);
        assert_eq!(u32::from(TEE_ParamType::ValueOutput), 2);
        assert_eq!(u32::from(TEE_ParamType::ValueInout), 3);
        assert_eq!(u32::from(TEE_ParamType::MemrefInput), 5);
        assert_eq!(u32::from(TEE_ParamType::MemrefOutput), 6);
        assert_eq!(u32::from(TEE_ParamType::MemrefInout), 7);
    }

    #[test]
    fn test_tee_param_type_roundtrip() {
        // 测试双向转换的往返一致性
        let values = vec![0, 1, 2, 3, 5, 6, 7];
        for value in values {
            let param_type = TEE_ParamType::from(value);
            let back_to_u32: u32 = param_type.into();
            assert_eq!(value, back_to_u32);
        }
    }

    #[test]
    fn test_tee_value_default() {
        // 测试 TEE_Value 的 Default trait
        let default_val = TEE_Value::default();
        assert_eq!(default_val.a, 0);
        assert_eq!(default_val.b, 0);
    }

    #[test]
    fn test_tee_parameter_default() {
        // 测试 TEE_Parameter 的 Default trait
        let default_param = TEE_Parameter::default();
        assert_eq!(default_param.param_type, TEE_ParamType::None);
        assert_eq!(default_param.param.values.a, 0);
        assert_eq!(default_param.param.values.b, 0);
        assert!(default_param.param.data.is_empty());
    }

    #[test]
    fn test_packet_header_serialization_roundtrip() {
        // 测试 PacketHeader 序列化/反序列化的往返一致性
        let original = PacketHeader {
            data_type: 0x1234_5678_9ABC_DEF0,
            data_size: 0xFEDC_BA98_7654_3210,
        };

        let bytes = original.as_bytes();
        let restored = PacketHeader::from_bytes(bytes);

        assert_eq!(original.data_type, restored.data_type);
        assert_eq!(original.data_size, restored.data_size);
    }

    #[test]
    fn test_packet_type_conversion() {
        // 测试协议类型转换 - 覆盖所有分支
        assert_eq!(PacketType::from(0), PacketType::Unknown);
        assert_eq!(PacketType::from(1), PacketType::OpenSession);
        assert_eq!(PacketType::from(2), PacketType::CloseSession);
        assert_eq!(PacketType::from(3), PacketType::InvokeCommand);
        assert_eq!(PacketType::from(4), PacketType::RequestCancellation);
        assert_eq!(PacketType::from(5), PacketType::Unknown); // 未知值 -> Unknown
        assert_eq!(PacketType::from(0xFFFFFFFF), PacketType::Unknown); // 边界值

        assert_eq!(u64::from(PacketType::Unknown), 0);
        assert_eq!(u64::from(PacketType::OpenSession), 1);
        assert_eq!(u64::from(PacketType::CloseSession), 2);
        assert_eq!(u64::from(PacketType::InvokeCommand), 3);
        assert_eq!(u64::from(PacketType::RequestCancellation), 4);
    }

    #[test]
    fn test_packet_header_size() {
        use core::mem;

        // 测试协议头数据大小
        let packet0 = PacketHeader {
            data_type: u64::from(PacketType::OpenSession),
            data_size: CHUNK_SIZE,
        };

        let packet1 = PacketHeader {
            data_type: u64::from(PacketType::CloseSession),
            data_size: 44,
        };

        assert_eq!(mem::size_of_val(&packet0), PacketHeader::SIZE);
        assert_eq!(mem::size_of_val(&packet1), PacketHeader::SIZE);
        assert_eq!(PacketHeader::SIZE, mem::size_of::<PacketHeader>());
    }

    #[test]
    fn test_path_to_uuid_consistency() {
        // 相同路径应该生成相同的 UUID
        let uuid1 = path_to_uuid("/usr/bin/test");
        let uuid2 = path_to_uuid("/usr/bin/test");
        assert_eq!(uuid1, uuid2);
    }

    #[test]
    fn test_path_to_uuid_uniqueness() {
        // 不同路径应该生成不同的 UUID
        let uuid1 = path_to_uuid("/usr/bin/test1");
        let uuid2 = path_to_uuid("/usr/bin/test2");
        assert_ne!(uuid1, uuid2);
    }

    #[test]
    fn test_path_to_uuid_deterministic() {
        // 测试 UUID v5 的确定性：相同路径总是生成相同的 UUID
        // 这是 UUID v5 的核心特性，用于 CA 身份标识的稳定性

        // 已知路径的已知 UUID（回归测试，确保算法稳定）
        assert_eq!(
            path_to_uuid("/usr/bin/test"),
            "f2d62525-c975-5075-8bfd-ea1a7c98adc3"
        );

        // 不同路径生成不同 UUID
        assert_ne!(path_to_uuid("/usr/bin/test"), path_to_uuid("/usr/bin/ls"));
    }
}
