// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! PSK 协商错误类型定义。

use std::fmt::{Display, Formatter};

/// PSK 协商错误
#[derive(Debug)]
pub enum PskError {
    /// 密钥无效或格式错误
    InvalidKey,
    /// 输入数据无效
    InvalidInput,
    /// 长度不匹配
    InvalidLength,
    /// EC 点无效（非未压缩格式或不在曲线上）
    InvalidPoint,
    /// 签名验证失败
    VerificationFailed,
    /// 内部密码学错误（保留原始错误信息）
    InternalError(String),
}

impl Display for PskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid key"),
            Self::InvalidInput => write!(f, "invalid input"),
            Self::InvalidLength => write!(f, "invalid length"),
            Self::InvalidPoint => write!(f, "invalid EC point"),
            Self::VerificationFailed => write!(f, "verification failed"),
            Self::InternalError(e) => write!(f, "internal crypto error: {e}"),
        }
    }
}

impl std::error::Error for PskError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// PSK 操作的结果类型别名。
///
/// 封装 [`Result<T, PskError>`]，简化函数签名中的错误类型书写。
pub type PskResult<T> = Result<T, PskError>;
