// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//
// This file was modified by KylinSoft Co., Ltd. on 2025.

//! TEE 错误处理模块。
//!
//! 定义了 TEE Client API 的错误类型体系：
//! - [`ErrorKind`]：映射 GlobalPlatform TEE 标准错误码
//! - [`ErrorOrigin`]：标识错误来源（API / Comms / TEE / TA）
//! - [`Error`]：封装错误类型、来源及格式化输出，支持 `PoisonError` 转换

use std::{fmt, sync::PoisonError};

use num_enum::{FromPrimitive, IntoPrimitive};

use crate::raw;

/// TEE Result 类型。
pub type Result<T> = std::result::Result<T, Error>;

/// TEE 操作错误类型。
#[derive(Clone)]
pub struct Error {
    kind: ErrorKind,
    origin: Option<ErrorOrigin>,
}

/// 指定 TEE 客户端错误通用类别及其在 OP-TEE 客户端库中对应代码的列表。
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, FromPrimitive, IntoPrimitive,
)]
#[repr(u32)]
pub enum ErrorKind {
    /// 非特定原因。
    Generic = raw::TEEC_ERROR_GENERIC,
    /// 访问权限不足。
    AccessDenied = raw::TEEC_ERROR_ACCESS_DENIED,
    /// 操作已取消。
    Cancel = raw::TEEC_ERROR_CANCEL,
    /// 并发访问导致冲突。
    AccessConflict = raw::TEEC_ERROR_ACCESS_CONFLICT,
    /// 为请求的操作传递了过多数据。
    ExcessData = raw::TEEC_ERROR_EXCESS_DATA,
    /// 输入数据格式无效。
    BadFormat = raw::TEEC_ERROR_BAD_FORMAT,
    /// 输入参数无效。
    BadParameters = raw::TEEC_ERROR_BAD_PARAMETERS,
    /// 在当前状态下操作无效。
    BadState = raw::TEEC_ERROR_BAD_STATE,
    /// 未找到请求的数据项。
    ItemNotFound = raw::TEEC_ERROR_ITEM_NOT_FOUND,
    /// 请求的操作应该存在但尚未实现。
    NotImplemented = raw::TEEC_ERROR_NOT_IMPLEMENTED,
    /// 请求的操作有效，但在此实现中不支持。
    NotSupported = raw::TEEC_ERROR_NOT_SUPPORTED,
    /// 缺少预期数据。
    NoData = raw::TEEC_ERROR_NO_DATA,
    /// 系统资源耗尽。
    OutOfMemory = raw::TEEC_ERROR_OUT_OF_MEMORY,
    /// 系统正忙于处理其他任务。
    Busy = raw::TEEC_ERROR_BUSY,
    /// 与远程方的通信失败。
    Communication = raw::TEEC_ERROR_COMMUNICATION,
    /// 检测到安全故障。
    Security = raw::TEEC_ERROR_SECURITY,
    /// 提供的缓冲区对于生成的输出太短。
    ShortBuffer = raw::TEEC_ERROR_SHORT_BUFFER,
    /// 实现定义的错误代码。
    ExternalCancel = raw::TEEC_ERROR_EXTERNAL_CANCEL,
    /// 实现定义的错误代码：可信应用程序在操作期间发生崩溃。
    TargetDead = raw::TEEC_ERROR_TARGET_DEAD,
    /// 未知错误。
    #[default]
    Unknown,
}

impl ErrorKind {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            ErrorKind::Generic => "Non-specific cause.",
            ErrorKind::AccessDenied => "Access privileges are not sufficient.",
            ErrorKind::Cancel => "The operation was canceled.",
            ErrorKind::AccessConflict => "Concurrent accesses caused conflict.",
            ErrorKind::ExcessData => "Too much data for the requested operation was passed.",
            ErrorKind::BadFormat => "Input data was of invalid format.",
            ErrorKind::BadParameters => "Input parameters were invalid.",
            ErrorKind::BadState => "Operation is not valid in the current state.",
            ErrorKind::ItemNotFound => "The requested data item is not found.",
            ErrorKind::NotImplemented => {
                "The requested operation should exist but is not yet implemented."
            }
            ErrorKind::NotSupported => {
                "The requested operation is valid but is not supported in this implementation."
            }
            ErrorKind::NoData => "Expected data was missing.",
            ErrorKind::OutOfMemory => "System ran out of resources.",
            ErrorKind::Busy => "The system is busy working on something else.",
            ErrorKind::Communication => "Communication with a remote party failed.",
            ErrorKind::Security => "A security fault was detected.",
            ErrorKind::ShortBuffer => "The supplied buffer is too short for the generated output.",
            ErrorKind::ExternalCancel => "Undocumented.",
            ErrorKind::TargetDead => "Trusted Application has panicked during the operation.",
            ErrorKind::Unknown => "Unknown error.",
        }
    }
}

impl Error {
    pub fn new(kind: ErrorKind) -> Error {
        Error { kind, origin: None }
    }

    /// 从原始 TEE 错误代码创建 Error 实例
    pub fn from_raw_error(code: u32) -> Error {
        Error {
            kind: ErrorKind::from(code),
            origin: None,
        }
    }

    /// 设置错误来源
    pub fn with_origin(mut self, origin: ErrorOrigin) -> Self {
        self.origin = Some(origin);
        self
    }

    /// 获取错误类型
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// 获取错误来源
    pub fn origin(&self) -> Option<ErrorOrigin> {
        self.origin
    }

    /// 获取原始错误码（用于 FFI 接口）
    pub fn raw_code(&self) -> u32 {
        self.kind.into()
    }

    /// 获取错误描述信息
    pub fn message(&self) -> &str {
        self.kind().as_str()
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Error::new(ErrorKind::Generic).with_origin(ErrorOrigin::API)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "{} (错误代码 0x{:x}, 来源 0x{:x})",
            self.message(),
            self.raw_code(),
            self.origin().map(|v| v.into()).unwrap_or(0_u32),
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        self.message()
    }
}

impl From<ErrorKind> for Error {
    #[inline]
    fn from(kind: ErrorKind) -> Error {
        Error { kind, origin: None }
    }
}

/// 错误来源，取值与 GlobalPlatform TEE Client API 的 `TEEC_Origin` 一致，
/// 失败时由 C API 写入调用方的 `ret_origin` 输出参数。
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum ErrorOrigin {
    /// 错误来源于 TEE 客户端 API 实现。
    API = raw::TEEC_ORIGIN_API,
    /// 错误来源于底层通信栈（负责连接 rich OS 与 TEE）。
    COMMS = raw::TEEC_ORIGIN_COMMS,
    /// 错误来源于通用 TEE 代码。
    TEE = raw::TEEC_ORIGIN_TEE,
    /// 错误来源于可信应用（TA）。
    TA = raw::TEEC_ORIGIN_TRUSTED_APP,
    /// 未标注来源时的默认值。规范未定义该取值，库内约定为 5
    /// （`TEEC_ORIGIN_TRUSTED_APP` + 1），会原样暴露给调用方。
    #[default]
    UNKNOWN,
}

#[cfg(test)]
mod teec_error_tests {
    use super::*;

    /// 辅助宏：批量测试 ErrorKind 的 as_str 方法
    macro_rules! test_error_kind_messages {
        ($($variant:ident => $msg:expr),* $(,)?) => {
            $(
                assert_eq!(ErrorKind::$variant.as_str(), $msg);
            )*
        };
    }

    #[test]
    fn test_error_types_and_methods() {
        // 使用宏批量测试所有 ErrorKind 变体的消息
        test_error_kind_messages! {
            Generic => "Non-specific cause.",
            AccessDenied => "Access privileges are not sufficient.",
            Cancel => "The operation was canceled.",
            AccessConflict => "Concurrent accesses caused conflict.",
            ExcessData => "Too much data for the requested operation was passed.",
            BadFormat => "Input data was of invalid format.",
            BadParameters => "Input parameters were invalid.",
            BadState => "Operation is not valid in the current state.",
            ItemNotFound => "The requested data item is not found.",
            NotImplemented => "The requested operation should exist but is not yet implemented.",
            NotSupported => "The requested operation is valid but is not supported in this implementation.",
            NoData => "Expected data was missing.",
            OutOfMemory => "System ran out of resources.",
            Busy => "The system is busy working on something else.",
            Communication => "Communication with a remote party failed.",
            Security => "A security fault was detected.",
            ShortBuffer => "The supplied buffer is too short for the generated output.",
            ExternalCancel => "Undocumented.",
            TargetDead => "Trusted Application has panicked during the operation.",
            Unknown => "Unknown error.",
        }

        // 测试 Error 的创建和访问方法
        let error = Error::new(ErrorKind::BadParameters);
        assert_eq!(error.kind(), ErrorKind::BadParameters);
        assert_eq!(error.origin(), None);

        // 测试 from_raw_error 方法
        let raw_error = Error::from_raw_error(ErrorKind::Generic.into());
        assert_eq!(raw_error.kind(), ErrorKind::Generic);

        // 测试 with_origin 方法
        let error_with_origin = Error::new(ErrorKind::Generic).with_origin(ErrorOrigin::API);
        assert_eq!(error_with_origin.origin(), Some(ErrorOrigin::API));

        // 测试 raw_code 方法
        assert_eq!(error.raw_code(), u32::from(ErrorKind::BadParameters));

        // 测试 message 方法
        assert_eq!(error.message(), "Input parameters were invalid.");

        // 测试 Debug 格式化
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("错误代码"));

        // 测试 Display 格式化
        let display_str = format!("{}", error);
        assert!(display_str.contains("错误代码"));

        // 测试 From trait
        let from_kind: Error = ErrorKind::OutOfMemory.into();
        assert_eq!(from_kind.kind(), ErrorKind::OutOfMemory);

        // 测试 ErrorOrigin 的转换
        assert_eq!(u32::from(ErrorOrigin::API), raw::TEEC_ORIGIN_API);
        assert_eq!(u32::from(ErrorOrigin::COMMS), raw::TEEC_ORIGIN_COMMS);
        assert_eq!(u32::from(ErrorOrigin::TEE), raw::TEEC_ORIGIN_TEE);
        assert_eq!(u32::from(ErrorOrigin::TA), raw::TEEC_ORIGIN_TRUSTED_APP);
    }

    #[test]
    fn test_error_kind_all_variants_as_str() {
        // 测试所有 ErrorKind 变体
        let error_kinds = vec![
            ErrorKind::Generic,
            ErrorKind::AccessDenied,
            ErrorKind::Cancel,
            ErrorKind::AccessConflict,
            ErrorKind::ExcessData,
            ErrorKind::BadFormat,
            ErrorKind::BadParameters,
            ErrorKind::BadState,
            ErrorKind::ItemNotFound,
            ErrorKind::NotImplemented,
            ErrorKind::NotSupported,
            ErrorKind::NoData,
            ErrorKind::OutOfMemory,
            ErrorKind::Busy,
            ErrorKind::Communication,
            ErrorKind::Security,
            ErrorKind::ShortBuffer,
            ErrorKind::ExternalCancel,
            ErrorKind::TargetDead,
            ErrorKind::Unknown,
        ];

        for kind in error_kinds {
            let error = Error::new(kind);
            // 调用 kind 方法不应该崩溃
            let _ = error.kind();
        }
    }

    /// 测试 ErrorOrigin 到 u32 的转换
    #[test]
    fn test_error_origin_to_u32() {
        assert_eq!(u32::from(ErrorOrigin::API), raw::TEEC_ORIGIN_API);
        assert_eq!(u32::from(ErrorOrigin::COMMS), raw::TEEC_ORIGIN_COMMS);
        assert_eq!(u32::from(ErrorOrigin::TEE), raw::TEEC_ORIGIN_TEE);
        assert_eq!(u32::from(ErrorOrigin::TA), raw::TEEC_ORIGIN_TRUSTED_APP);
    }

    #[test]
    fn test_error_clone() {
        let error = Error::new(ErrorKind::Communication).with_origin(ErrorOrigin::COMMS);
        let cloned = error.clone();
        assert_eq!(cloned.kind(), ErrorKind::Communication);
        assert_eq!(cloned.origin(), Some(ErrorOrigin::COMMS));
    }

    #[test]
    fn test_error_from_poison() {
        let lock = std::sync::Mutex::new(42u32);
        let lock_clone = std::sync::Arc::new(lock);
        let lock_clone2 = lock_clone.clone();

        let handle = std::thread::spawn(move || {
            let _guard = lock_clone2.lock().unwrap();
            panic!("intentional panic to poison mutex");
        });
        let _ = handle.join();

        let error: Error = lock_clone.lock().unwrap_err().into();
        assert_eq!(error.kind(), ErrorKind::Generic);
        assert_eq!(error.origin(), Some(ErrorOrigin::API));
    }

    #[test]
    fn test_error_display_with_origin() {
        let error = Error::new(ErrorKind::Communication).with_origin(ErrorOrigin::COMMS);
        let display = format!("{error}");
        assert!(display.contains("Communication"));
        // orig 版本使用数字表示 origin,不是字符串
        assert!(display.contains("0x"));
    }

    #[test]
    fn test_error_display_no_origin() {
        let error = Error::new(ErrorKind::OutOfMemory);
        let display = format!("{error}");
        assert!(display.contains("resources"));
    }

    #[test]
    fn test_error_debug_format() {
        let error = Error::new(ErrorKind::Security).with_origin(ErrorOrigin::TEE);
        let debug = format!("{error:?}");
        // orig 版本的 Debug 格式包含错误消息和代码
        assert!(debug.contains("security") || debug.contains("fault"));
        // orig 版本使用数字表示 origin
        assert!(debug.contains("0x"));
    }

    #[test]
    fn test_error_origin_unknown() {
        assert_eq!(u32::from(ErrorOrigin::UNKNOWN), 5);
        assert_eq!(ErrorOrigin::from(5), ErrorOrigin::UNKNOWN);
    }
}
