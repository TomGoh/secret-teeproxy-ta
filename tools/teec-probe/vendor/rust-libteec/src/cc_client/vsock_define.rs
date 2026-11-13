// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! VSOCK 连接参数配置模块。
//!
//! 提供 VSOCK CID 和 Port 的默认值及环境变量读取功能，
//! 支持通过 `VSOCK_CID` / `VSOCK_PORT` 环境变量覆盖默认配置。

use std::env;
use std::sync::OnceLock;

static EXPLICIT_ENDPOINT: OnceLock<(u32,u32)> = OnceLock::new();

/// Explicit process-local endpoint for the APK/JNI adapter. The first successful
/// call fixes the endpoint for this SDK instance. Matching configuration is
/// idempotent and an incompatible later endpoint is rejected.
pub fn configure_vsock_endpoint(cid:u32,port:u32) -> Result<(), &'static str> {
    if cid<=2 || port==0 {return Err("invalid VSOCK endpoint");}
    let requested=(cid,port);
    match EXPLICIT_ENDPOINT.set(requested) {
        Ok(())=>Ok(()),
        Err(_) if EXPLICIT_ENDPOINT.get()==Some(&requested)=>Ok(()),
        Err(_)=>Err("VSOCK endpoint already configured differently"),
    }
}

/// 默认 VSOCK Server CID
pub const DEFAULT_VSOCK_SERVER_CID: u32 = 103;

/// 默认 VSOCK Port
pub const DEFAULT_VSOCK_PORT: u32 = 9999;

/// 获取 VSOCK Server CID
///
/// 优先从环境变量 `VSOCK_CID` 读取，如果未设置则使用默认值 103
///
/// **注意**: 此函数仅在库内部使用，不对外公开。
pub(crate) fn get_vsock_cid() -> u32 {
    if let Some(&(cid,_))=EXPLICIT_ENDPOINT.get() {return cid;}
    env::var("VSOCK_CID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_VSOCK_SERVER_CID)
}

/// 获取 VSOCK Port
///
/// 优先从环境变量 `VSOCK_PORT` 读取，如果未设置则使用默认值 9999
///
/// **注意**: 此函数仅在库内部使用，不对外公开。
pub(crate) fn get_vsock_port() -> u32 {
    if let Some(&(_,port))=EXPLICIT_ENDPOINT.get() {return port;}
    env::var("VSOCK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_VSOCK_PORT)
}

#[cfg(test)]
mod vsock_tests {
    use super::*;
    use std::{env, sync::Mutex};

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_default_vsock_cid() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // 清除环境变量，测试默认值
        // SAFETY: 在测试环境中修改环境变量是安全的，通过 Mutex 保证互斥访问
        unsafe { env::remove_var("VSOCK_CID") };
        let cid = get_vsock_cid();
        assert_eq!(
            cid, DEFAULT_VSOCK_SERVER_CID,
            "默认 CID 应该为 {}",
            DEFAULT_VSOCK_SERVER_CID
        );
    }

    #[test]
    fn test_default_vsock_port() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // 清除环境变量，测试默认值
        // SAFETY: 在测试环境中修改环境变量是安全的，通过 Mutex 保证互斥访问
        unsafe { env::remove_var("VSOCK_PORT") };
        let port = get_vsock_port();
        assert_eq!(
            port, DEFAULT_VSOCK_PORT,
            "默认 Port 应该为 {}",
            DEFAULT_VSOCK_PORT
        );
    }

    #[test]
    fn test_custom_vsock_cid() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // 保存原值
        let old_value = env::var("VSOCK_CID").ok();

        // 设置自定义 CID
        // SAFETY: 在测试环境中修改环境变量是安全的，通过 Mutex 保证互斥访问
        unsafe { env::set_var("VSOCK_CID", "200") };
        let cid = get_vsock_cid();
        assert_eq!(cid, 200, "自定义 CID 应该为 200");

        // 恢复原值或清除
        match old_value {
            Some(val) => unsafe { env::set_var("VSOCK_CID", val) },
            None => unsafe { env::remove_var("VSOCK_CID") },
        }
    }

    #[test]
    fn test_custom_vsock_port() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // 保存原值
        let old_value = env::var("VSOCK_PORT").ok();

        // 设置自定义 Port
        // SAFETY: 在测试环境中修改环境变量是安全的，通过 Mutex 保证互斥访问
        unsafe { env::set_var("VSOCK_PORT", "8888") };
        let port = get_vsock_port();
        assert_eq!(port, 8888, "自定义 Port 应该为 8888");

        // 恢复原值或清除
        match old_value {
            Some(val) => unsafe { env::set_var("VSOCK_PORT", val) },
            None => unsafe { env::remove_var("VSOCK_PORT") },
        }
    }

    #[test]
    fn test_invalid_vsock_cid() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // 保存原值
        let old_value = env::var("VSOCK_CID").ok();

        // 设置无效值，应该回退到默认值
        // SAFETY: 在测试环境中修改环境变量是安全的，通过 Mutex 保证互斥访问
        unsafe { env::set_var("VSOCK_CID", "invalid") };
        let cid = get_vsock_cid();
        assert_eq!(cid, DEFAULT_VSOCK_SERVER_CID, "无效 CID 应该回退到默认值");

        // 恢复原值或清除
        match old_value {
            Some(val) => unsafe { env::set_var("VSOCK_CID", val) },
            None => unsafe { env::remove_var("VSOCK_CID") },
        }
    }

    #[test]
    fn test_invalid_vsock_port() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // 保存原值
        let old_value = env::var("VSOCK_PORT").ok();

        // 设置无效值，应该回退到默认值
        // SAFETY: 在测试环境中修改环境变量是安全的，通过 Mutex 保证互斥访问
        unsafe { env::set_var("VSOCK_PORT", "not_a_number") };
        let port = get_vsock_port();
        assert_eq!(port, DEFAULT_VSOCK_PORT, "无效 Port 应该回退到默认值");

        // 恢复原值或清除
        match old_value {
            Some(val) => unsafe { env::set_var("VSOCK_PORT", val) },
            None => unsafe { env::remove_var("VSOCK_PORT") },
        }
    }
}
