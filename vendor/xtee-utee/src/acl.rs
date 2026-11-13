// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! CA 路径白名单 ACL：将 Host 侧 CA 可执行路径与 [`teec_protocol::CaAuthInfo::ca_uuid`] 比对。
//!
//! `ca_uuid` 须与 Host 使用相同字符串调用 [`path_to_uuid`] 的结果一致（字节级相同的路径字符串）。

use teec_protocol::CaAuthInfo;

use crate::error::{Error, Result};

/// 与协议层一致：将 Host 上 CA 二进制路径转为 UUID v5 字符串（与 `CaAuthInfo::ca_uuid` 同源算法）。
pub use teec_protocol::path_to_uuid;

/// 若 `ca_auth_info` 的 `ca_uuid` 与 `allowed_paths` 中任一路径的 [`path_to_uuid`] 结果相同，则放行。
///
/// 不检查 [`CaAuthInfo::verified`]；若需验签通过，请另行调用 [`check_ca_verified`]。
///
/// - 无 `ca_auth_info`：拒绝（[`Error::AccessDenied`]）。
/// - 白名单为空或无任何路径匹配：拒绝（[`Error::AccessDenied`]）。
///
/// 注意：`allowed_paths` 中的字符串必须与 Host 计算 `ca_uuid` 时使用的路径完全一致。
pub fn check_ca_path_whitelist(
    ca_auth_info: Option<&CaAuthInfo>,
    allowed_paths: &[&str],
) -> Result<()> {
    let info = ca_auth_info.ok_or(Error::AccessDenied)?;
    for path in allowed_paths {
        if path_to_uuid(path) == info.ca_uuid {
            return Ok(());
        }
    }
    Err(Error::AccessDenied)
}

/// 要求 CA 认证信息存在且 [`CaAuthInfo::verified`] 为真（可信通道侧验签通过）。
///
/// - 无 `ca_auth_info`：[`Error::AccessDenied`]。
/// - `verified == false`：[`Error::AccessDenied`]。
pub fn check_ca_verified(ca_auth_info: Option<&CaAuthInfo>) -> Result<()> {
    let info = ca_auth_info.ok_or(Error::AccessDenied)?;
    if !info.verified {
        return Err(Error::AccessDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_PATH: &str = "/usr/bin/test";
    const KNOWN_UUID: &str = "f2d62525-c975-5075-8bfd-ea1a7c98adc3";

    #[test]
    fn whitelist_accepts_matching_verified_ca() {
        let info = CaAuthInfo {
            ca_uuid: KNOWN_UUID.to_string(),
            verified: true,
        };
        assert!(check_ca_path_whitelist(Some(&info), &[KNOWN_PATH]).is_ok());
    }

    #[test]
    fn whitelist_rejects_wrong_uuid() {
        let info = CaAuthInfo {
            ca_uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            verified: true,
        };
        assert_eq!(
            check_ca_path_whitelist(Some(&info), &[KNOWN_PATH]),
            Err(Error::AccessDenied)
        );
    }

    #[test]
    fn whitelist_accepts_unverified_if_path_matches() {
        let info = CaAuthInfo {
            ca_uuid: KNOWN_UUID.to_string(),
            verified: false,
        };
        assert!(check_ca_path_whitelist(Some(&info), &[KNOWN_PATH]).is_ok());
    }

    #[test]
    fn verified_rejects_unverified() {
        let info = CaAuthInfo {
            ca_uuid: KNOWN_UUID.to_string(),
            verified: false,
        };
        assert_eq!(check_ca_verified(Some(&info)), Err(Error::AccessDenied));
    }

    #[test]
    fn verified_accepts_verified() {
        let info = CaAuthInfo {
            ca_uuid: KNOWN_UUID.to_string(),
            verified: true,
        };
        assert!(check_ca_verified(Some(&info)).is_ok());
    }

    #[test]
    fn verified_rejects_none() {
        assert_eq!(check_ca_verified(None), Err(Error::AccessDenied));
    }

    #[test]
    fn whitelist_rejects_none_auth() {
        assert_eq!(
            check_ca_path_whitelist(None, &[KNOWN_PATH]),
            Err(Error::AccessDenied)
        );
    }

    #[test]
    fn whitelist_rejects_empty_list() {
        let info = CaAuthInfo {
            ca_uuid: KNOWN_UUID.to_string(),
            verified: true,
        };
        assert_eq!(
            check_ca_path_whitelist(Some(&info), &[]),
            Err(Error::AccessDenied)
        );
    }
}
