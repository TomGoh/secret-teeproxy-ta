// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! TEE CA 认证模块
//!
//! 提供 CA（Client Application）身份认证功能，用于 TA 的 ACL 访问控制。
//!
//! ## 主要功能
//!
//! - **CA 身份标识**: 基于调用者路径生成 UUID v5
//! - **签名验证**: 使用 tasign 验证 ELF 文件签名
//! - **结果缓存**: 基于 (PID, inode, mtime, dev) 的复合键缓存验签结果
//!
//! ## CA 验签缓存
//!
//! 使用 DashMap 实现无锁并发访问，缓存键为 (进程ID, CA文件标识)。
//!
//! CA 文件标识基于 inode、mtime 和 dev，可检测：
//! - 文件被替换（inode 变化）
//! - 文件内容修改（mtime 变化）
//! - 不同设备上的同名文件（dev 区分）
//!
//! 缓存策略：
//! - 同一进程内，CA 文件未改变时复用验签结果
//! - 进程 fork 后，若执行文件被替换则重新验签
//! - 不同进程的 CA 文件各自独立缓存
//!
//! ## TA 访问控制
//!
//! TA 侧据 `CaAuthInfo` 识别调用者，关键字段：
//! - `ca_uuid`: 哪个 CA 发起的请求
//! - `verified`: 验签是否通过（包含签名验证和证书链验证）

use std::{fs, os::unix::fs::MetadataExt, sync::LazyLock};

use dashmap::DashMap;
use log::{debug, warn};

use teec_protocol::{CaAuthInfo, path_to_uuid};

/// TA 签名 CA 证书链（生产环境）。
///
/// `certs/kylin-xtee-ca-sign-root.pem` 内含两张证书：自签的麒麟软件根证书
/// （Kylin Software Root Cert）与其签发的 CA 证书（Kylin Software Applications Cert）。
/// 校验 TA 签名 ELF 的证书链；若签发链与本文件不一致，链校验不通过，
/// `CaAuthInfo::verified` 为 `false`。
/// 默认启用；当 `test-root-ca` feature 启用时改用 tasign 内置测试根证书。
#[cfg(not(feature = "test-root-ca"))]
const TA_SIGN_ROOT_CA_PEM: &[u8] = include_bytes!("../../certs/kylin-xtee-ca-sign-root.pem");

/// 加载 CA 证书链 PEM 字节，用于证书链验证。
///
/// 编译期通过 feature flag 决定使用哪份证书链：
/// - 默认（未启用 `test-root-ca`）：嵌入 `certs/kylin-xtee-ca-sign-root.pem`
///   （麒麟软件根证书 + 其下级 CA 证书；x-kernel 侧须使用同一份证书链）；
/// - 启用 `test-root-ca`：tasign 内置测试根证书（`tasign::cert::CA_CERT_PEM`），
///   以支持 TEST 签名 ELF 的完整证书链验证。
fn load_root_ca_cert() -> &'static [u8] {
    #[cfg(not(feature = "test-root-ca"))]
    {
        debug!("使用内置 CA 根证书");
        TA_SIGN_ROOT_CA_PEM
    }

    #[cfg(feature = "test-root-ca")]
    {
        debug!("使用 tasign 内置测试根证书");
        tasign::cert::CA_CERT_PEM
    }
}

/// 缓存键：(进程ID, CA文件标识)
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    pid: i32,
    ca_file_id: CaFileId,
}

/// CA 文件唯一标识（基于 inode + mtime + dev）
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CaFileId {
    inode: u64,      // inode 号
    mtime: i64,      // 修改时间（秒）
    mtime_nsec: i64, // 修改时间（纳秒部分）
    dev: u64,        // 设备号
}

/// 获取 CA 文件的唯一标识（基于已打开文件句柄的元数据）
///
/// 使用 `File::metadata()`（即 fstat）从文件描述符读取元数据。与基于路径的
/// `fs::metadata()` 不同，fd 的元数据与后续从同一 fd 读取的内容必然来自
/// 同一文件实例，消除两次独立路径解析之间的 TOCTOU。
fn get_ca_file_id_from_file(file: &fs::File) -> Option<CaFileId> {
    match file.metadata() {
        Ok(metadata) => Some(CaFileId {
            inode: metadata.ino(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            dev: metadata.dev(),
        }),
        Err(_) => None,
    }
}

/// 全局缓存：使用 DashMap 提供无锁并发访问
/// key为(PID, CA文件标识)，value为CA认证信息
static CA_AUTH_CACHE: LazyLock<DashMap<CacheKey, CaAuthInfo>> = LazyLock::new(DashMap::new);

/// 获取或执行 CA 认证（带缓存）
///
/// 返回 CA 认证信息，用于 TA 的 ACL 访问控制。
///
/// 缓存键基于进程 ID 和 CA 文件标识，可检测：
/// - 同一进程内文件未改变时复用结果
/// - 文件被替换（inode/mtime 变化）时重新验签
/// - 不同进程的 CA 文件各自独立缓存
///
/// # 返回
///
/// 返回 `CaAuthInfo`，包含：
/// - `ca_uuid`: CA 的唯一标识（基于调用者路径生成的 UUID v5）
/// - `verified`: 验签是否通过（包含签名验证和证书链验证）
pub fn get_or_verify_ca() -> CaAuthInfo {
    // 获取当前进程 ID
    let pid = std::process::id() as i32;

    // 获取调用者可执行文件路径
    let ca_path = match std::fs::read_link("/proc/self/exe") {
        Ok(path) => path.to_string_lossy().to_string(),
        Err(_) => "<unknown>".to_string(),
    };

    // 生成 CA UUID（基于路径）
    let ca_uuid = path_to_uuid(&ca_path);

    if ca_path == "<unknown>" {
        warn!("CA path unknown, skipping verification");
        return CaAuthInfo {
            ca_uuid,
            verified: false,
        };
    }

    // 打开文件一次并持有文件描述符：缓存键（元数据）与验签内容均从同一
    // fd 读取，消除基于路径的 fs::metadata 与 fs::read 两次独立解析之间
    // 的 TOCTOU 窗口。此前攻击者可在窗口内替换文件，使
    // verified=true 的验签结果被缓存到另一个（恶意）文件的元数据键下，
    // 此后恶意文件换回原路径即可命中缓存绕过验签。
    let mut file = match fs::File::open(&ca_path) {
        Ok(f) => f,
        Err(e) => {
            warn!("无法打开CA文件 {}: {}", ca_path, e);
            return CaAuthInfo {
                ca_uuid,
                verified: false,
            };
        }
    };

    // 从同一文件描述符读取元数据，确保缓存键与验签内容一致
    let ca_file_id = match get_ca_file_id_from_file(&file) {
        Some(id) => id,
        None => {
            warn!("无法获取CA文件元数据: {}", ca_path);
            return CaAuthInfo {
                ca_uuid,
                verified: false,
            };
        }
    };

    // 构建缓存键
    let key = CacheKey { pid, ca_file_id };

    if let Some(result) = CA_AUTH_CACHE.get(&key) {
        debug!(
            "CA认证缓存命中: pid={}, inode={}",
            pid, key.ca_file_id.inode
        );
        return result.value().clone();
    }

    // 缓存未命中，执行验签（内容从同一 fd 读取）
    debug!("CA认证缓存未命中，执行验签: pid={}, path={}", pid, ca_path);
    let result = perform_ca_auth_internal(ca_uuid, &mut file);

    CA_AUTH_CACHE.insert(key, result.clone());

    result
}

/// 清除所有缓存（主要用于测试）
pub fn clear_cache() {
    CA_AUTH_CACHE.clear();
}

/// 内部认证函数：从已打开的文件句柄读取 ELF 内容并调用 tasign 验签
///
/// 内容与调用方缓存键的元数据来自同一文件描述符，保证验签结果与缓存键
/// 的一致性（防 TOCTOU）。
fn perform_ca_auth_internal(ca_uuid: String, file: &mut fs::File) -> CaAuthInfo {
    debug!("开始验证 CA ELF 签名");

    let mut elf_data = Vec::new();
    if let Err(e) = std::io::Read::read_to_end(file, &mut elf_data) {
        warn!("无法读取ELF文件: {}", e);
        return CaAuthInfo {
            ca_uuid,
            verified: false,
        };
    }

    let ca_pem = load_root_ca_cert();
    debug!("CA 根证书已加载（编译期嵌入）");

    let verified = match tasign::verify_elf_signature(&elf_data, Some(ca_pem)) {
        Ok(_) => {
            debug!("CA ELF 签名验证成功（含证书链验证）");
            true
        }
        Err(e) => {
            warn!("签名验证失败: {}", e);
            false
        }
    };

    CaAuthInfo { ca_uuid, verified }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CA 验签缓存测试

    #[test]
    fn test_ca_file_id_uniqueness() {
        // 测试 CaFileId 的比较逻辑
        let id1 = CaFileId {
            inode: 12345,
            mtime: 1000,
            mtime_nsec: 0,
            dev: 1,
        };

        let id2 = CaFileId {
            inode: 12345,
            mtime: 1000,
            mtime_nsec: 0,
            dev: 1,
        };

        let id3 = CaFileId {
            inode: 12345,
            mtime: 2000, // mtime不同
            mtime_nsec: 0,
            dev: 1,
        };

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_clear_cache() {
        let test_key = CacheKey {
            pid: 99999,
            ca_file_id: CaFileId {
                inode: 12345,
                mtime: 1000,
                mtime_nsec: 0,
                dev: 67890,
            },
        };

        let test_info = CaAuthInfo {
            ca_uuid: "test-uuid".to_string(),
            verified: true,
        };

        CA_AUTH_CACHE.insert(test_key.clone(), test_info);

        clear_cache();
        assert!(
            !CA_AUTH_CACHE.contains_key(&test_key),
            "cache should be cleared"
        );
    }

    #[test]
    fn test_get_or_verify_ca_returns_info() {
        clear_cache();
        let info = get_or_verify_ca();
        assert!(!info.ca_uuid.is_empty());
    }

    #[test]
    fn test_get_or_verify_ca_caches_result() {
        clear_cache();
        let info1 = get_or_verify_ca();
        let info2 = get_or_verify_ca();
        assert_eq!(info1.ca_uuid, info2.ca_uuid);
        assert_eq!(info1.verified, info2.verified);
        clear_cache();
    }

    #[test]
    fn test_perform_ca_auth_internal_current_exe() {
        let exe_path = std::fs::read_link("/proc/self/exe")
            .unwrap()
            .to_string_lossy()
            .to_string();
        let mut file = fs::File::open(&exe_path).unwrap();
        let result = perform_ca_auth_internal("test-uuid".to_string(), &mut file);
        assert_eq!(result.ca_uuid, "test-uuid");
    }

    #[test]
    fn test_perform_ca_auth_internal_empty_content_unverified() {
        // 空内容无法通过 ELF 签名验证：必须 fail-closed（verified=false）
        let dir = std::env::temp_dir();
        let path = dir.join("rust-libteec-ca-auth-empty-test.bin");
        std::fs::write(&path, b"").unwrap();
        let mut file = fs::File::open(&path).unwrap();
        let result = perform_ca_auth_internal("test-uuid".to_string(), &mut file);
        assert_eq!(result.ca_uuid, "test-uuid");
        assert!(!result.verified);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_get_ca_file_id_from_file_current_exe() {
        let exe_path = std::fs::read_link("/proc/self/exe")
            .unwrap()
            .to_string_lossy()
            .to_string();
        let file = fs::File::open(&exe_path).unwrap();
        let file_id = get_ca_file_id_from_file(&file);
        assert!(file_id.is_some());
        let id = file_id.unwrap();
        assert!(id.inode > 0);
    }

    #[test]
    fn test_cache_key_and_content_from_same_fd() {
        // 缓存键元数据与验签内容均来自同一文件描述符。
        // 即使打开后路径上的文件被替换（新 inode），
        // fd 的元数据保持不变，且从 fd 读取的内容仍是打开时实例的内容，
        // 攻击者无法使 verified 结果与缓存键指向不同文件。
        let dir = std::env::temp_dir();
        let path = dir.join("rust-libteec-ca-auth-toctou-test.bin");
        let new_path = dir.join("rust-libteec-ca-auth-toctou-test-new.bin");
        std::fs::write(&path, b"original").unwrap();

        let mut file = fs::File::open(&path).unwrap();
        let id1 = get_ca_file_id_from_file(&file).unwrap();

        // 模拟攻击者在 metadata 读取与内容读取之间替换路径上的文件
        std::fs::write(&new_path, b"replaced").unwrap();
        std::fs::rename(&new_path, &path).unwrap();

        // fd 元数据不受路径替换影响（同一 inode）
        let id2 = get_ca_file_id_from_file(&file).unwrap();
        assert_eq!(id1, id2, "fd 元数据必须与打开时的文件实例一致");

        // fd 读取的内容仍是打开时的实例，而非替换后的文件
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut data).unwrap();
        assert_eq!(data, b"original", "fd 内容必须来自打开时的文件实例");

        std::fs::remove_file(&path).unwrap();
    }
}
