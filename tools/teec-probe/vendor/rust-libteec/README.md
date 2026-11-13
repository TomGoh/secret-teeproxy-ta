# rust-libteec

[![Crates.io](https://img.shields.io/crates/v/rust-libteec.svg)](https://crates.io/crates/rust-libteec)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## 介绍

基于 GlobalPlatform TEE Client API 规范的 TEE (Trusted Execution Environment) 客户端库的 Rust 实现。该库提供与可信执行环境中的可信应用 (TA) 通信的接口，支持通过机密通信通道（TLS + VSOCK）进行安全数据传输。

## 主要特性

- **完整的 TEEC API 实现**: 支持上下文管理、会话管理、命令调用等所有标准 API
- **机密通信**: 基于 SM2 ECDH 密钥协商 + TLS 动态 PSK 的加密通信通道（SM4-GCM），CA 与 TA 之间的所有数据都通过此通道传输，每次连接使用独立密钥，具备前向安全性
- **纯 Rust 国密栈**: 密码学原语基于 `tee_crypto` crate（RustCrypto 生态纯 Rust 实现），在 `xtee-psk` 子 crate 中提供纯 Rust 封装的 SM2 ECDH / HKDF-SM3 / SM2 签名验签接口；TLS 加密通道则直接使用 `mbedtls-smx` 国密库
- **共享内存管理**: 管理 MEMREF 类型参数的本地缓冲区（数据通过网络序列化传输）
- **CA 认证**: 自动验证客户端应用的签名和证书链，为 TA 提供 ACL 访问控制信息
- **多参数类型支持**: VALUE、MEMREF（INPUT/OUTPUT/INOUT）、PARTIAL MEMREF 等
- **线程安全**: 使用 DashMap 实现并发安全的缓存和上下文管理

## 机密通信流程

网络架构上，CA 和 TA 之间通过 VSOCK（虚拟机套接字）通信，数据经由 TLS（SM4-GCM）加密传输。

```
  CA (Client)                           TA (Server)
     |                                      |
     |  ─── VSOCK 连接 ─────────────────────→  |
     |                                      |
     |  ─── ECDH 公钥交换 ─────────────────→  |  SM2P256R1 密钥协商
     |  ←── ECDH 公钥交换 + 签名 ────────────  |  长期密钥签名
     |                                      |
     |      HKDF-SM3(shared_secret)         |  派生 32 字节动态 PSK
     |                                      |
     |  ─── TLS PSK 握手 ─────────────────→  |  ECDHE-PSK-SM4-GCM-SM3
     |  ←── TLS PSK 握手 ──────────────────  |
     |                                      |
     |  ─── 加密通信（SM4-GCM）────────────→  |  机密数据传输
     |  ←── 加密通信（SM4-GCM）─────────────  |
```

每次连接流程：

1. **VSOCK 连接** — CA 通过 VSOCK 与 TA（由 vsock-manager 代理）建立 TCP-like 连接
2. **ECDH 密钥协商** — 双方生成临时 SM2P256R1 密钥对，交换公钥，服务端使用长期密钥签名，客户端通过 TOFU 模式校验服务端身份
3. **动态 PSK 派生** — 双方各自使用 HKDF-SM3 从共享秘密派生出相同的 32 字节 PSK（共享秘密离开作用域时自动清零）
4. **TLS PSK 握手** — 使用 ECDHE-PSK-SM4-GCM-SM3 密码套件完成 TLS 握手
5. **加密通信** — 后续所有数据通过 SM4-GCM 加密传输

每次连接独立生成临时密钥对，即使某次 PSK 泄露也不影响历史通信（前向安全性）。

## 主要常量

所有密码学常量集中定义在 `xtee-psk/src/constants.rs`，保持单一数据源：

| 常量 | 值 | 说明 |
|------|----|------|
| `SM2_COORDINATE_LEN` | 32 | SM2 坐标分量长度（字节） |
| `SM2_PUBLIC_KEY_LEN` | 64 | SM2 公钥长度（x\|\|y） |
| `SM2_POINT_LEN` | 65 | 未压缩 EC 点长度（0x04\|\|x\|\|y） |
| `PSK_LEN` | 32 | PSK 密钥长度 |
| `MAX_SIG_LEN` | 256 | 签名最大长度 |

常量间存在派生关系：`SM2_PUBLIC_KEY_LEN = SM2_COORDINATE_LEN * 2`，`PSK_LEN = SM2_COORDINATE_LEN`。

## 软件架构

```
rust-libteec/
├── src/
│   ├── cc_client/          # 机密通信客户端模块
│   │   ├── client.rs       # TLS + VSOCK 客户端实现
│   │   ├── tofu.rs         # 服务端身份 TOFU 校验
│   │   └── vsock_define.rs # VSOCK 配置
│   ├── teec/               # TEEC API 实现模块
│   │   ├── c_api.rs        # C API FFI 薄包装层（TEEC_* 函数入口）
│   │   ├── ca_auth.rs      # CA 认证和缓存管理
│   │   ├── context.rs      # TEE 上下文生命周期管理
│   │   ├── mod.rs          # 模块声明与重导出
│   │   ├── operation.rs    # 操作参数处理
│   │   ├── safe_ptr.rs     # 安全指针操作封装
│   │   ├── session.rs      # 会话管理（含机密通信通道）
│   │   ├── shared_memory.rs# 共享内存管理
│   │   ├── vmem.rs         # CA 地址空间区间校验（纵深防御）
│   │   └── fuzz_api.rs     # fuzz feature 下的内部转发层（产品构建不编译）
│   ├── error.rs            # 错误类型定义
│   ├── lib.rs              # 库入口
│   └── teec_trace.rs       # 日志跟踪
├── certs/                  # CA 根证书
│   └── kylin-xtee-ca-sign-root.pem  # 证书链（麒麟软件根证书 Kylin Software Root Cert + 其签发的 Kylin Software Applications Cert），编译期嵌入用于校验 TA 签名
├── xtee-psk/               # PSK 协商密码学原语（子 crate）
│   └── src/
│       ├── lib.rs          # 模块声明 + 公共 API 重导出
│       ├── constants.rs    # 协议常量（SM2 点长度、PSK 长度等）
│       ├── error.rs        # PskError 错误类型 + PskResult 别名
│       ├── keygen.rs       # 随机数生成器 + ECDH/DSA 密钥对生成
│       ├── ec_point.rs     # SEC1 未压缩点 → SM2 公钥点解析 / 公钥点提取
│       ├── ecdh.rs         # ECDH 共享秘密 + HKDF-SM3 PSK 派生
│       ├── sign.rs         # SM2 DSA 签名/验签（防 MITM）
│       ├── protocol.rs     # 协议帧构建/解析（EcdhResponse）
│       ├── negotiate.rs    # PskTransport trait + 协商主流程 + ServerPskContext
│       └── virga_transport.rs # virga VSOCK 传输层 PskTransport 实现
├── teec-api-types/         # TEE API 类型定义（子 crate）
├── teec-protocol/          # 通信协议定义（子 crate）
├── examples/               # Rust 示例程序
├── c-examples/             # C 语言示例程序
└── tests/                  # 集成测试
```

### xtee-psk crate

密码学原语库，基于 `tee_crypto` crate 封装国密接口，通过 `PskTransport` trait
将网络 I/O（send/recv）与密码学协商逻辑解耦，供客户端和服务端各自实现传输层并调用
统一的 `server_ecdh_negotiate` / `client_ecdh_negotiate` 协商函数。

各功能分散在独立子模块中，`lib.rs` 仅负责模块声明和公共 API 重导出：

| 模块 | 职责 |
|---|---|
| [`constants`](xtee-psk/src/constants.rs) | 协议常量（点长度、签名字段大小、PSK 长度等） |
| [`error`](xtee-psk/src/error.rs) | `PskError` 错误类型和 `PskResult` 别名 |
| [`keygen`](xtee-psk/src/keygen.rs) | 随机数生成器创建、ECDH/DSA 密钥对生成 |
| [`ec_point`](xtee-psk/src/ec_point.rs) | SEC1 未压缩点解析为 `Sm2PublicPoint`、从密钥对提取 SEC1 公钥点 |
| [`ecdh`](xtee-psk/src/ecdh.rs) | ECDH 共享秘密计算 + HKDF-SM3 PSK 派生 |
| [`sign`](xtee-psk/src/sign.rs) | SM2 DSA 签名/验签（防 MITM） |
| [`protocol`](xtee-psk/src/protocol.rs) | 协议帧构建/解析（`EcdhResponse`） |
| [`negotiate`](xtee-psk/src/negotiate.rs) | `PskTransport` trait + 协商主流程 + `ServerPskContext` |
| [`virga_transport`](xtee-psk/src/virga_transport.rs) | virga VSOCK 传输层的 `PskTransport` 实现 |

核心功能列表：

- **命名常量**: `SM2_COORDINATE_LEN`、`SM2_PUBLIC_KEY_LEN`、`SM2_POINT_LEN`、`PSK_LEN`、`MAX_SIG_LEN`
- **SM2 密钥对生成**: `generate_ecdh_keypair`（ECDH 密钥交换）、`generate_dsa_keypair`（数字签名）
- **ECDH 共享秘密**: `ecdh_compute_shared`（对 `ecc_shared_secret` 返回的 32 字节 x 坐标再做一次 SM3，返回 `Zeroizing`，离开作用域自动清零）
- **HKDF-SM3 密钥派生**: `derive_psk`（从 ECDH 共享秘密派生 32 字节 PSK）
- **SM2 签名/验签**: `sign_ecdh_exchange` / `verify_ecdh_signature`（服务端身份认证）
- **协议消息**: `build_ecdh_response` / `parse_ecdh_response`（ECDH 协商消息序列化）
- **服务端上下文**: `ServerPskContext`（封装长期 DSA 密钥及协商入口 `negotiate`，跨连接复用）
- **随机数生成器**: `CryptoRng`（StdRng aliased）

### 客户端 tofu.rs

基于 TOFU（Trust On First Use，首次使用时信任）模型的服务端身份校验：
首次连接信任并缓存服务端长期公钥，后续连接校验一致性。若公钥发生变化，
视为服务端重启导致的合法密钥轮换：以 warn 级别告警并重新记录新公钥后接受连接
（可更新 TOFU；严格模式下的拒绝路径可由调用方恢复）。

- `verify_server_identity` — TOFU 身份校验入口

## 安装教程

### 系统要求

- **Rust 1.85 或更高版本**（edition 2024）
- Linux 操作系统（支持 VSOCK）
- GCC（用于编译 C 示例）
- clang
- **CMake 3.16 或更高版本**（Android 交叉编译建议 3.22+）

> **CMake 版本说明**：rust-mbedtls 依赖的 mbedtls-sys 通过 CMake 构建 MbedTLS 库。低版本 CMake 会导致编译失败：
> - CMake < 3.13：Rust `cmake` crate 的 `-B` 构建目录参数不可用
> - CMake < 3.16：Android 交叉编译时 `CMAKE_TOOLCHAIN_FILE` 与 NDK 工具链文件配合不完善
> - CMake < 3.22：NDK r25+ 的 `android.toolchain.cmake` 可能无法正常工作
>
> 可通过 `cmake --version` 检查当前版本，如需升级请参考 [CMake 官方下载页](https://cmake.org/download/)。

### Linux 构建

```bash
# 构建发布版本
cargo build --release

# 或使用 Makefile
make build
```

### Android 16 交叉编译

使用 NDK r29 和 `cargo-ndk` 交叉编译 aarch64 目标：

1. **下载 Android NDK r29**：
   ```bash
   # 从 Android 官方下载
   wget https://dl.google.com/android/repository/android-ndk-r29-linux.zip
   unzip android-ndk-r29-linux.zip
   ```
   或通过 Android Studio 的 SDK Manager 安装，NDK 位于 `~/Android/Sdk/ndk/29.x.x/`。

2. **安装 cargo-ndk**：
   ```bash
   cargo install cargo-ndk
   ```

3. **设置 NDK 环境变量**：
   ```bash
   export ANDROID_NDK_HOME=/path/to/android-ndk-r29
   ```

4. **编译**：
   ```bash
   cargo ndk --platform 35 build --release --target arm64-v8a
   ```

   - `--platform 35`：对应 Android 16 (API level 35)
   - `--target arm64-v8a`：aarch64 目标架构
   - 编译产物位于 `target/aarch64-linux-android/release/libcc_teec.so`

5. **AOSP 预编译部署**：

   将 `libcc_teec.so` 复制到 AOSP 源码树的预编译目录下，并编写对应的 `Android.bp`：

   ```bp
   cc_prebuilt_library_shared {
       name: "libcc_teec",
       srcs: ["libcc_teec.so"],
       compile_multilib: "64",
       shared_libs: ["libc", "libdl"],
       vendor: true,
   }
   ```

   然后在产品的 `device.mk` 中添加：
   ```makefile
   PRODUCT_PACKAGES += libcc_teec
   ```

   编译 AOSP 后 `libcc_teec.so` 安装到设备 `/vendor/lib64/`。

6. **编译 C 示例（Android）**：

   编译 `libcc_teec.so` 后，可以直接编译并签名 C 示例：
   ```bash
   make android-c-examples
   ```

   或单独操作：
   ```bash
   # 仅编译 C 示例（不签名）
   make -C c-examples android

   # 编译 + 签名
   make -C c-examples android-sign
   ```

   签名后的 C 示例二进制部署到 AOSP 时，编写对应的 `Android.bp`：
   ```bp
   cc_prebuilt_binary {
       name: "cc-teec",
       srcs: ["cc-teec"],
       vendor: true,
       strip: {
           none: true,
       },
       shared_libs: ["libcc_teec", "libc", "libdl"],
   }
   ```

   > `strip: { none: true }` 用于保留 `.ta_signature` ELF 段，AOSP 默认 strip 会移除该段。

   然后在产品的 `device.mk` 中添加：
   ```makefile
   PRODUCT_PACKAGES += cc-teec
   ```

### 安装到系统（Linux，可选）

```bash
sudo make install
```

## 使用说明

### Rust 项目中使用

在 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
rust-libteec = "0.5"
```

基本使用示例请参考 [examples/cc-teec.rs](examples/cc-teec.rs)，对应的 TA 示例位于 [xtee-rust-sdk-fuxi/examples/param](https://gitee.com/openkylin/xtee-rust-sdk-fuxi/tree/master/examples/param)（UUID: `9b28392f-39d2-497d-91af-b6600e3d6a3e`）。

### 运行示例

```bash
# 运行 Rust 示例
cargo run --release --example cc-teec

# 编译并运行 C 示例（默认嵌入生产根证书）
make test-c-examples
```

> C 示例（`cc-teec`、`kybox-test`、`kyde-test`）默认用 tasign 内置 **TEST 证书** 签名；
> 客户端库默认编译期嵌入 **生产根证书**（`certs/kylin-xtee-ca-sign-root.pem`）。
> 二者不匹配时，运行时验签会打印
> `签名验证失败: ... certificate chain verify failed: chain build failed`，
> 这是证书不匹配，不是验签实现缺陷。

#### 测试证书签名验证

用 **TEST 根证书** 构建库，使 TEST 签名的 C 示例能通过证书链验证：

```bash
RUST_LOG=DEBUG make test-c-examples CARGO_FEATURES=test-root-ca
```

成功时日志出现 `CA ELF 签名验证成功（含证书链验证）`；不用该 feature 时则为
`签名验证失败: ... chain build failed`。

也可单独用 tasign-tool 验证已签名 ELF：

```bash
tasign-tool verify-elf --elf c-examples/cc-teec --ca-cert TEST
```

#### 生产证书签名验证

用生产证书签名 C 示例，再用默认（生产根证书）构建的库验证：

```bash
# 1) 用生产证书签名 C 示例（leaf/key/中间证书按实际证书填写）
make -C c-examples all \
  KYCA_LEAF_CERT=/path/leaf.pem \
  KYCA_LEAF_KEY=/path/leaf.key \
  KYCA_LEAF_KEY_PASS=password \
  KYCA_INTERMEDIATE_CERT=/path/intermediate.pem

# 2) 默认（生产根证书）构建库并运行
RUST_LOG=DEBUG make test-c-examples
```

验签对象是发起会话的 CA 可执行文件自身的 ELF 签名（`.ta_signature` 段），
结果以 `CaAuthInfo.verified` 随 OpenSession 交给 TA 做 ACL 决策——客户端库
不做 fail-closed，是否放行由 TA 的 ACL 决定。`test-root-ca` 仅用于开发调试，
生产构建保持默认（嵌入生产根证书）。

### 运行测试

```bash
# 运行单元测试
make test

# 运行覆盖率测试
make coverage
```

## 特性标志

- `ca-sign-verify`: 启用 CA 认证功能，包含签名验证与证书链验证（默认启用）。依赖 `tasign` crate
- `test-root-ca`: 启用 tasign 内置测试根证书（开发调试用）。默认不启用，编译期嵌入 `certs/kylin-xtee-ca-sign-root.pem`（麒麟软件根证书及其下级 CA 组成的证书链，用于校验 TA 签名；x-kernel 侧须使用同一份证书链）。依赖 `ca-sign-verify`
- `debug_level_0` ~ `debug_level_4`: 控制日志详细程度（默认 level_2）

## 参与贡献

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 许可证

本项目采用 Apache License 2.0 许可证 - 详见 [LICENSE](LICENSE) 文件

## 联系方式

- 项目主页: https://gitee.com/openkylin/rust-libteec
- 问题反馈: https://gitee.com/openkylin/rust-libteec/issues


## TLS ciphertext tampering regression

The default build has no injection API. The optional `attack-test` feature exposes
`attack_test::AttackTestCcClient`, a separate client that shares production
VSOCK, ECDH, TOFU and TLS configuration. Enabling the feature does not alter
ordinary TEEC clients or install global hooks. Injection is disabled until the
caller explicitly arms one application-data record. The adapter flips one bit
in TLS 1.2 GCM ciphertext, preserving the record header, explicit nonce and tag.
It tracks actual injections and retains the typed `SslInvalidMac` failure so
transport errors, EOF and timeouts cannot satisfy the regression assertion.

```bash
cargo test --manifest-path Cargo.toml --features attack-test tampering -- --nocapture
```

`make test-attack` runs the same suite through the repository Makefile, and
`make check` includes that target so the regression tests are not skipped by
the default `cargo test` run.

These tests include fragmented raw reads and real TLS 1.2 SM4-GCM over a local
TCP connection. The SDK-owned `tests/ta-runtime/cases/tls_tamper_detect` case
adds normal TEEC and VSOCK guest controls. After a corrupted connection, callers
must close any known TA session through a fresh connection; closing TLS alone
is not a TA CloseSession. This feature is test infrastructure, not a production
fault-injection setting.
