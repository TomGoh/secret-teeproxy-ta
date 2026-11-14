# secret-teeproxy-ta

灵触→灵润→DeepSeek密钥保护MVP的TA与可复用进程内CA实现。TA使用xkernel的GP持久对象保存凭证，通过LSP/1接收请求，在TA内填充提供商认证并完成上游TLS。Android负责传递加密记录和交付解密后的HTTP响应。

## 当前入口

1. [当前提供商、并发与传输设计](docs/provider-expansion-v0.6.md)
2. [当前扩展需求](docs/requirements-provider-expansion-v0.6.md)
3. [当前验收矩阵](docs/provider-expansion-acceptance-v0.6.md)
4. [CA—TA协议](docs/contracts/ca-ta-protocol-v1-draft.md)、[注册表](docs/contracts/lsp-v1-contract-registry.json)、[schema](docs/contracts/lsp-v1-metadata.schema.json)、[当前运行配置](docs/contracts/lsp-provider-profile-v0.6.json)
5. [备用CA的Java/JNI、配置与测试入口](tools/teec-probe/README.md)
6. [实现与设备验收交接](docs/IMPLEMENTATION-HANDOFF-20261113.md)

当前默认支持四个活跃请求、八个GP会话和64MiB总上传预留量，每请求最大32MiB。CA在灵润APK进程内执行。TA保存Key并处理认证与上游TLS，保护路径的失败向上层交付明确错误。

`docs/contracts`为工作区规范的字节一致交接快照，SHA256见CONTRACT.lock.json。当前使用v0.6运行配置，CID从实际VM身份取得。初始HELLO输入上限16KiB，协商bulk_input_frames后输入上限61440B，回复上限32768B。v0.5文档保留最初MVP的历史配置。

## 实现

- `src/wire.rs`校验帧、参数、身份、序号和元数据。
- `src/store.rs`实现凭证版本、CAS、幂等收据、临时TTL与撤销。
- `src/gp.rs`管理GP双槽持久对象与初始化锚点，所有GP调用归属于存储工作线程。
- `src/http.rs`处理HTTP头、Content-Length、chunked与完整结束。
- `src/relay.rs`管理有界TLS/HTTP处理、流控、取消和终态快照。
- `src/app.rs`实现LSP状态机、请求准入、上传、租约与管理操作。
- `tools/teec-probe`提供复用同一网络泵的测试CLI和APK内Rust/C/Java库。

TA UUID为 `c86d23b9-e568-509e-a9b2-0ad40668caf5`。CMD_EXCHANGE为 `0x1000`，GP参数类型为 `0x0265`。管理端口为10099，CID由实际VM运行结果提供。HELLO返回当前并发上限4、会话上限8及缓冲界限。

## 构建

宿主机逻辑测试采用Rust 1.95与本仓库Cargo.lock。

```sh
cargo test --locked
```

在AArch64构建机安装musl工具链及Rust的 `aarch64-unknown-linux-musl` target后构建TA。

```sh
export CARGO_BUILD_JOBS=2
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
export CC_aarch64_unknown_linux_musl=musl-gcc
cargo build --locked --release --features tee --target aarch64-unknown-linux-musl
```

生成的ELF需要使用xkernel兼容的tasign流程签名，安装文件名为 `<TA_UUID>.ta`。开发签名和部署的可复现记录位于总工作区 `artifacts/ta-implementation-20261113/`。Android原生库的构建与打包说明见备用CA文档。

## 首次存储初始化

在持久卷和 GP 存储视图就位后、服务 TA 取得存储锚点前，使用已签名的 TA 执行以下一次性入口。

```sh
/tee/ta/c86d23b9-e568-509e-a9b2-0ad40668caf5.ta --ensure-vault-initialized
```

新空存储与合法 BOOTSTRAP 初始化完成后输出 `LSP_VAULT_READY result=INITIALIZED`。已有 READY 状态经过完整校验后输出 `LSP_VAULT_READY result=ALREADY_READY`。成功退出码为0，损坏、异常对象或存储所有权冲突返回1。现有 `--initialize-vault` 入口用于明确的新存储初始化，遇到 READY 状态会拒绝。

对应回归位于 `tests/gp_firstboot.rs`，直接执行 GP 适配器并注入对象API，覆盖部分初始化恢复、已有凭据读取、写入失败与锚点所有权冲突。2026-11-14的73项宿主机回归和首次空盘实际TEEC记录位于总工作区 `artifacts/iso-integration-20261114/ta-firstboot/` 与 `vm-preflight/`。

## 设备验证

2026-11-13，`.18`与`.19`的独立protected调试VM已部署同一签名TA，保留现有kernel.bin。实际teec凭证管理、准入BUSY、上传偏移、取消、终态处理、DeepSeek官方 `/models` HTTP 200和Chat Completions SSE已通过。`.19`已通过保留instance/data的VM重启后凭证引用调用。普通测试APK的应用UID10121也已通过进程内JNI→teec→TA→DeepSeek的MODELS与SSE调用。

2026-11-13晚间，`.19`整合APK已通过灵触实际圈选、摘要、理解、翻译、润色结果展示和复制的五动作验证。最终大帧CA/TA与manager空闲回收组合已完成容量、性能、异常退出恢复与两设备六动作复测。当前设备结果和精确源码/产物身份集中在总工作区 `artifacts/provider-expansion-20261113/`，详细验收状态随交付记录更新。

详细合同中的调查证据链接指向总工作区。真实Key、签名私钥、用户数据和设备镜像保存在各自受限位置，交接包按代码、合同、公共测试产物的明确清单生成。
