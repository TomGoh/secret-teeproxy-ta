# rust-libteec fuzz targets

基于 [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) 的模糊测试套件，
面向 `rust-libteec` 及其子 crate（`teec-protocol`、`xtee-psk`）中不依赖真实
TEE 设备的纯 Rust 核心逻辑：通信协议数据面、错误码映射、UUID 布局转换、
参数编解码、操作验证、日志格式化、vsock 配置与 PSK 协商协议，以及
C FFI 入口、共享内存管理、操作参数读写回、地址空间校验与 CA 签名认证。

## Layout（对齐 Wfuzz 测试规范 rust 节 / x-kernel 布局）

```
fuzz/
├── wfuzz.json                 # WFUZZ 项目配置（fuzz 目录即测试根目录，module_root 为 .）
├── fuzz_build.sh              # WFUZZ 本地构建脚本（nightly 工具链）
├── extract_entrypoints_list.py
├── Cargo.toml
├── fuzz_targets/              # 15 个独立入口点
├── .cargo/config.toml         # Kylin 内网 crates.io 镜像（容器内构建使用）
├── corpus/ artifacts/         # cargo-fuzz 本地运行产物（gitignored）
└── entrypoints.json entrypoints_list.txt   # fuzz_build.sh 生成产物（gitignored）
```

- `wfuzz.json` 与 `fuzz_targets/` 均位于 `fuzz/` 内，测试时以 `wfuzz.json`
  所在目录为测试根目录，`module_root` 为 `.`；
- 每个 fuzz target 为独立入口点，可用 `WFUZZ_TEST_ENTRYPOINT=<target>` 单独测试；
- 输入处理遵循规范的"模糊测试特殊输入处理规范"：fuzz target 只消费 `&[u8]`，
  用 `Unstructured` 按固定顺序构造结构化输入，所有取值以 `unwrap_or` 兜底，
  保证输入不足时 target 自身不 panic；无全局状态、无额外 I/O，保持确定性。

## `fuzz` feature（仅模糊测试启用，产品构建不带）

`fuzz/Cargo.toml` 以 `rust-libteec = { path = "..", features = ["fuzz"] }` 引入被测库，
该 feature 在 `src/lib.rs` 中多暴露一个 `fuzz` 模块，其余成员均来自
`src/teec/fuzz_api.rs`（`#[cfg(feature = "fuzz")]`）与 `src/teec/vmem.rs` 的
`check_range_in_maps_for_fuzz`：

- 存在的理由：fuzz target 只可见 crate 的公开面，而大多数健壮性逻辑位于
  `pub(crate)`/`pub(super)`；若在 target 里复刻这些逻辑，测到的是复刻品而不是产品实现；
- 边界：这些转发函数**只做类型转换与转发**，不复制产品逻辑、不参与非 fuzz 构建；
  唯一新增的产品侧代码是 `vmem` 的一个薄包装（真实函数仍是私有的 `check_range_in_maps`）；
- 产品构建（`Makefile`、`debian/build.sh` 的 `cargo build --release --lib`）不带该
  feature，因此 C ABI 与导出符号集完全不变，可用
  `nm -D --defined-only target/release/libcc_teec.so | grep -c TEEC_` 复核（应为 10）。

## 一次性安装

```bash
# 需要 nightly 工具链（libFuzzer 依赖 sanitizer，仅 nightly 可用）
rustup install nightly
cargo install cargo-fuzz
```

## 运行

```bash
cd fuzz

# 列出所有 fuzz target
cargo +nightly fuzz list

# 运行单个 target（Ctrl-C 停止；崩溃语料写入 fuzz/artifacts/<target>/）
cargo +nightly fuzz run fuzz_tee_request
cargo +nightly fuzz run fuzz_tee_response
cargo +nightly fuzz run fuzz_packet_header
cargo +nightly fuzz run fuzz_uuid
cargo +nightly fuzz run fuzz_error_code
cargo +nightly fuzz run fuzz_param_codec
cargo +nightly fuzz run fuzz_operation_validate
cargo +nightly fuzz run fuzz_teec_trace
cargo +nightly fuzz run fuzz_config
cargo +nightly fuzz run fuzz_shared_memory
cargo +nightly fuzz run fuzz_operation_params
cargo +nightly fuzz run fuzz_c_api
cargo +nightly fuzz run fuzz_vmem
cargo +nightly fuzz run fuzz_psk_negotiate
cargo +nightly fuzz run fuzz_ca_auth

# 限定运行时长（秒）和最大输入大小
cargo +nightly fuzz run fuzz_tee_response -- -max_total_time=60 -max_len=4096

# 多核并行
cargo +nightly fuzz run fuzz_tee_request -- -jobs=8 -workers=8
```

## WFUZZ 平台构建

在 Wfuzz 平台（v11-2603 容器，ubuntu 用户）上，需要用 WFUZZ SDK 生成入口点
清单并合并回 `fuzz/wfuzz.json`。参考 Wfuzz 测试规范 rust 节：

```bash
cd /code/fuzz            # wfuzz.json 所在目录 = 测试根目录
source ~/.bashrc         # wfuzz 在 PATH 中（SDK 安装后）
./fuzz_build.sh
```

`fuzz_build.sh` 的构建阶段等价于依次执行：

```bash
export RUSTUP_TOOLCHAIN=nightly
export __CARGO_TEMPORARY_BUILD_DIR_NEW_LAYOUT_OPT_OUT=1

wfuzz build --output-entrypoints entrypoints.json
wfuzz entrypoints-merge -w wfuzz.json -e entrypoints.json
python3 extract_entrypoints_list.py wfuzz.json entrypoints_list.txt
cat entrypoints_list.txt
```

构建完成后，`fuzz_build.sh` 自动循环读取 `entrypoints_list.txt`，为每个入口点在
**后台并行**启动模糊测试（日志写入 `wfuzz-test-<name>.log`，均可独立查看失败原因）：

```text
==> launching fuzzing for all entrypoints in background
  [10:00:01] fuzz_tee_request -> wfuzz-test-fuzz_tee_request.log
  [10:00:01] fuzz_config      -> wfuzz-test-fuzz_config.log
==> waiting for 9 background fuzz job(s) to finish
  fuzz_tee_request: OK
  fuzz_config: FAILED (see wfuzz-test-fuzz_config.log)
```

所有入口点并行执行（互不等待），任一口失败脚本以非零退出码结束并指出对应日志；
也可按规范手动逐个测试（无需重新编译）：

```bash
WFUZZ_TEST_ENTRYPOINT=fuzz_tee_request wfuzz fuzz
WFUZZ_TEST_ENTRYPOINT=fuzz_config wfuzz fuzz
# …其余入口点同理
```

构建/测试产物（均已 gitignore）：`entrypoints.json`、`entrypoints_list.txt`、
`wfuzz-fuzz-targets/`、`wfuzz-test-*`。

## Fuzz target 一览

| Target                   | 目标代码                                        | 检验属性 |
|--------------------------|-------------------------------------------------|----------|
| `fuzz_tee_request`       | `teec_protocol::TEE_Request` postcard 编解码    | 全变体 × 参数类型 × CA 认证信息 round-trip 字节稳定；任意请求流反序列化不 panic |
| `fuzz_tee_response`      | `teec_protocol::TEE_Response` 反序列化（响应路径） | 任意响应字节流不 panic；成功解析结果 round-trip 一致 |
| `fuzz_packet_header`     | `teec_protocol::PacketHeader` 解析 + `PacketType` 转换 | 16 字节协议头字节级 round-trip；类型双向转换一致 |
| `fuzz_uuid`              | `teec::uuid_to_string` 布局转换（fuzz feature 实际函数） | 任意 16 字节构造的 UUID 转换不 panic 且与标准解析一致 |
| `fuzz_error_code`        | `error::{ErrorKind, ErrorOrigin}` 错误码映射    | 任意 u32 错误码转换/格式化不 panic；已注册码往返一致 |
| `fuzz_param_codec`       | `TEE_ParamType::from(u32)` + `TEEC_PARAM_TYPES` 编解码 | 参数类型转换正确；编码→解码 round-trip 一致；高 16 bit 为零 |
| `fuzz_operation_validate`| 共享内存标志验证（复刻）+ `build_parameters_from_operation`（实际函数） | 共享内存标志验证安全；12+ match 分支的参数构建路径；垃圾 `memref.parent` 指针按登记表拒绝；空指针返回错误 |
| `fuzz_teec_trace`        | `rust_dprintf` + `dump_buffer` 日志格式化       | 任意 C 字符串/缓冲区不 panic；无效 UTF-8 返回 -1；空指针安全返回 |
| `fuzz_config`            | `xtee-psk` 协商协议 + vsock 配置（`parse_or_default` 为复刻逻辑） | identity 确定性；ECDH 响应帧任意输入不 panic、build→parse round-trip；derive_psk 确定性；VSOCK 解析不 panic |
| `fuzz_shared_memory`     | `SharedMemoryManager` 分配/注册/读写/回收（实际函数，经 `fuzz` feature 转发） | 未注册句柄恒拒绝；越界 offset/size 恒拒绝；影子副本逐字节一致；重复释放幂等；`release_by_context` 只回收该上下文；`size` 大于登记长度时拒绝 |
| `fuzz_operation_params`  | `OperationParams` 访问器 + `build/update_operation_from_parameters`（实际函数） | 越界槽位恒拒绝；tmpref 写回按声明长度截断且不改动超出部分；memref 读回与登记表一致；TT 应答写回「只减不增」；未支持参数类型恒拒绝。**刻意不覆盖**「tmpref 声明长度 > 真实缓冲长度」：target 把声明长度钳制在真实长度内，该场景按 TMPREF 安全契约属 CA 违约（见 `src/teec/c_api.rs` 的 OpenSession/InvokeCommand 说明），纳入会得到 ASAN 堆越界假阳性 |
| `fuzz_c_api`             | 10 个 `TEEC_*` C FFI 入口（实际函数，经 `fuzz_api::ffi_*` 转发；`TEEC_InitializeContext` **仅校验空指针/未登记路径**，避免向 CID 103:9999 发起真实 vsock 连接） | 空指针/空出参 → 精确错误码且 `ret_origin` 回写为合法变体；伪造 ctx/session 不污染登记表；未连接会话不得解引用空上下文；共享内存 FFI 分配/注册→读回→释放端到端一致 |
| `fuzz_vmem`              | `vmem::check_range_in_maps` / `range_readable` / `range_writable`（实际函数 + fuzz hook） | 单行 maps 文本独立 oracle 逐案比对；跨 VMA/表外/畸形行恒判不可用；真实堆可读写、`.text` 可读不可写；指针区间溢出恒拒绝 |
| `fuzz_psk_negotiate`     | `client_ecdh_negotiate` / `server_ecdh_negotiate` + `sign`/`ec_point`/`ecdh`/`keygen`/`protocol`/`error`（实际函数，脚本化传输；另直接调用 `ecdh_compute_shared` + `derive_psk`） | 诚实协商两侧 PSK 与身份标识一致且非全零；篡改/截断/无响应恒失败（不得「验签失败仍派生 PSK」）；帧长与 SEC1 前缀不变式；直接调 `ecdh_compute_shared` 时任何失败恒为 `InvalidPoint`（对端输入非法不得兜底成 `InternalError`），成功时共享秘密恰为 32 字节 SM3 输出；OS 熵源必须可用 |
| `fuzz_ca_auth`           | `get_or_verify_ca` + `clear_cache` | 未签名可执行文件下 `verified` 恒为 false（**标志层** fail-closed：CA 侧对验证失败只 warn 不阻断，会话级强制点在 TA 侧命令级鉴权，见 `src/teec/session.rs` 的 OpenSession 认证段）；清缓存前后结论一致；CA uuid 为合法 UUIDv5 |

## 重放崩溃语料

```bash
cargo +nightly fuzz run fuzz_tee_response fuzz/artifacts/fuzz_tee_response/crash-xxxx
```

## 上传 gerrit 前检查（对照 Wfuzz 测试规范"五"）

1. 确认无 crash；若发现代码缺陷，先修复 `src/` 中的实现；
2. 将 `wfuzz.json` 中 `project` 字段去掉调试时添加的时间戳后缀（如
   `rust-libteec-202604021212` → `rust-libteec`）；
3. 首次上传前联系平台管理员将 `rust-libteec` 加入 wfuzz 测试名单；
4. 若被测函数逻辑变更，本目录下 fuzz target 中的适配/复刻逻辑须同步更新；
5. 静态检查：本目录是**独立 workspace**（`Cargo.toml` 内自带 `[workspace]`），
   根 `Makefile` 的 `clippy` 目标未包含它，须在此目录单独执行：

   ```bash
   cd fuzz
   cargo +nightly clippy --workspace --all-targets -- -D warnings
   cargo +nightly fmt -- --check
   ```

## 复刻逻辑清单（产品逻辑变更时须同步）

以下 fuzz target 内含对 `src/` 产品实现的**复刻或适配**逻辑，而非直接调用
实际函数。产品逻辑变更时，除更新 `fuzz_*` 目标外，还必须同步下列复刻，
否则 fuzz 测到的行为将与真实行为偏离：

| fuzz target              | 复刻逻辑                                                | 对应产品实现                              |
|--------------------------|---------------------------------------------------------|-------------------------------------------|
| `fuzz_operation_validate`| `validate_shm_flags`：共享内存 size/flags 合法性验证    | `SharedMemoryManager::allocate`           |
| `fuzz_operation_validate`| MEMREF/垃圾 `parent` 指针处理预期                        | 共享内存登记表校验（`is_registered`）     |
| `fuzz_operation_validate`| `make_operation` 中 union 前 8 字节布局假设（64 位平台） | `TEEC_Parameter` union 布局               |
| `fuzz_config`            | `parse_or_default`：VSOCK 配置字符串解析                | `vsock_define`                            |

其余 **13** 个 target（15 个入口点减去上表所列的 2 个 target：`fuzz_operation_validate`、
`fuzz_config`；含 `fuzz_shared_memory`、`fuzz_operation_params`、`fuzz_c_api`、
`fuzz_vmem`、`fuzz_psk_negotiate`、`fuzz_ca_auth`）**不复制产品逻辑**，而是通过
`fuzz` feature 暴露的转发层直接调用真实实现（`src/teec/fuzz_api.rs` 及
`src/teec/vmem.rs` 的 hook）。转发层只做类型转换、不做参数预处理、不改错误码，
因此产品逻辑变更时无需同步。

> `fuzz/.Cargo.lock` 与仓库根 `.gitignore` 约定一致不纳入版本控制；
> 需要在多台机器复现 fuzz 构建时，可临时生成并提交锁文件排查。

## 已知环境问题：nightly cargo build-dir layout v2

2026-08 之后的 nightly cargo 默认启用新的构建目录布局（`build/<name>/<hash>`，
见 rust-lang/cargo#17258），而 `mbedtls-smx` 的 build.rs 按旧布局
（`build/<name>-<hash>`）解析 OUT_DIR，会触发其内部断言失败。
若在较新 nightly 上构建失败，设置以下环境变量回退旧布局：

```bash
export __CARGO_TEMPORARY_BUILD_DIR_NEW_LAYOUT_OPT_OUT=1
cargo +nightly fuzz build
```

（Wfuzz 平台使用的工具链不受影响；该变量为 cargo 临时兼容开关。）
