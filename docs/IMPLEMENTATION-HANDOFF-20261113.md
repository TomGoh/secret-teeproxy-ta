# 当前 v0.6 实现入口

当前四请求、三协议、bulk 输入与 APK 集成见 `docs/provider-expansion-v0.6.md`、`tools/teec-probe/README.md`、`CONTRACT.lock.json`，以及总工作区 `artifacts/provider-expansion-20261113/FINAL-REPORT.md`。实际 Java 类和 `tools/teec-probe/include/lsp_backup_ca.h` 描述交付 API。

下方保留当日首版单路 MVP 的历史设备和产物检查点。当前运行 CID 由总工作区 `device18/runtime-endpoint.json`、`device19/runtime-endpoint.json` 提供。

# TA实现与CA联调交接

2026-11-13。适用于灵触圈选文字，经灵润自定义提供商调用DeepSeek官方Chat Completions的MVP。生产CA整合在灵润APK的服务进程内，现阶段生成并发上限为1。

## 当前实现与运行入口

签名TA已部署到 `.18` 和 `.19` 各自独立的protected调试VM。现有kernel.bin继续使用冻结产物。rootfs增量加入TA、GP manager和自启动组件，各设备使用独立instance/data。两台Android的本次boot ID保持一致，调试VM各完成了一次保留存储的受控重启。

| 项目 | .18 | .19 |
| --- | --- | --- |
| ADB | `10.42.27.18:5555` | `10.42.27.19:5555` |
| 当前CID | `2051` | `2049` |
| GP manager端口 | `10099` | `10099` |
| namespace | `demo` | `demo` |
| 已导入凭证引用 | `f0035ee9570e4c74878455460f8319aa` | `a6d5d0959f1549d3ab1067e1303f0899` |
| 凭证版本 | `1` | `1` |
| 代码目录 | `/data/local/tmp/lsp-magictouch-mvp-ta-20261113-122542` | `/data/local/tmp/lsp-magictouch-mvp19-ta-20261113-124033` |

两台的TA UUID均为 `c86d23b9-e568-509e-a9b2-0ad40668caf5`，profile为 `deepseek-prod-v1`。当前CID来自运行时记录，VM再次启动时应重新发现。备用CA在进程内固定一次endpoint，CID变化后重建灵润的runtime进程并建立新会话。

总工作区的 `artifacts/ta-implementation-20261113/vm/ta-candidate-122542/runtime-endpoint.json` 与 `vm19/ta-candidate-124033/runtime-endpoint.json` 包含boot、owner、CID与TA epoch。联调前应核对记录和当前设备。

## 稳定的CA—TA契约

详细字段、错误和状态定义继续使用 `docs/contracts` 的LSP/1合同与 `CONTRACT.lock.json`。本轮实现沿用这些字段含义。

| 项目 | 实际实现 |
| --- | --- |
| GP命令 | `CMD_EXCHANGE=0x1000` |
| GP参数 | `TEMP_INPUT, TEMP_OUTPUT, VALUE_OUTPUT, NONE`，编码 `0x0265` |
| p0 | 完整LSP输入帧，最大16384B |
| p1 | 预分配32768B，返回完整LSP输出帧 |
| p2.a / p2.b | LSP状态 / 实际输出长度 |
| 输出容量不足 | `E_OUTPUT_CAPACITY=0x1001`，p1为空，p2.b为32768，序号与副作用均未消费 |
| 输入帧头 | 64B，little-endian，JSON严格校验 |
| u64元数据 | 按合同使用十进制字符串 |
| 身份关联 | TA epoch、session nonce、request ID及call sequence |
| 当前准入 | 1个活跃生成，8个GP会话，第二个生成明确BUSY |

管理会话使用HELLO后执行CREDENTIAL_PUT、QUERY与DELETE。PUT采用调用方生成的operation_id与expected_version。成功收据需与QUERY核对。正常请求携带namespace、credential_ref和expected_version。查询结果包括状态、版本及收据。

请求会话依次执行HELLO、REQUEST_OPEN、BODY_CHUNK、BODY_COMMIT、STEP与FINISH。CA按credit排空TLS输出、写入TCP，保存尚未被TA接收的TLS输入，按累计offset交互。终态释放、取消和STATUS读取遵循合同。网络或Invoke结果不确定时结束当前代，并按业务结果与管理收据处理恢复。

TA验证固定的 `api.deepseek.com:443`、SNI与证书链，认证头在TA内构造。JSON及SSE字节作为HTTP body交给CA。当前支持CHAT与MODELS。

## 可以直接复用的备用CA

`tools/teec-probe`包含同一Rust库的CLI与APK模式。Java入口为 `com.kylinos.systemai.tee.BackupTeeClient`，APK中加入Java JAR与以下两个ARM64库。

- `liblsp_backup_ca.so`
- `liblsp_backup_jni.so`

调用与配置完整说明见 `tools/teec-probe/README.md`。`open(cid,10099)`异步创建专属SDK owner，`rawCall(config,body)`执行完整LSP/TLS/TCP处理，完成HTTP后返回原始body和transport元数据。body输入与输出各限2MiB，适用于本次文字演示。调用完成后该handle关闭，下一次调用创建新handle。

rawCall聚合完整SSE body后返回，与已调查的灵触raw响应聚合展示路径衔接。灵润适配层需要校验HTTP、TA终态、SSE `[DONE]` 和模型finish_reason，读取非null的 `delta.content`，处理usage及上游错误事件。取消与关闭通过独立原子状态交给owner处理，cleanup future报告SDK CloseSession/FinalizeContext返回。

低层 `exchange(frame,capacity)`用于管理导入或需要自行处理LSP的集成。Java配置中的expected_version为整数，库编码LSP时转为合同要求的字符串。密钥输入由调用方在内存中提供，调用方负责擦除原始数组。

任务专属rust-libteec副本包含两项Android功能适配，均保留上游协议。

1. 显式、进程内不可变的VSOCK endpoint配置，支持APK已有Java线程的初始化场景。
2. Android/AArch64带标签堆指针在VMA权限检查时归一化地址，实际访问和释放继续使用原始指针。此项已通过普通APK真实Invoke验证。

CA身份校验编译选项保留。测试身份实际报告 `verified=false`，开发TA授权策略接受此次联调。APK库模式身份的进一步绑定与安全加固继续按已约定优先级记录。

## 已完成的验收

| 层次 | 结果与证据 |
| --- | --- |
| TA宿主机逻辑 | 42/42测试通过，覆盖wire/store/App/TLS/HTTP及异常输入 |
| 备用CA宿主机逻辑 | 17/17测试通过，含SDK VMA兼容与SSE截断回归 |
| Java生命周期 | 80例JNI stub测试通过，覆盖取消、关闭、完成竞争与重复清理 |
| 两台真实protected VM | 签名TA执行、GP初始化/恢复、teec HELLO和p1/p2关联通过 |
| 两台假凭证套件 | CRUD/CAS/收据、BUSY、上传offset、零credit取消、终态与slot释放通过 |
| 两台真实DeepSeek | `/models` HTTP200，Chat Completions SSE标记、stop、DONE及HTTP完整结束通过 |
| 两台持久化 | 各自调试VM重启后沿用原credential_ref，真实SSE通过 |
| 重复真实SSE | `.18`一组连续10次通过，`.19`短标记一组连续10次通过 |
| 普通Android应用 | 最终冻结库在`.18` UID10121、`.19` UID10120各通过MODELS、SSE、取消后新请求、关闭后新请求六步，共12/12通过 |
| 已知密钥表示日志扫描 | console/manager/VM与验收日志的文本、hex大小写和base64匹配计数均为0，原始远端日志仅在扫描进程内存中处理 |

总工作区 `artifacts/ta-implementation-20261113/` 保存构建脚本、源码manifest、签名验证、设备报告、真实调用状态摘要和失败记录。根目录的测试程序通过non-PTY stdin执行一次显式导入，后续调用使用凭证引用。

首轮32-token合成生成未通过标记与finish校验，扩大测试预算至512后通过。`.19`早期长随机串重复测试第4轮得到完整HTTP200、stop与DONE，但标记不匹配，该轮失败证据保留。后续短标记十连验收通过。早期APK调用的Android tagged-pointer错误已修正并通过真实应用复测。

## 当前产物身份

| 产物 | SHA256 |
| --- | --- |
| 冻结kernel.bin | `7acf3cb1b1b8826b96ec78e14292b60c509fb87cbcf1d83e4dc50a6ac1fcc5f1` |
| 最终签名TA | `6501e028346906bfa8005d48e44a0b60ffc705a9dd8e0351da12d343b297939d` |
| GP manager | `08aa568d3d43b402269918d8bb65c8cc4487265c8347dbb2d162e6b972378dae` |
| 最终Bionic CA core | `280af05efc6e1c4d2ad1c855471546aef759f0e81b5ebe184459cec14f5be7c8` |
| JNI adapter | `038fa83f0b81bf7632e9c1948cd00491e19a6c6fda964b33adf348786ddaeebb` |
| Java JAR | `220aa9874207791809f6db4af40fc7c52d2ccc0118d976165c3f15d9dca411cd` |
| 最终测试APK | `a64486982acdc4be3bc79daabb20a0a4dfda71b32120589bfb23791e95d0737c` |

CA基线为rust-libteec `1a6c7619bfd1690a426b92115a68d76caa282638`，TA SDK为 `6966f624e15d572eea8f08ecd13656349f0c81fe`，rust-libutee为 `2a42b2976e57f72ca555c493e41c784d37b10285`，manager为xtee-apps `f571294dd0898f2e82e0522d43bd045056bcc129`。实际锁文件和任务适配源码随仓库提供。

## 接下来双方联合完成

1. 灵润同事接入现有CA实现或备用模块，将选定DeepSeek提供商映射到TA凭证引用，并在runtime进程内使用当前CID。
2. 将SystemAiManager的submitCloudRaw分派到CA，接入请求结果、错误、取消和完成回调。
3. 进行系统灵润APK替换与灵触真实圈选联合验收，覆盖摘要、理解、翻译、润色、取消及后续重试。

当前联合验收仍待整合后的灵润APK。GP异常掉电、manager内部全部清理及控制面专项验证另列后续测试项。两台guest UTC约快8小时，已记录，当前实际TLS调用通过。
