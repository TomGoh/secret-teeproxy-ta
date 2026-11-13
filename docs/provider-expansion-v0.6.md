# 灵润可信调用扩展设计 v0.6

本轮扩展保留LSP/1.0的帧头、GP命令、参数布局、凭证引用与请求状态机。新增能力通过HELLO的`lsp-provider-dev-v2`及features/limits描述，已有DeepSeek调用字段继续可用。

## 提供商绑定

`deepseek-prod-v1`使用固定官方目标，提供CHAT、RESPONSES、MESSAGES和MODELS。对应路径为`/chat/completions`、`/responses`、`/anthropic/v1/messages`和`/models`。

`custom-provider-v1`在CREDENTIAL_PUT中加入可选字段`provider_config`，该profile要求配置包含以下两个字段。

```json
{
  "provider_type": "anthropic_messages",
  "base_url": "https://api.deepseek.com/anthropic/v1/"
}
```

base_url为最多1024个UTF-8字节的HTTPS前缀，保存时正规化。类型和前缀随凭证版本进入GP快照并参与operation receipt指纹。每条请求获得不可变的Key、提供商和撤销状态快照，PUT更新后既有请求继续使用原版本，DELETE撤销该引用的在途请求。

| provider_type | 请求operation | POST后缀 | 认证 | 流式格式 |
| --- | --- | --- | --- | --- |
| openai_compatible | CHAT | chat/completions | Bearer | SSE |
| openai_responses | RESPONSES | responses | Bearer | 语义SSE事件 |
| anthropic_messages | MESSAGES | messages | x-api-key与版本头 | Messages SSE |
| google_gemini | GENERATE | models/{model}:generateContent或streamGenerateContent | x-goog-api-key | JSON/SSE |
| ollama_native | OLLAMA_CHAT | chat | Bearer | JSON/NDJSON |

MODELS使用空body的GET，通常后缀为models，Ollama为tags。Gemini在REQUEST_OPEN提供`model_id`，路径中的模型作为单个segment编码。auth、Host、TLS验证名、请求方法和具体后缀由TA从已保存配置派生。

## 并发与资源

TA默认允许4个活跃请求和8个GP会话。准入同时检查请求数和64MiB总上传预留量，每请求上限32MiB。持有请求资源的RAII permit在完成、取消、失败、超时或Session析构时归还。

凭证持久写入继续单写者处理，并保留单个未完成修改的对账保护。QUERY和请求snapshot通过同一有界队列序列化读取，各自等待结果，读取操作保持独立于修改的pending状态。OPEN总期限在等待存储前固定，存储等待与内存预留计入同一预算。

每个CA请求使用独立SDK Context、Session、owner线程和连接，Context地址稳定。上层可以并行创建多个请求，TA按协商上限准入并返回明确的BUSY。

## 增量交付

备用Java模块继续提供`rawCall`聚合接口，并加入`streamCall(config,body,listener)`。listener依次接收HTTP头和原始body片段，完成future提供元数据、总字节数、TA终态及CA测量值。

native owner和调用线程间采用单事件队列及显式ACK。消费者接管当前事件后继续处理网络和TEEC，限制慢消费者产生的排队。取消、关闭和完成在Java端提交单一terminal winner，SDK对象由owner处理至Close/Finalize返回，cleanup单独提供观察结果。

聚合输出可配置至64MiB，增量交付保留有界片段。请求体最大32MiB。Rust错误、callback异常、clone失败和传输结果不确定均有明确失败路径。同步callback应及时返回，已经进入callback的调用栈及其数组保留至返回。

## 时限与恢复

CA在请求入口固定期限，上传、连接、TLS、callback ACK和FINISH共同使用剩余预算。网络超时取当前剩余预算和阶段上限的较小值。阻塞SDK调用或平台解析器返回后重新检查期限，保留真实资源归属。

管理操作通过operation receipt和QUERY对账。生成中断后向调用方报告失败，上层显式创建新代请求。握手、错误、取消和重新连接的测量均进入验收记录。

## 当前传输与进程资源实现

初始 HELLO 使用 16 KiB 输入帧。TA 返回 `bulk_input_frames` 和 `frame_input_max=61440` 后，CA 使用至多 57280 B 上传切片。旧端点继续采用 15000 B 切片。回复帧上限为 32768 B，JSON 元数据上限为 4096 B。TA 在 GP 入口接管并清理输入缓冲区，外层回复承载输出参数。序列化边界测试覆盖 65536 B manager 容量与实际最大帧组合。

TA Rust 分配器使用 96 MiB 固定 buddy arena，C 内存接口沿用兼容的分配和释放配对。实际传输仍可能增加进程的映射数量。项目 manager 可通过 `TEE_TA_IDLE_RECYCLE_UUID` 显式启用指定 TA 的空闲回收，阈值为 2048 个映射。仅在活跃会话和 pending Open 均归零、实例 PID/启动标识/空闲代际匹配、manager 持有对应 Child 时执行回收。新实例准入等待旧 Child 的真实退出和 reap。退出失败时保留回收状态，后续 Open 有界报告忙。

每个存活的 CA context 固定绑定其 HELLO epoch、nonce、序号与 request_id。两组互不重叠的 context 之间允许发生 TA 空闲回收，随后以新 HELLO 建立关联。MagicSmooth 管理操作和请求分别持有短生命周期 context，完成 Close/Finalize 后释放。持久凭证引用和版本跨回收继续有效。

manager 按连接持有 GP session 的唯一清理责任。连接 EOF、Open 回复写入失败和显式 Close 使用同一关闭所有权机制。等待在途 Invoke 收敛后，Close 采用新的有限清理预算，清理完成后会话名额归还。CA 进程中断和后续四请求、八会话恢复作为实机测试项目。

SDK 缓冲区校验按连续虚拟地址范围累计检查所需权限，覆盖跨相邻 VMA 的合法输入。只读区域的写访问继续由权限检查拒绝。Android native C 接口的输入上限与 HELLO 协商上限共同控制大帧使用。

先前 lifecycle/supervisor 文档保留完整恢复协议的后续设计。当前可复现部署采用本节的 manager Child 所有权、连接清理和空闲回收，源码补丁、编译产物和设备接受结果随交付清单冻结。

## 测试与观察

CA侧记录SDK open、Invoke次数/累计/最大耗时、HTTP头、首body、整体时间、TLS字节与HTTP字节。TA终态与CA测量值在结果中分别保存来源。性能测试使用同机同请求体的直接HTTPS基线和可信通路，另测独立TEEC吞吐。

具体字段见[LSP契约](ca-ta-protocol-v1-draft.md)、[注册表](lsp-v1-contract-registry.json)和[metadata schema](lsp-v1-metadata.schema.json)。测试范围见[验收矩阵](../testing/provider-expansion-acceptance-v0.6.md)。
