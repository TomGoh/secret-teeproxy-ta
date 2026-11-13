# CA—TA 通信契约 LSP/1 草案

状态为已实现的 LSP/1.0 工作契约，当前提供商扩展与设备验收进行中。接口双方应结合 v0.6 提供商配置和当前发布清单使用。旧 MVP 的 16 KiB 输入通过能力协商兼容。后端产物、设备身份与测试结果见本轮验收记录。[提供商扩展设计](provider-expansion-v0.6.md)

本契约覆盖 CA 同事与 TA 实现者的交界。CA 不自行拼接带 Key 的 HTTP；TA 不等待公网 socket。SDK 机密通道与 TA 到 DeepSeek 的 TLS 会话是两个独立层次。

## 1 通道、身份与版本

每个请求独立 TEEC_Context + TEEC_Session，由一个 CA worker 独占。管理通道使用另一个 context/session。TA session 默认只绑定一个 request_id；结束后关闭，不复用成下一次生成。

业务 HELLO 选择 role=request 或 management，返回 ta_epoch 和 session_nonce。role 只决定允许的业务命令，不授予权限。保留SDK当前CaAuthInfo及其实际验证结果，TA按明确记录的现有准入契约处理；首版不额外要求尚未启用的库身份增强。只有实际OpenSession被拒绝时才解决必要适配，不能伪造verified或更改其它已部署TA的ACL。灵润服务仍按既有入口权限和namespace决定管理/使用操作。app_process身份不能称为APK身份，开发阶段准入不能当作生产强化鉴权。

ta_epoch 是 TA 进程实例生成的 128 bit 随机标识，重启改变；session_nonce 是本 SDK session 的 128 bit 标识，重开改变。它们用于检测陈旧或错误关联，不是凭证或远程证明。非 HELLO 请求均带二者。

首版仅协商 major=1、minor=0。未知 major、opcode、flags 和顶层 metadata 字段明确拒绝；后续扩展必须有版本/能力协商。不能将未知字段默认为旧行为。

## 2 GP 调用封装

提案命令号：CMD_EXCHANGE = 0x00001000；本项目TA UUID提案为 c86d23b9-e568-509e-a9b2-0ad40668caf5，供双方使用同一个标识。它与CA ACL一起在设计评审和部署清单中确认；不是授权能力，也不冒用旧demo TA UUID。

| 参数 | 类型 | 语义 |
| --- | --- | --- |
| p0 | TEEC_MEMREF_TEMP_INPUT | 一份完整 LSP 请求帧。初始 HELLO 上限 16384 B，协商 bulk_input_frames 后上限为 min(frame_input_max, 61440) B |
| p1 | TEEC_MEMREF_TEMP_OUTPUT | CA 预分配至少 32768 B；TA 只返回一份总长不超过 32768 B 的回复帧 |
| p2 | TEEC_VALUE_OUTPUT | a=业务状态；b=实际回复帧字节数。仅 OUTPUT_CAPACITY 时 b=32768、p1为空 |
| p3 | TEEC_NONE | 保留，必须为空 |

GP ParamTypes 为 0x0265，必须用所选 SDK 构造，不能自行重写 postcard 或把 GP 枚举值当其序列化 variant index。

调用入口先验证参数类型和 p1 容量，再做业务解析或状态变化。p1 不足时返回 TEEC_SUCCESS、p2.a=E_OUTPUT_CAPACITY、p2.b=32768、p1.size=0；**不消费输入、不推进序号/TLS、不修改凭证**。这是唯一允许自动按相同 call_seq 重试的业务返回。

合法业务错误走 TEEC_SUCCESS + p2 + 错误帧。GP/SDK transport 返回非成功时，不依赖输出参数带回业务数据，也不相信未完整校验的 p1。结果不确定时按第 10 节处理。

若p1实际已达到32768而仍收到E_OUTPUT_CAPACITY，按协议不一致终止，不进入重试循环。

正常回复必须同时满足：p2.b == SDK 返回的 p1.size == header.frame_len，且 p2.a == header.status。仅检查 SDK 返回成功不够，不能接受静默截断。

固定 SDK 的 TEMP_OUTPUT 容量位于 `params[1].param.values.a`，输入 `data` 为空。TA 入口从 values.a 取得 p1 容量，出口将完整回复放入 p1.data。CA 复制回来的长度取 data.len()，并同时验证实际容量、帧长度和 p2.b。E_OUTPUT_CAPACITY 时 p1.data 为空，p2.b 为 32768。

TA 入口将 p0.data 移入本次调用持有的 Zeroizing 缓冲区，全部返回路径的 p0.data 为空，参数类型和值字段保持有效。SDK 对 TEMP_INPUT 的返回数据采用输入参数语义，CA 继续拥有原调用帧。容量不足时业务序号和业务状态保持在可按同 seq 重试的位置，入口缓冲区在退出时清理。

manager 外层序列化容量为 65536 B。最大输入请求的实际序列化长度为 61478 B，加长度前缀为 61482 B。清理 p0 后，满 32768 B 输出的外层回复为 32798 B，加前缀为 32802 B。旧回显行为与新最大输入组合的回复达到 94240 B，回归测试要求序列化器明确拒绝这个越界样例。扩展输入须随 p0 清理能力一起发布。

## 3 业务帧字节格式

固定 64 B 头，随后 metadata JSON，再随后原始 binary payload。所有固定宽度整数为 little-endian。UUID 字节按通常显示的 32 位十六进制顺序排列，不进行 GUID 混合端序变换。

| 偏移 | 字段 | 宽度 | 规则 |
| --- | --- | --- | --- |
| 0 | magic | 4 B | ASCII LSP1 |
| 4 | major | u16 | 1 |
| 6 | minor | u16 | 0 |
| 8 | opcode | u16 | 第 5 节 |
| 10 | flags | u16 | 请求=0；回复=1；其余位为0 |
| 12 | header_len | u16 | 64 |
| 14 | reserved0 | u16 | 0 |
| 16 | frame_len | u32 | 64 + meta_len + payload_len；无尾部多余字节 |
| 20 | meta_len | u32 | metadata 的 UTF-8 字节数，≤4096 |
| 24 | request_id | 16 B | HELLO/管理命令为全0；请求命令为非零 UUID |
| 40 | call_seq | u64 | 从1开始，回复与本次请求一致，不允许回绕 |
| 48 | status | u32 | 请求必须0；回复业务状态 |
| 52 | payload_len | u32 | binary payload 字节数 |
| 56 | reserved1 | u64 | 0 |

等价 struct 为 `<4sHHHHHHII16sQIIQ`。初始和旧端点请求帧上限为 16384 B，协商 `bulk_input_frames` 后请求帧上限为 61440 B，回复上限为 32768 B。metadata 和 payload 共用预算，可发送数据量按 frame_limit - 64 - 实际 meta_len 计算。当前 CA 的保守上传切片为扩展端点 57280 B、旧端点 15000 B，TLS 接收切片另行遵守实际帧预算。

metadata 必须是严格 UTF-8 JSON object；重复键、NaN/Infinity、浮点值、非 object 根、未知字段和越界数字拒绝。嵌套字段同样拒绝重复键。JSON 对象键序与空白无语义，golden 采用紧凑固定顺序编码便于比对。MAX_JSON_DEPTH=8（根object深度为1，每嵌套object/array加1，标量不另加深度），字段表之外的扩展只能由后续版本定义。

累计字节 offset、credential_version 和 next_call_seq 用十进制字符串表示 u64（无加号和前导零，0除外，必须≤2^64-1）。单帧切片 offset/length、容量、超时毫秒等用非负 JSON 整数 u32。epoch、nonce、operation_id、credential_ref 用32个小写十六进制字符，request_id 同时遵守二进制头规则。

## 4 公共 metadata 与响应

HELLO 请求不含 epoch/nonce。其余请求公共字段：
- ta_epoch、session_nonce：必须与本连接 HELLO 一致。
- remaining_ms：请求通道可选，仅能缩短 TA 已有总体截止时间，不能延长。
- operation-specific 字段：第 5 节定义。没有允许的 payload 时 payload_len 必须0。

所有完整回复公共字段：
- ta_epoch、session_nonce、next_call_seq。
- state：第 6 节的状态。
- error：null，或 {code:固定名称, stage:固定阶段, retry:固定类别}；不回显 Key、认证头或原始业务正文。
- 管理成功的 result 或请求通道的 progress：按下文定义，不能混用。

request progress：
- accepted_input_bytes：本次 BODY_CHUNK 或 STEP 接管的 payload 字节数。
- uploaded_body、accepted_tls_rx、emitted_tls_tx、emitted_http_body：累计 u64 十进制字符串。
- rx_credit：TA 下一轮可接管的 TLS 输入字节数，u32；不是永久保留额度。
- net_tx_pending、http_body_pending：TA 是否仍有相应数据待交付。
- need_step：TA 是否可在没有新网络数据时继续有限推进。
- poll_after_ms：无立即工作时建议轮询/心跳间隔；不能超过协商 lease 刷新要求。
- events：typed 输出列表，见第 7 节。
- terminal：null 或 TA 终止事实快照，见第 9 节。

若请求通道回复无法编码进限定 metadata/payload，TA 必须分批输出，保留 pending；不可临时突破 p1 容量。内部不可恢复错误终止该请求，不拼接半份 JSON 回复。

## 5 命令定义

下表所列字段均为 operation-specific；非 HELLO 另加公共 epoch/nonce。R表示必填，O表示可省略，其默认值在表内给出。

| opcode | 命令与通道 | metadata / payload | 成功行为 |
| --- | --- | --- | --- |
| 0x0001 | HELLO，任一新通道 | R role、supported_versions=[{major,minor}]；O client_name≤64字节；无payload | 协商后绑定角色，返回版本、epoch、nonce、capabilities和limits |
| 0x0010 | CREDENTIAL_PUT，管理 | R operation_id、credential_ref、namespace、profile_id、expected_version；O temporary=false、ttl_ms、provider_config；payload为Key UTF-8字节 | 原子保存Key/版本/receipt，返回非秘密结果 |
| 0x0011 | CREDENTIAL_QUERY，管理 | R credential_ref、namespace；无payload | 返回 absent/live/deleted/expired、version、profile、temporary及receipt.operation_id |
| 0x0012 | CREDENTIAL_DELETE，管理 | R operation_id、credential_ref、namespace、expected_version；无payload | 记录删除与receipt，阻止新用并标记在途撤销 |
| 0x0100 | REQUEST_OPEN，请求空通道 | R namespace、profile_id、credential_ref、expected_version、operation、body_length、overall_timeout_ms、response_mode、completion_policy；O headers=[]、model_id（GENERATE必填）；无payload | 绑定request_id、固定凭证版本、预留上传额度 |
| 0x0101 | BODY_CHUNK，请求 | R body_offset；payload为body原始片段 | 接管全部片段、递增body offset；不联网 |
| 0x0102 | BODY_COMMIT，请求 | R body_sha256；R net_tx_credit、app_rx_credit；无payload | 验证完整body，启动有限TLS推进；返回由TA确定的 connect_target |
| 0x0103 | STEP，请求 | R input_kind、tls_rx_offset、net_tx_credit、app_rx_credit；network_error时R network_error_code；tls_rx时payload为密文，其余无payload | 接管0或全部输入，推进有限工作量，返回typed输出与credit |
| 0x0104 | FINISH，请求 | R reason=consumer_complete/response_consumed；无payload，不接受credit字段 | 结束该请求，保留实际HTTP/TLS状态 |
| 0x0105 | CANCEL，请求 | R reason=user/caller_gone/timeout/shutdown；无payload | 停止该请求，清空相应队列，返回终止事实 |
| 0x0106 | STATUS，请求 | 无payload | 返回状态快照，不推进TLS、不出队数据、不刷新lease |

operation枚举为CHAT、RESPONSES、MESSAGES、GENERATE、OLLAMA_CHAT和MODELS。MODELS使用GET和空body，其他操作使用POST，具体路径来自TA profile。response_mode为json、sse或ndjson，ndjson用于OLLAMA_CHAT。Chat、Responses和Messages按顶层stream字段判定，Gemini根据response_mode选择端点，Ollama缺省stream为true。completion_policy为HTTP_COMPLETE或MODEL_TERMINAL，json/MODELS使用HTTP_COMPLETE。raw调用默认HTTP_COMPLETE并交付完整HTTP body，MODEL_TERMINAL允许模型终态后的提前关闭并保留实际HTTP尾部状态。

v0.6通过HELLO的`provider_configuration`和`concurrent_requests`公布扩展。CREDENTIAL_PUT可携带闭合对象provider_config，字段为provider_type和base_url。`custom-provider-v1`要求该配置，类型取灵润的五种provider_type，HTTPS API前缀最多1024个UTF-8字节。配置正规化后持久化并参与receipt指纹，QUERY/PUT结果返回对应非秘密配置。已有`deepseek-prod-v1`继续使用固定官方目的地。

GENERATE在REQUEST_OPEN提供model_id，最多256个UTF-8字节，用于构造Gemini模型路径。其余operation使用profile既定后缀。请求采用固定版本的凭证与目的地快照，PUT后的既有请求使用原版本，DELETE撤销所有在途版本。扩展运行配置见[lsp-provider-profile-v0.6.json](lsp-provider-profile-v0.6.json)。

namespace/profile_id为1至64字节受限ASCII标识。headers为最多32个{name,value}对，总编码大小受4096字节metadata限制。Host、Authorization、x-api-key、x-goog-api-key、anthropic-version、Content-Length、Transfer-Encoding、Connection和Proxy-*等保留头由TA构造。HTTP/1.1使用Connection: close和Accept-Encoding: identity，并保留明确的重定向响应。意外的非identity内容编码返回E_HTTP_PARSE，stage为content_encoding。

Key 为1至4096字节UTF-8，不允许NUL/CR/LF；TA不默默trim或修改Key。temporary=true时ttl_ms必填，且1≤ttl_ms≤limits.max_temporary_ttl_ms；temporary=false时禁止携带ttl_ms。临时凭证不持久化。同一ref创建后temporary属性固定，PUT不得在永久/临时之间切换；转换需创建新ref并按规则删除旧ref，避免跨存储残留。普通请求帧不包含Key。

HELLO capabilities至少给出受支持operation、auth/profile列表、会话角色、业务协议版本、选定后端契约标识；limits至少包括frame_input_max（旧端点16384、bulk_input_frames端点61440）、frame_output_max=32768、json_max=4096、max_request_body、max_concurrent_requests、max_sessions、max_pending_net_rx、max_pending_net_tx、max_pending_http_body、upload_idle_ms、lease_ms、heartbeat_max_ms、max_overall_ms、max_header_bytes、max_credential_bytes、max_temporary_ttl_ms。除已验证的帧预算外，设备资源限额在G4冻结，不从旧常量直接继承。

CREDENTIAL_QUERY的absent/live/deleted/expired是正常状态，不返回明文Key。PUT/DELETE先检查同ref+namespace的末条receipt：operation_id相同且指纹相同，返回该receipt并标记replayed，不再进行当前版本CAS；同ID不同指纹返回E_OPERATION_CONFLICT。仅新操作再检查expected_version（新增为0），提交后更新版本和末条receipt。早于末条记录的历史操作不承诺重放原结果；其旧expected_version冲突时不写入，调用方QUERY对账。详见附录A。

管理与请求role不符返回E_ROLE。一个request session不能再绑定第二个request_id；重复OPEN不能隐式关闭上一请求。STATUS在OPEN前仍必须携带非零头request_id，帧级校验后返回E_STATE并消费seq；零ID始终是E_REQUEST_ID且不消费seq。

## 6 状态机与序号

请求通道状态：
NEW → HELLO_READY → UPLOADING → HANDSHAKING → EXCHANGING → HTTP_COMPLETE → ENDED。
任一绑定请求状态可进入 CANCELLED、EXPIRED 或 FAILED；这些都是不可逆终态，不能重新OPEN。

MODELS也经过OPEN和BODY_COMMIT，但body_length=0且hash为空body的SHA-256。HTTP_COMPLETE表示HTTP传输封装完整，不表示模型业务成功；CA仍须解析json/sse结论并FINISH。

| 命令 | 允许状态 | 主要状态变化 |
| --- | --- | --- |
| HELLO | NEW | 成功后绑定角色；不得重复改变角色 |
| OPEN | HELLO_READY/request | 固定凭证快照、预约body额度，进入UPLOADING |
| BODY_CHUNK | UPLOADING | offset连续且不超过body_length；只接管整块 |
| BODY_COMMIT | UPLOADING且长度完整 | 校验hash，进入HANDSHAKING；有限加密输出 |
| STEP | HANDSHAKING/EXCHANGING/HTTP_COMPLETE | 有界推进；未发送的body也按credit逐步加密 |
| FINISH | consumer_complete: EXCHANGING/HTTP_COMPLETE且允许MODEL_TERMINAL、已发HEAD和正文；response_consumed: HTTP_COMPLETE且已交付HTTP_END | 仅控制终止，不输出新数据；不伪造HTTP完整 |
| CANCEL | 已绑定请求 | 进入CANCELLED；若先已终态，保留原终态 |
| STATUS | 已成功OPEN并绑定request_id的请求通道，包括终态 | 纯查询，状态不变；OPEN前返回E_STATE并消费seq，不能作为零ID例外 |
| PUT/QUERY/DELETE | HELLO_READY/management | 管理对象按版本/operation receipt更新，通道仍可使用 |

call_seq初值1供HELLO，随后逐次递增。回复的call_seq必须等于本次请求，next_call_seq明确告知后续值。SDK/manager不能透明重放Invoke；选型验证必须确认该点。

| 结果 | 是否推进call_seq | 输入/业务状态 | CA动作 |
| --- | --- | --- | --- |
| GP参数类型错误或SDK失败 | 不可依赖 | SDK失败可能结果未知 | 关闭/中止该对象，不自动重放 |
| E_OUTPUT_CAPACITY | 不推进 | 全部无副作用 | 补足p1，以相同seq重试一次 |
| 帧格式、版本、epoch/nonce、request ID或seq校验失败 | 不推进 | 不接管payload；不推进请求 | 判协议错误，关闭该session |
| 合法帧但命令状态不允许、凭证/版本/配额错误 | 推进 | 按错误类别无业务修改或已终止 | 使用next_seq，不重放原命令 |
| STEP成功且accepted_input_bytes=0 | 推进 | 可能已处理旧pending并产生输出 | 排空后用新seq、原TLS offset重交未接管输入 |
| STEP/BODY_CHUNK接管成功 | 推进 | accepted为完整payload长度 | 将相应输入offset前移 |
| TLS/HTTP/内部不可恢复错误 | 推进（若完整回复可得） | 请求进入FAILED，保留已交付部分事实 | 终止请求，不补发生成 |
| 对已终态再次FINISH/CANCEL | 推进 | 保留最先终态，不产生第二个REQUEST_END | 幂等返回终态快照，再关闭 |

格式层错误返回最小错误帧（若能安全关联头），或GP错误；不能为了返回错误解读或输出原始秘密数据。若无法确定关联，CA不得将回复交给另一请求。

管理operation receipt与Key记录原子提交，采用“每ref末条receipt+有界退休保留”策略，详见附录A和存储设计。live记录各限64，永久/临时总记录各限192；DELETE/过期将既有槽位转为退休记录，至少保留600000ms后才可GC，未到期不为新写提前淘汰。永久GC同样通过完整快照提交；加载TA后保守重新起退休保留期限。临时表重启可消失。GC后的QUERY absent仅表示当前无记录，不证明从未存在或某次操作提交与否。

CA为每次新预设生成全新的随机ref和operation_id，禁止复用旧ref。结果未知只QUERY，不自动重发旧PUT/DELETE；超过退休保留窗口后不承诺返回旧receipt，也不承诺可信端无限识别所有已淘汰ref。对退休ref的拒绝与末条receipt查重只在其仍被保留时成立。不得把有限缓存描述为永久防重用或跨存储重置exactly-once。

## 7 STEP、事件与数据所有权

STEP.input_kind 只能是 none、tls_rx、tcp_eof、network_error：
- none：payload为空，用于drain/heartbeat，不能当EOF。
- tls_rx：payload非空；tls_rx_offset等于此前已接管TLS字节数。
- tcp_eof：payload为空；CA本地所有已读TLS数据必须先被TA接管，offset匹配；TA把EOF排在已有输入之后处理。
- network_error：payload为空；network_error_code只允许dns_failed、connect_failed、connect_timeout、read_failed、write_failed、reset、idle_timeout，区分大小写，不接受额外值或系统错误原始敏感串。精确集合也写入注册表；dns_failed为解析失败，connect_failed为非超时建连失败，connect_timeout为网络连接期限，read_failed/write_failed为对应非超时I/O失败，reset为明确连接复位，idle_timeout为网络I/O停滞期限。

网络阶段期限到期使用network_error，TA产生E_NETWORK、stage=network、end_reason=transport_error；CA保留自己产生的connect_timeout/idle_timeout并对外映射timeout。总体、上传总体控制或消费者期限到期使用CANCEL(reason=timeout)，已观察到TA自身E_DEADLINE也映射timeout。若总体期限已经到期，不再以网络错误覆盖它；无法送达控制帧时保留本地已知原因和远端未知，不伪造TA终态。

每STEP同时给net_tx_credit、app_rx_credit，单位是本轮最多可接管的payload字节，不是累计配额。TA输出各类数据不超过对应credit，总帧仍受32768限制。HTTP_HEAD和错误/取消终态使用另外的有限保留预算。HTTP_END必须等先前所有HTTP_BODY从TA排空后才能输出；不能借“控制优先”越过正文。CA同样在先前正文向消费者交付之后再交付正常HTTP_END/Terminal。

v1接管输入为全或无：accepted_input_bytes只能为0或payload_len。TA先检查有界NET_RX队列容量，再接管整块；后续TLS处理可以分多轮。如果已接管后处理失败，accepted仍表示这些字节已归TA，不得重送。credit会随全局资源变化而缩小，accepted=0是合法背压，CA须有退避/总体期限，不能忙循环。

事件descriptor采用：
{event_seq, kind, offset, length, stream_offset?, may_contain_request?, details?}

- event_seq是从1开始的session内累计u64字符串，所有输出种类共享顺序。
- offset/length是单帧payload内u32索引。descriptor按payload顺序排列，非空切片连续、无重叠、完整覆盖payload；零长控制事件位于当前游标，不推进游标。
- NET_TX/HTTP_BODY携带stream_offset；分别从0累计，不能混用。HTTP_HEAD不计入body offset。
- 同一帧events最多8个，metadata总长≤4096。队列剩余内容在后续STEP返回。

| kind | payload | 含义 |
| --- | --- | --- |
| NET_TX | 原始TLS字节 | 仅发送到TA指定的上游目标；may_contain_request标记可能含请求应用数据 |
| HTTP_HEAD | 完整UTF-8 JSON {status,headers:[{name,value}]} | 一次响应头事件，status为HTTP整数；编码后受max_header_bytes及帧预算限制 |
| HTTP_BODY | 原始响应body字节 | 已解TLS并处理HTTP framing；保持业务字节，不在TA改写SSE/JSON |
| HTTP_END | 无 | details说明HTTP framing完整及累计body字节；不能由消费者提前结束伪造 |
| REQUEST_END | 无 | details为第9节的终止事实；每请求最多产生一次 |

一份HTTP_HEAD必须作为完整事件返回，不能让CA猜拼接格式；超限报E_HTTP_LIMIT。不得在HTTP_HEAD之前发HTTP_BODY，HTTP_END后不得再发HTTP_BODY。HTTP_COMPLETE状态可在pending正文尚未排空时出现，但HTTP_END事件不能提前出现。非2xx也返回头和有界错误体，最终由CA形成provider_error。

**所有权转移：** TA组装回复时将本批事件从pending出队。只有GP成功且整帧校验通过，CA才提交本地状态并接管输出；p1必须复制/转移到CA自有缓冲后才能复用。CA负责NET_TX短写余量和HTTP_BODY未消费余量，不能再次向TA索取同批数据。

v1无DATA_ACK、无成功回复缓存、无丢包续传。回复未知或校验失败时，整请求失败并关闭通道，不重试寻找丢失输出。该规则实现live session内确定回复的至多一次交付，不提供端到端exactly-once。

CA调度顺序：
1. 优先处理取消、deadline、连接错误。
2. 按部分写offset发送已接管NET_TX；在该数据可能含请求时更新side_effect状态。
3. 有界交付已接管HTTP_HEAD/BODY给Observer和调用方；两个消费者都计入保留预算。
4. 有TA pending且有相应credit时发空STEP排空；没有credit时仍允许控制/heartbeat。
5. 只在有NET_RX credit和本地容量时读取socket，再按offset交给TA。
6. need_step=false且无socket工作时等待事件或heartbeat；不无限空pump。

BODY_COMMIT返回一次connect_target={host,port,sni,alpn}，全部由TA profile确定；CA在成功COMMIT后连接该目标，缓存并转发NET_TX。v1每请求一条上游TCP/TLS连接，不复用连接池、不使用HTTP/2多路复用或TLS 0-RTT。COMMIT未知时CA不得开始发送未确认的输出。

## 8 错误码

BODY长度未完整、offset或OPEN配额错误不启动网络，可保留原UPLOADING/HELLO_READY状态；BODY_DIGEST错误进入FAILED。活动请求发现凭证撤销进入FAILED(end_reason=revoked)。TLS/HTTP/网络致命错误回复仅产生错误/REQUEST_END控制信息，不再输出新业务数据，已经交付的部分保留为partial。所有业务错误在完整合法帧获准处理后消费seq，格式/身份关联错误则不消费。

这里明确选择故障/取消控制优先：致命错误可丢弃TA尚未交给CA的pending正文，不能为了等待APP_RX恢复而阻塞错误、取消或资源回收。emitted_http_body只计真正已交给CA的正文，不把丢弃量计为已交付；CA已经接管的字节保留其partial/实际交付事实。MODEL_TERMINAL在合法模型终态后提前FINISH的路径，可能没有观察到随后发生的断网；它与仍开放连接且已经观察到故障的路径有不同信息，允许不同outcome。已知故障不能被尚在TA队列、CA未验证的结束标记覆盖成成功。HTTP_END的正常排空规则保持不变。

错误帧status与p2.a一致。重试类别为none、resize_only、new_request_only、reconcile_management；不表示自动重新生成。

| 状态 | 数值 | 语义 |
| --- | --- | --- |
| OK | 0x0000 | 本次命令正常处理，不等于模型生成成功 |
| E_OUTPUT_CAPACITY | 0x1001 | p1容量不足，无任何业务副作用 |
| E_WIRE_FORMAT | 0x1002 | 头、JSON、字段、长度或payload格式错误 |
| E_VERSION | 0x1003 | 业务协议版本不支持 |
| E_ROLE | 0x1004 | 通道角色不允许此命令 |
| E_STATE | 0x1101 | 当前状态不允许操作 |
| E_STALE_EPOCH | 0x1102 | epoch或nonce不匹配 |
| E_SEQUENCE | 0x1103 | 重复、跳跃或回绕seq |
| E_REQUEST_ID | 0x1104 | 请求关联错误 |
| E_CREDENTIAL_NOT_FOUND | 0x1201 | 引用不可用 |
| E_VERSION_CONFLICT | 0x1202 | 凭证expected_version不匹配 |
| E_OPERATION_CONFLICT | 0x1203 | 管理operation_id重复但内容不同 |
| E_PROFILE_DENIED | 0x1204 | profile、operation、目标或namespace不允许 |
| E_STORAGE | 0x1205 | 读取失败或写入结果未知；不能据此判断未提交 |
| E_CREDENTIAL_REVOKED | 0x1206 | 凭证已撤销 |
| E_STORAGE_NOT_COMMITTED | 0x1207 | 经权威存储复读确认本次管理写未提交；不能仅因API报错就返回此码 |
| E_BUSY | 0x1301 | 无请求/session/global额度 |
| E_LIMIT | 0x1302 | 大小或资源上限 |
| E_BODY_LENGTH | 0x1303 | COMMIT前body不完整或超长 |
| E_BODY_OFFSET | 0x1304 | 上传offset不连续 |
| E_BODY_DIGEST | 0x1305 | 完整body hash不匹配 |
| E_TLS | 0x1401 | 上游TLS验证或记录处理失败 |
| E_HTTP_PARSE | 0x1402 | HTTP framing不合法 |
| E_NETWORK | 0x1403 | CA报告的网络失败 |
| E_DEADLINE | 0x1404 | 总体期限/lease/上传空闲超时 |
| E_HTTP_LIMIT | 0x1405 | 响应头或有界解析资源超限 |
| E_INTERNAL | 0x1fff | 不可恢复内部失败，终止该请求 |

HTTP 401/429/5xx保存在HTTP_HEAD，不直接冒充以上错误码。上游模型failed/incomplete是CA业务观察结果，不由TA根据TCP EOF猜测。

存储提交事实按[凭证存储契约](credential-store-v1.md)判定。PUT/DELETE的写入结果未知返回E_STORAGE、retry=reconcile_management；QUERY/普通读取失败返回E_STORAGE、retry=none，不能转换成absent。只有复读得到完整、可校验且与写前基线完全相同的权威状态，才能返回E_STORAGE_NOT_COMMITTED、retry=none，并将本次management_commit_state记为not_committed_confirmed。该码不授权自动重试；调用方重新决定操作，仍须遵守operation_id与expected_version规则。暂时无法判定时保留unknown。内存临时凭证的错误也不能冒充永久存储提交证据。

管理PUT/DELETE的确定预提交拒绝也须保留事实：stage=credential,state=HELLO_READY的E_ROLE/E_STATE/E_CREDENTIAL_NOT_FOUND/E_VERSION_CONFLICT/E_OPERATION_CONFLICT/E_PROFILE_DENIED/E_CREDENTIAL_REVOKED/E_BUSY/E_LIMIT，以及stage=wire,state=HELLO_READY的E_WIRE_FORMAT，仅能在本次变更尚未开始前返回。CA在完整关联校验后可标本次not_committed_confirmed；这不证明同operation_id更早的未知尝试从未提交。写入开始后不能用这些码掩盖结果未知，必须按readback返回已提交/0x1207/未知E_STORAGE。E_INTERNAL/E_DEADLINE/错误epoch或seq/SDK未知不构成未提交证明。E_OUTPUT_CAPACITY按第2节无副作用GP分支处理，不伪造普通错误帧。完整本地映射见[本地契约](ca-local-contract-v1.md)。

## 9 终态、时钟与竞争

TA terminal至少含：
end_reason（consumer_complete/response_consumed/cancelled/deadline/revoked/transport_error/internal_error）；
http_framing（not_started/in_progress/complete/invalid）；
tls_phase、close_notify_received；
request_application_bytes_generated；
emitted_http_body；
app_resources（released）；
manager_cleanup（not_asserted）。

REQUEST_END仅说明TA应用对象终止，不能宣称manager binding/SDK worker已回收。manager/runtime清理由独立生命周期接口与测试验证。

CA对上层Terminal至少含：
outcome=completed/incomplete/provider_error/transport_error/cancelled/timeout/protocol_error；可另含已锁存的model_outcome，与整体交付结果分别记录；
http_status、model_stop_reason、transport_snapshot、delivered_body_bytes；
side_effect_state=not_sent/possibly_sent/response_observed；
cleanup_state=pending/released/unknown。

FINISH.consumer_complete要求MODEL_TERMINAL策略，TA状态为EXCHANGING/HTTP_COMPLETE且已输出HTTP_HEAD和正文；合法业务终态由CA负责判断。FINISH.response_consumed仅在TA已输出HTTP_END且pending HEAD/BODY为空时允许。两个FINISH以及CANCEL均为立即控制终止：丢弃TA尚未交付的NET_TX/HTTP_BODY，不返回新数据或close_notify，只返回REQUEST_END/终态快照。正常FINISH不得清空CA已接管的APP_RX。

Observer首先锁存模型结果，不立即发布上层Terminal。CA可先FINISH清理TA，但必须将已经承诺交付的正文按序交付完毕后才发布正常completed/incomplete/provider_error。若调用者中途取消、退出或消费超时，可丢弃剩余CA队列并按实际delivered计数结束，保留已知model_outcome，不冒充正文已完整交付。

| 竞争或期限 | 决定规则 |
| --- | --- |
| 用户取消与业务完成 | Observer锁存模型结果不等于对外终态；正常结果通过正文交付栅栏后才参与终态提交。取消/退出先提交则丢弃余量并记录partial；只通知一次 |
| CANCEL与STEP/COMMIT | 同session顺序执行；已受理取消后CA不转发新收到的NET_TX，不再入队普通数据 |
| TA内部deadline/revoke与正常STEP | 每个有界操作入口及内部安全点检查；先到的不可逆终态保留 |
| FINISH与已失败/已取消 | 不能覆盖原终态；返回原快照 |
| 模型已终态但HTTP尚未结束 | FINISH.consumer_complete，明确提前关闭，不造HTTP_END |
| HTTP/TCP已结束但无模型终态 | 按协议报告截断；不是成功 |
| 数据credit为0 | 仍可CANCEL/FINISH/STATUS/heartbeat；总体期限和消费停滞规则仍生效 |

CA与TA的单调时钟不共享原点。OPEN传剩余毫秒预算，TA在自己的时钟上设deadline；后续remaining_ms只能缩短。合法STEP（包括空heartbeat）可刷新idle lease，但不能越过overall deadline；STATUS和无效命令不刷新lease。上传另有idle期限，慢速上传不能无限持有全部预约内存。

TA定时清扫必须独立运行；manager连接owner cleanup必须处理CA崩溃、断连和Open结果丢失。SDK中止路径必须不依赖已占用的Invoke mutex。上述机制经真实设备验证前，不承诺固定毫秒数内全部回收。

## 10 结果不确定与关闭

对OPEN/BODY_CHUNK/BODY_COMMIT/STEP的SDK失败、截断回复或错误关联，CA不提交该回复的本地状态，不重放命令、不恢复同一生成。关闭连接，标记partial及失败，side_effect_state保守记录。

对于已确定业务结果之后的FINISH、CANCEL或Close回包丢失，保留已知业务结果/本地取消事实，cleanup_state标为unknown，不把未知清理过程宣称已完成，也不发起另一轮生成。等待owner cleanup并记录回收证据。

管理PUT/DELETE结果未知时，重建管理连接后QUERY同credential_ref与receipt.operation_id/版本进行对账。相同operation_id的重试必须经过内容一致性和expected_version规则，不能只在CA缓存里去重。

关闭顺序：停止上游I/O及普通工作入队 → 业务FINISH/CANCEL（可执行时）→ SDK CloseSession → FinalizeContext → worker回收。任一步卡住按SDK中止和owner cleanup处理，不能用全局kill其它请求的方式实现单请求取消。

## 11 双方最低契约测试

1. HELLO版本、role、epoch/nonce与未知字段拒绝。
2. GP容量不足：相同seq重试后恰好一次状态推进；其他错误不套用该规则。
3. 输入meta/payload边界、UTF-8/重复键/整数溢出/保留位/多余尾部。
4. BODY offset、长度、hash及COMMIT前不联网。
5. STEP accepted=0仍产生输出：新seq、原TLS offset重交，不重复接管。
6. 明文/密文混合输出切片与p1复用，不能串用途或串请求。
7. NET_TX短写与APP_RX慢消费者，credit=0仍可取消。
8. TCP EOF有序排在所有已读输入之后；空STEP不等于EOF。
9. 双请求交错，一条CANCEL另一条完成，管理请求不被长模型流锁住。
10. 三协议终态、keep-alive、模型受限、不完整和中途截断。
11. 已有模型终态但HTTP不完整时FINISH，保留真实framing状态。
12. COMMIT/STEP回包丢失，生成不盲重试；管理写回丢失可对账。
13. CA退出、manager断连、TA重启、旧epoch/session/request句柄拒绝。
14. SDK卡住时取消受理与worker回收分开，不能把5秒read timeout当全程deadline。
15. 临时凭证过期、更新/删除与在途请求、保存失败及重启receipt恢复。
16. 同一套frame/trace由CA mock-TA和TA mock-CA分别执行，再双端交叉联调。

设计辅助的 [golden向量与参考校验器](../../artifacts/design-preflight-20261112/protocol-draft/README.md) 已覆盖固定头与容器；它不是TA/CA实现，也没有验证本节全部状态机。本文及附录是完整业务字段和状态语义的规范来源；双方实现时据此生成/实现逐opcode业务校验器并执行共同样例，不能把当前只测容器的脚本当作已完成产品decoder。生成器版本与实现契约一同冻结。



## 附录A 闭合 metadata 与管理规则

本附录是字段表的补充约束；所有object均additionalProperties=false。无明确允许的字段必须拒绝。完整回复顶层固定为：
ta_epoch、session_nonce、next_call_seq、state、error、result、progress。
HELLO/管理成功使用result且progress=null；请求通道成功使用progress且result=null；业务错误error非null、result=null。错误回复的progress按下表确定，禁止实现者自行选择null或快照。error={code,stage,retry}；stage为wire/hello/credential/open/upload/tls_handshake/tls_io/http/network/finish/cancel/deadline/cleanup/internal/content_encoding之一；retry取第8节所列类别。header.status与error.code名称须对应，OK时error=null。

| 错误路径 | progress与events |
| --- | --- |
| HELLO/管理错误、尚未成功OPEN的请求错误 | progress=null，不能因失败OPEN或STATUS绑定request_id |
| 格式/版本/epoch/nonce/ID/seq校验失败 | progress=null，不推进业务；无法安全关联时用GP错误，不编造关联帧 |
| 已绑定请求、合法命令造成非致命业务拒绝 | 完整progress，accepted_input_bytes=0、events=[]、terminal=null，保留原非终态 |
| 已绑定请求，本命令首次导致FAILED/CANCELLED/EXPIRED且允许控制输出 | 完整progress及terminal，events恰好一个REQUEST_END，details等于terminal；不携带NET_TX/HTTP_BODY；accepted仍按真实接管量为0或整块 |
| 已终态后再次FINISH/CANCEL或其它完整关联业务拒绝 | 完整progress及原terminal，events=[]，不再次发REQUEST_END |
| STATUS | 纯状态查询，始终events=[]；已绑定则返回完整快照（终态时带terminal），不借查询出队终态事件或续租 |

定时清扫可先锁存终态；下一次可输出控制的命令至多交付一次REQUEST_END，STATUS仅读快照不消费该事件。连接已关闭时不保证还会收到REQUEST_END；不能为了“补终态”重放未知调用。

### A.1 HELLO成功result

固定字段：selected_version={major:1,minor:0}、role、capabilities、limits。

capabilities固定为：
- operations：CHAT/RESPONSES/MESSAGES/MODELS的去重数组。
- profiles：{id,auth_by_operation}数组；auth_by_operation字段只能为已支持operation名称，值bearer或x_api_key。
- backend_contract_id：长度1至128字节ASCII版本标识，仅用于匹配配置，不作设备证明。
- features：去重字符串数组；v1定义bounded_pump、business_cancel、epoch_bound_sessions、temporary_credentials、provider_configuration、concurrent_requests、credential_rebind和bulk_input_frames。

limits为第5节列出的完整对象，所有值为u32。max_header_bytes指HTTP_HEAD编码后的JSON payload上限，且不得超过单帧可用payload。heartbeat_max_ms必须小于lease_ms，且CA应在其范围内刷新。无法满足frame预算或最低能力的HELLO应失败，不能让双方自行猜默认限额。

### A.2 管理成功result

固定字段：
credential_ref、namespace、state、version、profile_id、temporary、ttl_remaining_ms、receipt、replayed。

- state=absent/live/deleted/expired。
- version为u64十进制字符串；absent固定"0"。
- absent时profile_id/temporary/ttl_remaining_ms/receipt均为null；其它状态保留对应非秘密元数据。
- 永久记录ttl_remaining_ms=null；临时live为剩余毫秒，expired/deleted为0。
- receipt=null，或{operation_id,operation,committed_version}，operation为put/delete，版本为u64字符串；这是已提交操作事实，不等同当前Key仍可用。
- QUERY的replayed固定false；重复末条PUT/DELETE为true，并返回当前state与原receipt，避免临时Key已过期仍显示live。

临时凭证绑定经授权的灵润服务提供的namespace，不绑定创建它的management session；关闭该管理session不会立即删除，否则后续独立请求session无法使用。灵润服务在调用者退出时主动DELETE；TA TTL到期拒绝新OPEN并标记在途撤销，独立清扫释放秘密数据。重启后临时引用失效，不能自动用旧ref重放PUT；需要新的ref和显式预设。

### A.3 管理指纹与查重优先级

operation_id的查重作用域为(namespace,credential_ref)。指纹只在TA内部存储，不返回给CA：
SHA256(opcode_u16LE || LP(namespace) || ref_raw16 || expected_version_u64LE || LP(profile_id) || temporary_u8 || ttl_ms_u32LE || LP(secret_bytes))。
LP(x)=字节长度u32LE后跟原始字节。DELETE固定profile_id空、temporary=0、ttl=0、secret为空。PUT在缺省temporary=false时ttl固定0；字符串按原始UTF-8，不进行Unicode归一或trim。指纹不包含连接epoch/nonce/call_seq。

检查顺序：
1. 验证管理准入、帧、scope和字段。
2. 若末条receipt的operation_id相同，先比较指纹；相同则返回receipt，不再做CAS，不改版本。
3. 否则DELETE无记录先返回E_CREDENTIAL_NOT_FOUND，不对不存在的记录执行虚拟version=0 CAS，也不能据此认定先前DELETE成功。PUT无记录要求expected_version=0；已有记录先执行expected_version检查，不匹配返回E_VERSION_CONFLICT。匹配但保留记录已deleted/expired时，新PUT/DELETE返回E_CREDENTIAL_REVOKED，不复活、不再递增版本。
4. 通过以上检查才执行新操作并原子提交Key/状态/version/receipt。更早的receipt或已被GC的退休记录不在重放保证内；旧调用只能QUERY对账，不自动把absent当作允许重新创建旧ref。

### A.4 请求progress与connect_target

progress只允许第4节列出的全部字段，并增加connect_target（null或{host,port,sni,alpn}）；各字段每次都返回。connect_target仅成功BODY_COMMIT首次给出，其他回复为null。host/sni为规范化ASCII主机名，port为1..65535整数，alpn固定"http/1.1"。

events descriptor按kind闭合：
- NET_TX：event_seq、kind、offset、length、stream_offset、may_contain_request。
- HTTP_HEAD：event_seq、kind、offset、length；payload闭合为{status,headers}，headers元素为{name,value}。
- HTTP_BODY：event_seq、kind、offset、length、stream_offset。
- HTTP_END：event_seq、kind、offset、length=0、details={framing:"complete",body_bytes}。
- REQUEST_END：event_seq、kind、offset、length=0、details等于本帧progress.terminal。

terminal闭合为第9节列出的全部TA字段；tls_phase取not_started/handshake/application/closed/failed；字节计数为u64十进制字符串；close_notify_received为bool；app_resources固定"released"，manager_cleanup固定"not_asserted"。

request_id与call_seq从固定头关联。OPEN前STATUS若给合法非零ID，则返回E_STATE且progress=null；不能让TA绑定它。OPEN成功后所有请求命令都必须使用已绑定ID。

失败OPEN不绑定ID且保持HELLO_READY，wire允许用下一seq再次提交OPEN并选择新的非零request_id；成功OPEN后不能换ID或复用成另一生成。生产CA首版对确定的OPEN拒绝返回其错误并关闭本次context，不自动重放或无界排队；业务层可显式发起新的请求。全局mutation fence保留，以避免磁盘/内存发布间隙被新OPEN或QUERY观察，不改成在变更中读旧状态。


### A.5 精确标量类型

| 字段 | wire JSON类型及范围 |
| --- | --- |
| expected_version、version、committed_version、body_length、body_offset、tls_rx_offset | 规范u64十进制字符串，允许"0"，禁止数字类型/前导零/符号/越界 |
| next_call_seq、event_seq | 同上，但必须≥1 |
| uploaded_body、accepted_tls_rx、emitted_tls_tx、emitted_http_body、stream_offset、body_bytes、request_application_bytes_generated | 规范u64十进制字符串，允许"0" |
| body_sha256 | 64个小写十六进制字符，表示完整原始body字节的SHA-256，不是base64或binary字段；空body使用标准空串hash |
| net_tx_credit、app_rx_credit、accepted_input_bytes、rx_credit、poll_after_ms | JSON u32整数，允许0；bool不视作整数 |
| overall_timeout_ms | JSON u32整数，范围1..limits.max_overall_ms |
| remaining_ms | JSON u32整数，允许0；0表示已到期，只可触发终止而不能延长期限 |
| ttl_ms | JSON u32整数；仅temporary=true时出现，范围1..limits.max_temporary_ttl_ms |
| ttl_remaining_ms | JSON u32整数或null；语义见A.2 |
| temporary、replayed、net_tx_pending、http_body_pending、need_step、may_contain_request、close_notify_received | JSON bool；仅A.2声明的absent temporary允许null |
| events[].offset、events[].length | 单帧u32 JSON整数，非累计offset |
| HTTP_HEAD.status | JSON整数200..599；v1只向CA发最终响应头，1xx在TA内部处理且最多8条，101升级拒绝 |
| host、sni、profile/namespace标识 | 文中限定的ASCII字符串；不得含NUL/CR/LF |
| result/progress/error/terminal/receipt及connect_target的null | 必须用JSON null，不能用空字符串或空object代替 |
| 其它枚举和标识 | 必须为本稿列出的精确字符串或32位小写hex，区分大小写 |

BODY_CHUNK必须有非空payload，且上传累计量不超过body_length。空body直接COMMIT，不使用空BODY_CHUNK刷新上传idle期限。

## 附录B 机器可读注册表

[协议注册表](lsp-v1-contract-registry.json)记录TA UUID提案、GP命令、帧限额、opcode/status和DeepSeek profile。该文件与本文共同评审；它不是完整metadata JSON Schema或已部署配置，不能单凭加载它跳过字段/状态验证。

逐opcode的[闭合metadata schema](lsp-v1-metadata.schema.json)与本文共同维护。schema顶层的validationEnvelope只是检查器输入：direction/opcode/status来自已解析固定头，request_bound来自本地会话状态，只有metadata对象是真实wire JSON；不得把这个检查封套发送给TA。E_OUTPUT_CAPACITY只有GP参数回复，没有LSP metadata。共享lsp-wire crate由双方共同维护并采用同一schema/fixture版本，首版不各自创造另一套字段校验规则。严格UTF-8/重复key/浮点词法、u64上界、帧/事件字节切片、credit/历史状态和真实提交事实仍须执行代码校验，schema不替代这些语义。

## 附录C 业务级完整示例

[lsp-v1-business-examples.json](lsp-v1-business-examples.json)提供独立场景的完整request/reply字段、payload和前置条件，供两位开发者分别实现mock测试。所有Key和资源限额都是fixture值，TLS字节是合成数据，不代表设备能力或真实加密结果。

检查入口：[generate-business-examples.py](../../artifacts/design-preflight-20261112/generate-business-examples.py) --check-only。该检查只验证字段/计数/切片等样例一致性，不是TA/CA状态机执行结果。

本轮新增[错误、背压与大帧样例](lsp-v1-edge-examples.json)：网络分类、TLS接管后失败、revoked/deadline、accepted=0、混合typed payload、32KiB且8个事件、下一帧HTTP_END、APP_RX=0时的故障优先，以及只查询已终态快照。每例显式给出先前会话条件；它们是独立帧对而非伪装成已执行端到端trace。校验器见[check-wire-contract.py](../../artifacts/cursor-opus55-review-20261113-005109/check-wire-contract.py)。

## 附录D 进程内 API 的边界

[JNI生命周期设计](ca-jni-lifecycle-v0.1.md)与[C ABI声明](lsp-ca-ffi-v1-draft.h)约束Java/native之间的所有权。event ticket及ACK/NACK仅用于进程内交付，不新增本文opcode，不构成TA数据ACK或Invoke重放。

本地cancel对management操作不发送LSP CANCEL。queued取消表示未发；PUT/DELETE已发时结果可能未知，须保留非秘密operation_id/ref/expected_version查询对账；已提交不会因本地取消而回滚，不保留Key自动重试。

## 已保存密钥的配置更新

CREDENTIAL_PUT可携带reuse_existing_key=true并使用空payload。TA对已有live引用执行expected_version和operation_id校验，在TA内复用Key并保存新的provider_config与版本。其receipt按元数据与复用标记计算，支持QUERY对账及重启后的同操作重放。普通PUT继续要求显式Key。不存在或已撤销的引用按既定错误和CAS顺序返回。
