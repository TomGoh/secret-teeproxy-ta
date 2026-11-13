# CA 进程内功能性交接合同 v1

状态：功能设计合同，供Java/JNI、Rust CA和TA分工实现；不是已部署配置或实现通过声明。配套：[JSON Schema](ca-local-contract-v1.schema.json)、[C ABI声明](lsp-ca-ffi-v1-draft.h)、[JNI生命周期](ca-jni-lifecycle-v0.1.md)、[LSP通信协议](ca-ta-protocol-v1-draft.md)。

本轮优先补全功能闭环，身份增强后置。CA仍在灵润APK/:runtime进程内作为Rust库运行；不引入独立CA服务/helper，不新增签名强制或运行时verified=true开关。既有SDK行为需如实记录，不能将后置身份任务描述为已验证。以下JSON不承载签名根、身份证明或descriptor UUID覆盖值。

## 1 范围、编码与默认规则

本合同定义JNI传给C ABI的config/request metadata、独立secret/body bytes，以及readEvent返回的metadata。它是Java与CA之间的本地合同，不是LSP wire。Rust CA负责补充TA epoch、session nonce、request ID、call_seq及GP封装；Java不得直接提交这些远端会话字段。

所有metadata：
- 严格UTF-8 JSON object，contract_version固定1，document_type为对应的精确枚举。
- 未知字段、重复key、NaN/Infinity、浮点字面量、孤立surrogate和超过8层容器深度一律拒绝。规则只针对本地metadata；业务body可以包含temperature等合法JSON浮点值。
- 除event外，规范化后的紧凑UTF-8 metadata不得超过8192 B。event受runtime的max_event_metadata_bytes限制。
- object均additionalProperties=false；没有明确默认的输入字段必须提供。输出字段全部必填，未知事实用JSON null，不能省略或改为空字符串。
- u32为JSON整数，bool不能当整数；u64必须为规范十进制字符串，范围0..18446744073709551615，禁止前导零、符号和数字类型。event_sequence/ticket等明确要求正数。
- hex128为32个小写hex；identifier采用[A-Za-z0-9._-]{1,64}。correlation_id为null或1..128字节[A-Za-z0-9._:-]，仅做诊断关联，不作身份或句柄。
- JSON Schema的default只是注释，不自动填充。实现先按本合同补默认，再重新验证和执行跨字段规则；不能指望validator替应用修改输入。
- JSON Schema不辨别被解析后的重复key或1.0/1词法差别，入口parser须单独落实；检查脚本已覆盖这些规则。

所有输入失败返回固定本地ABI错误，不把validator错误全文、原始metadata、Key或正文写日志。C函数调用期间借用数组，成功准入前复制；body和secret不编码为metadata字段或base64字符串。

## 2 runtime config

document_type=runtime_config。所有字段必填，无隐式远端探测。

| 字段 | 类型与规则 |
| --- | --- |
| contract_version | 整数1 |
| sdk_profile | identifier；指向本构建可识别的功能性SDK组合配置，不是身份已验证声明 |
| required_backend_contract_id | 1..128可见ASCII字符；要求HELLO所返回组合标识匹配 |
| endpoint | 闭合{cid,port}；cid为3..4294967294、port为1..4294967294的u32 |
| resources | 第3节全部容量字段，不能只提供部分覆盖 |
| timeouts | 第3节全部时间字段，单位毫秒 |
| profiles | 1..16个不重复identifier；允许使用的provider profile集合 |

config不接受TA UUID、descriptor UUID、Key、verified、签名根或任意自定义密码算法字段。产品与测试宿主复用同源核心和ABI；具体构建身份差异由后置身份设计负责，不能靠Java改UUID伪装成另一构建。

create成功仅代表本地配置合法、内存额度与调度设施可准入。没有证明SDK、TA或DeepSeek可达。PROBE异步返回真实HELLO能力；每个请求context还要核对自身HELLO，不能永久复用一次旧能力结果。

## 3 初始工程配置与协商

Schema顶层x-initial-engineering-config给出完整可复制初始值。它是实现起点，不是设备能力值、容量测量或性能承诺。以固定1GiB可信VM作为后续验证环境，但不能据此推断所有内存均可供TA正文使用。

### 3.1 本地容量

| resources字段 | 初始值 | 本地配置边界/含义 |
| --- | --- | --- |
| max_request_workers | 2 | 1..32；首版验收要求实际至少双请求重叠 |
| max_queued_requests | 4 | 0..128；队列项数不代表可绕过body字节预算 |
| max_queued_management | 8 | 0..128；共享admin worker单飞 |
| max_operation_records | 32 | 1..1024；覆盖活动、排队、待清理与未release记录 |
| max_request_body_bytes | 33554432，即32MiB | 1..64MiB，本地单请求上限；需再与TA上限比较 |
| max_request_body_reservation_bytes | 67108864，即64MiB | 1..256MiB；全部已准入请求正文的合计预约，不是TA动态余量 |
| max_native_retained_bytes | 134217728，即128MiB | 128KiB..512MiB；本模块拥有的正文副本、缓冲与暂存预算 |
| net_rx_bytes_per_request | 65536 | 16KiB..1MiB |
| net_tx_bytes_per_request | 65536 | 32KiB..1MiB |
| app_rx_bytes_per_request | 65536 | 16KiB..4MiB |
| max_event_metadata_bytes | 8192 | 4KiB..64KiB |
| max_event_body_bytes | 16384 | 1..64KiB，不能大于app_rx缓冲 |
| max_credential_bytes | 4096 | v1固定，与LSP一致 |
| max_pending_java_events_per_operation | 1 | v1固定，一个未结算ticket |

max_operation_records至少为workers+request queue+management queue+1，额外记录被用尽时仍可拒绝准入。max_request_body不得超过总body预约预算；总body预约必须小于native总预算。至少要留出一个大body复制及per-flow缓冲的空间，不应在短锁内分配或复制。

预约body额度在Rust复制之前取得；提交失败释放预约。预约包含排队中的正文，不能等到发TA OPEN才计费。Java原数组和其自行保留的已ACK结果不在native总预算内，Java适配器另有有界消费策略；不能把128MiB说成整个灵润进程的堆上限。

TA总正文预约初始同为64MiB，但**CA和TA分别独立执行上限**。现有HELLO不包含动态global body剩余量，v1不新增这个wire字段。TA OPEN仍是权威准入，竞争者可能使其返回E_BUSY；HELLO能力不是预约成功。

单个存储快照512KiB等vault预算属于TA存储设计，不能与32MiB单请求正文或64MiB总正文预约混用。

### 3.2 时间参数

| timeouts字段 | 初始毫秒 | 含义 |
| --- | --- | --- |
| default_overall_ms | 120000 | 未指定操作期限时采用 |
| max_overall_ms | 600000 | 本地操作总期限上限 |
| sdk_connect_open_ms | 15000 | SDK连接、ECDH/TLS及OpenSession合计预算；不按子阶段重置 |
| sdk_connect_ms | 5000 | 上述合计预算内的连接子阶段cap |
| sdk_handshake_ms | 10000 | 上述合计预算内的ECDH/TLS握手子阶段cap |
| sdk_call_budget_ms | 5000 | 普通Invoke子阶段cap；Open阶段还受合计剩余预算限制；不套用到CloseSession |
| sdk_graceful_close_ms | 15000 | 独立SDK优雅关闭序列总预算，包含等待与CloseSession/FinalizeContext；CloseSession取该预算剩余量，不受普通Invoke的5秒cap限制 |
| worker_reap_grace_ms | 3000 | transport abort之后观察本地worker收尾的宽限；未结束标STALLED，不强制free |
| network_connect_ms | 15000 | 上游连接预算 |
| network_idle_ms | 30000 | 网络I/O停滞预算；心跳不是业务完成 |
| upload_idle_ms | 10000 | 正文上传停滞预算 |
| heartbeat_ms | 1000 | 本地心跳目标间隔，受TA约束 |
| consumer_idle_ms | 30000 | Java消费者无进展预算 |
| event_ack_ms | 30000 | event ticket消费确认预算 |
| max_read_wait_ms | 1000 | 单次readEvent最长等待 |
| cleanup_observe_ms | 2000 | UI或控制方观察清理状态的窗口，与优雅关闭/worker回收预算不同，不强制free |
| default_temporary_ttl_ms | 60000 | UI/测试预设入口可选用的建议TTL；wire temporary=true仍须显式ttl_ms |
| max_temporary_ttl_ms | 300000 | 本地临时凭证TTL上限 |

时间字段均为正u32；max_overall/max_temporary等工程配置绝对上限为3600000ms，max_read_wait/cleanup_observe上限60000ms。default不得超过对应max。所有有效期限取已有总体剩余预算和阶段预算的较小值，不允许跨阶段无限重置总期限。

SDK连接开始时建立D_open=min(请求overall deadline, 当前单调时间+sdk_connect_open_ms)。连接、ECDH/TLS与Open的实际预算依次取min(对应子阶段cap, D_open剩余时间)，不是5000+10000+5000累计20秒；前段耗尽15秒后不能再开始Open。普通Invoke取min(sdk_call_budget_ms, 请求总体剩余时间)。

请求结束后的资源清理采用独立且不可重置的sdk_graceful_close_ms预算；耗尽后请求transport abort，再观察worker_reap_grace_ms。清理预算不能延长生成或继续正文交付。cleanup_observe_ms仅控制UI/status查询等待，不决定SDK是否已停止。worker仍活跃时保留对象并报告STALLED；manager Close等待上限8000ms已包含全部内部清理阶段，不能把各阶段相加；CA关闭总预算15000ms为通信与本地收尾留余量。不得因15秒、3秒或2秒任一计时到达就free或强杀线程。

readEvent等待超时仅返回WAIT_TIMEOUT，不取消请求。消费期限到期可以触发本地timeout；SDK阻塞中止仍须适配实现。上述所有时间值都是工程配置和预期控制策略，不是已证实的SDK或TA资源回收上界。

### 3.3 与TA协商

- 核对LSP版本、backend_contract_id、profile/operation/auth及必需能力；不匹配明确失败。
- v1帧预算固定输入16384、输出32768、JSON4096，不通过本地配置增大。
- effective单请求body、并发、每流可用缓冲、总体期限和临时TTL上限取本地与HELLO可见上限的min。并发还需为admin预留至少一个session；协商结果不足2不得宣称满足双并发验收。
- heartbeat间隔不超过TA heartbeat_max_ms且严格小于lease_ms；建议选min(local heartbeat, TA heartbeat_max, floor(lease/2))，结果为0视为不兼容。
- 总body预约、native总预算与Java未ACK配额是本地独立准入；不从未存在的远端global余量字段推断。
- per-STEP credit是当轮容量，不是HELLO授予的永久配额。已读未交给TA的密文、partial write余量及未消费APP_RX均计入占用。
- 所有最终有效值由PROBE的effective_resources/effective_timeouts返回，不伪造设备实测来源。

## 4 request 与management输入

以下对象各自携带contract_version=1和指定document_type。secret/body是C ABI的独立bytes参数，不存在于JSON。metadata的namespace由灵润入口绑定；mock使用显式测试namespace，不将其当生产身份认证证明。

### 4.1 request

| 字段 | 必选性、类型与默认 |
| --- | --- |
| document_type | 必填，request |
| correlation_id | 可选，默认null；诊断标识 |
| namespace/profile_id | 必填identifier；profile必须在runtime配置与TA能力中 |
| credential_ref | 必填hex128 |
| expected_version | 必填u64字符串；不接受JSON number |
| operation | 必填CHAT/RESPONSES/MESSAGES/MODELS |
| response_mode | 必填json/sse |
| completion_policy | 可选，默认HTTP_COMPLETE；json/MODELS仅HTTP_COMPLETE |
| overall_timeout_ms | 可选，默认runtime.default_overall_ms；1..有效max_overall_ms |
| headers | 可选，默认[]；至多32个闭合{name,value} |

body_length、SHA-256、LSP标识和序号由native根据实际独立body bytes生成。MODELS body必须为空；其它operation要求完整JSON object，stream缺省false，对应json模式；stream=true对应sse。检查可解析性与stream意图时不重编码body，转发原始字节，保留合法业务浮点值和扩展字段。

正文检查须在本模块资源预算内进行，可采用有界扫描读取顶层stream意图；不得为32MiB正文无约束地物化另一棵JSON对象树。预算不足明确拒绝准入，不套用metadata的“禁止浮点”规则拒绝合法temperature等业务参数。

输入header name采用HTTP token字符集、1..256字符；value不得含NUL/CR/LF。拒绝Host、Authorization、x-api-key、Content-Length、Transfer-Encoding、Connection及Proxy-*（不区分大小写）。native生成LSP OPEN前还须检查实际wire metadata≤4096B，不能以本地8192B上限代替远端预算。

### 4.2 管理metadata

| document_type / C managementKind | 必填字段（除版本/类型） | 可选字段与默认 | 独立secret参数 |
| --- | --- | --- | --- |
| credential_put / PUT=1 | namespace、credential_ref、operation_id、profile_id、expected_version | correlation_id=null；temporary=false；overall_timeout_ms取runtime默认；temporary=true时ttl_ms必填 | 1..4096B UTF-8；不含NUL/CR/LF，不trim |
| credential_query / QUERY=2 | namespace、credential_ref | correlation_id=null；overall_timeout_ms取runtime默认 | 必须空 |
| credential_delete / DELETE=3 | namespace、credential_ref、operation_id、expected_version | correlation_id=null；overall_timeout_ms取runtime默认 | 必须空 |
| probe / PROBE=4 | 无 | correlation_id=null；overall_timeout_ms取runtime默认 | 必须空 |

operation_id/ref为hex128，expected_version为u64字符串。temporary=false禁止ttl_ms；true时1≤ttl_ms≤本地和TA有效TTL上限。同ref永久/临时属性不可切换。

共享的只是单飞admin worker。每个PUT/QUERY/DELETE/PROBE在dispatch时创建本项独占的TEEC context/session，Open/HELLO后立即执行一次该项管理操作，之后Close/Finalize；PROBE仅HELLO后关闭。不得保留跨人工输入等待的idle管理context，不新增HELLO lease字段。每项overall期限从准入开始，创建context前也检查剩余预算。

PROBE是本地SDK Open/HELLO能力查询组合，不新增LSP opcode。成功submit仅代表排队；管理结果必须等异步事件。cancel management不发送request-role的LSP CANCEL：未发queued操作可确定not_sent；inflight写可能提交，须按下节对账。

## 5 Event metadata

所有Event输出字段必填，默认值不自动添加。公共字段如下：

| 字段 | 类型与约束 |
| --- | --- |
| document_type/contract_version | event / 1 |
| event_type | response_head/body/management_result/terminal |
| operation_kind | request/put/query/delete/probe |
| correlation_id | 与输入规范化后相同，可能null |
| request_id | request时为native生成hex128；管理操作固定null |
| event_sequence | 正u64字符串，与C lsp_ca_event.event_sequence一致 |
| ticket | 正u64字符串，与C ticket一致；NACK重读同sequence但新ticket |

metadata中的sequence/ticket为了自描述而重复C字段，JNI必须核对一致。C header的kind映射为head=1、body=2、management_result=3、terminal=4；非BODY时stream_offset=0、flags=0、body_len=0。BODY时flags=HAS_STREAM_OFFSET、offset与metadata一致。metadata_len按实际紧凑UTF-8字节计算。

读取缓冲不足不返回这份完整Event，只返回C required lengths且ticket=0；不能构造一份ticket=0的伪Event JSON。JSON Schema验证不能代替C缓冲长度、ticket归属及序列检查。

### 5.1 response_head

增加http={status,headers}。status为200..599；headers为最多128个闭合{name,value}。仅request操作可以收到。HEAD无独立body bytes，HTTP头内容全部在metadata中。保留必要头；不把Header metadata记录到无约束日志。

PROBE及每个request HELLO都必须检查local.max_event_metadata_bytes ≥ TA.max_header_bytes + 768 B。768 B是此版本固定公共Event封套的保守编码预算，不是性能测量；初始TA header 4096 B、local metadata 8192 B满足该关系。不满足时明确报告配置/能力不兼容，不能丢头、截断或临时突破本地限额。实际编码后仍检查总UTF-8长度；超过预算视为协议/实现错误。

### 5.2 body

增加stream_offset（u64字符串）、byte_length（正u32）。实际bytes位于C输出body buffer，长度必须等于byte_length和C body_len；连续event的stream_offset按正文长度累加。不得逐块强制UTF-8解码，不在JSON内放base64副本。

### 5.3 management_result

增加result_type及result。

result_type=credential用于PUT/QUERY/DELETE；result字段沿用LSP闭合的credential_ref、namespace、state、version、profile_id、temporary、ttl_remaining_ms、receipt、replayed：
- state为absent/live/deleted/expired；version为u64字符串。
- absent时version=\"0\"，profile_id/temporary/ttl_remaining_ms/receipt为null、replayed=false。
- 永久记录ttl_remaining_ms=null；临时状态按LSP说明返回。
- receipt=null或{operation_id,operation=put/delete,committed_version}。
- QUERY不宣称重放，replayed=false；重复写操作先查末条receipt再CAS的语义不变。

result_type=capabilities仅用于PROBE。result是完整HELLO result（selected_version、role=management、capabilities、limits），另有effective_resources和effective_timeouts两字段，形状与runtime配置对应。profile能力与limits均为实际返回事实，不得拿初始工程配置伪装成TA声明。

管理失败不伪造一份absent result；它通过terminal报告错误。尤其QUERY存储读取失败不能按“对象不存在”处理。

### 5.4 terminal

增加terminal对象，所有字段必填：

| 字段 | 类型及职责 |
| --- | --- |
| outcome | completed/incomplete/provider_error/transport_error/cancelled/timeout/protocol_error，粗粒度上层结论 |
| local_error | null或{status,stage}；status为C ABI负错误码-12..-1，stage为admission/allocation/codec/delivery/shutdown/internal |
| sdk_transport | {state,phase,result,origin}；state=not_started/ok/error/unknown；result为u32或null，origin为1/2/3/4或null；phase=none/connect/handshake/open/invoke/close/finalize/abort |
| lsp | null或最后确定的{status,name,stage,state,retry}；status/name必须与注册表一致，retry为null或none/resize_only/new_request_only/reconcile_management |
| http_status | null或200..599；非2xx不能为completed |
| network_error_code | null或dns_failed/connect_failed/connect_timeout/read_failed/write_failed/reset/idle_timeout；CA实际网络故障事实，不能由TA错误名猜测；管理操作固定null |
| model_outcome | null或completed/incomplete/provider_error/protocol_error；与整体取消或交付失败分开 |
| model_stop_reason | null或1..128可见ASCII；保留受限输出、工具调用等停止原因 |
| transport_snapshot | null或LSP TA terminal完整快照，不伪造app_resources/manager状态 |
| delivery | {body_bytes_emitted,body_bytes_confirmed,body_bytes_dropped,evidence}；计数为u64字符串，confirmed+dropped≤emitted；evidence=confirmed/unknown_after_lease_expiry/detached |
| cleanup | {local,remote}；local=live/requested/sdk_closing/local_released/stalled；remote=not_asserted/pending/confirmed/unknown |
| management_commit_state | C ABI管理提交状态的精确字符串映射，见第6节 |
| management_remote_commit | null或committed/not_committed/unknown；远端写入事实，不能与本地cancel混为一谈 |
| reconciliation | null或{operation_id,credential_ref,expected_version,receipt}，只包含非秘密对账数据 |
| side_effect_state | not_sent/possibly_sent/response_observed；涉及服务商或可信端写入时保守记录 |

TA terminal形状与LSP完全一致：end_reason、http_framing、tls_phase、close_notify_received、request_application_bytes_generated、emitted_http_body、app_resources=\"released\"、manager_cleanup=\"not_asserted\"。只有收到真实快照才填写，否则null。

SDK result=0不能覆盖LSP业务错误；LSP OK不能覆盖HTTP错误；HTTP200不能证明模型完整；模型完成也不能覆盖交付失败或cancel。cleanup是事件创建时的快照，后续operation_get_info可以显示新清理状态，但不会重复发送或改写已交付Terminal。

正常Terminal须在已承诺正文ACK栅栏之后。readEvent成功仅表示取得事件；ACK_DELIVERED必须等Java串行适配器实际把正文交给约定消费者。JNI复制或任意Handler.post不算消费。lease失效后的confirmed是已确认下界，evidence必须体现未知，不虚构精确完整交付。

## 6 提交事实与错误域映射

### 6.1 C状态与JSON状态

| C management_commit_state | JSON字符串 | management_remote_commit | 含义 |
| --- | --- | --- | --- |
| 0 | not_applicable | null | 普通请求、QUERY、PROBE |
| 1 | not_sent | null | PUT/DELETE在进入远端调用前退出，确定未发 |
| 2 | unknown | unknown | 已进入写入路径，无法确定提交结果 |
| 3 | committed | committed | 有对应operation_id的已提交receipt |
| 4 | not_committed_confirmed | not_committed | 本次调用未新增提交：确定的预提交拒绝或权威复读确认 |

PUT/DELETE的reconciliation始终带operation_id/ref/原expected_version；committed时receipt必须非null且operation_id匹配。其它操作的reconciliation固定null。

远端新增E_STORAGE_NOT_COMMITTED=0x1207表示明确未提交，retry=none；映射not_committed_confirmed。E_STORAGE并带reconcile_management用于提交不确定，映射unknown。QUERY读取失败为E_STORAGE/retry=none，不返回absent。写入进入持久化后的异常由TA按存储设计readback判断，CA不根据网络错误自行猜测未提交。

共享admin worker单飞，每项操作独占新context/session。中止inflight写不代表回滚。出现unknown后，只有原管理SDK调用/worker已实际退出、单飞执行槽可用，才以新context执行只读QUERY探测同ref；远端提交未知与本地worker静止是两个独立条件。原worker仍STALLED时不得另开admin worker/context绕过名额，未开始的队列继续按原deadline收敛；若E_BUSY表示存储栅栏未退出，暂停发送尚未开始的后续PUT/DELETE。队列中从未发送的Key仍计入有界预算、沿用原overall deadline，到期清零并报timeout/not_sent。后续只读QUERY允许执行；探测无E_BUSY且可信管理服务正常响应后才恢复未开始的写，仍用原expected_version，不自动改CAS条件。QUERY非E_BUSY错误若不能证明栅栏已退出，继续暂停而非猜测可写。原写结果未知后立即禁止将Key用于重试，清理已无借用的副本；仍由inflight SDK/FFI持有的缓冲必须由原worker在确认无引用后擦除，控制线程不得提前清零或free。STALLED期间仍持有的secret继续计入预算，只保留必要的活跃调用所有权，不作为后台重试缓存；非秘密元数据用于对账，不自动重放；QUERY成功也只有匹配receipt等证据才可确认历史提交，普通当前版本不足以消除unknown。QUERY absent仅证明当前不可用；Java可记录RESOLVED_UNAVAILABLE并解除配置绑定，原写仍unknown，不自动复用ref重发。需重新预设时通过显式输入获取Key。

### 6.1.1 确定的预提交拒绝

以下映射仅针对本次PUT/DELETE：SDK Invoke确定成功，完整业务回复的长度、opcode、epoch/nonce、请求关联和call_seq均已校验，且stage/state满足下表。表中错误只能在该次管理写进入StorageWorker之前返回；进入持久化后不能借这些错误码跳过readback，必须返回committed、明确复读的0x1207或unknown/E_STORAGE。

| stage | channel state | 允许的有限状态集合 | management_commit_state |
| --- | --- | --- | --- |
| wire | HELLO_READY | E_WIRE_FORMAT | not_committed_confirmed |
| credential | HELLO_READY | E_ROLE、E_STATE、E_CREDENTIAL_NOT_FOUND、E_VERSION_CONFLICT、E_OPERATION_CONFLICT、E_PROFILE_DENIED、E_CREDENTIAL_REVOKED、E_BUSY、E_LIMIT | not_committed_confirmed |
| credential | HELLO_READY | E_STORAGE_NOT_COMMITTED且retry=none，来自权威复读 | not_committed_confirmed |

对应management_remote_commit均为not_committed。版本冲突、同ID内容冲突和额度拒绝不是提交未知；保留原错误以便调用方查询或修正输入，不自动重放Key。

**“本次调用未新增提交”不等于“该operation_id的所有历史尝试均未提交”。** 同ID更早的未知尝试可能已提交且末条receipt被后续操作覆盖。新的CAS拒绝仅说明当前attempt没有写入，不能据此消除历史unknown。每个native operation handle保存本次调用事实，历史事务仍需凭receipt/版本证据对账。

E_OUTPUT_CAPACITY没有普通LSP回复帧，不能套用上述JSON映射。只有同步SDK/GP调用确定成功、p1.size=0、p2.a=E_OUTPUT_CAPACITY、p2.b=32768、且本次实际提供的p1容量小于32768等无副作用分支全部验证后，才能在无法resize或调用被取消时记本次not_committed_confirmed。正常路径仍可按LSP约定同seq扩容重试一次。实际已提供完整容量却收到该错误、GP失败或输出不一致时，视为协议/结果不确定，不能猜测未提交。

E_INTERNAL、E_DEADLINE、错误epoch/nonce/sequence/request关联、截断帧以及SDK当前Invoke结果未知，均不能仅凭状态名字推断未提交。此时management_commit_state=unknown；未验证的业务数据不进入terminal.lsp。只有写调用明确尚未发出才用not_sent。

terminal.lsp用于管理写时，必须属于本次PUT/DELETE的已验证回复，不能引用其它管理操作或本次HELLO的旧结果。若已得到确定结果后才在Close/Finalize/清理abort中出错，保留先前结果并更新cleanup，不降级或伪造提交事实。辅助检查中的commit_evidence仅是验证器的测试前置事实，不是Java可注入的metadata或身份声明。

### 6.2 错误映射原则

规范性完整状态映射、三协议JSON/SSE终态表及致命错误优先规则见[CA outcome/Observer合同](ca-outcome-observer-v1.md)。下表是摘要；不能依靠“一般”类别自由选择实现。网络阶段connect_timeout/idle_timeout经STEP(network_error)报告，并保留network_error_code映射timeout；总体/消费者期限经CANCEL(timeout)，不伪造网络故障。

| 情况 | 表达方式 |
| --- | --- |
| 入参/handle/缓冲错误 | C ABI同步localStatus；尚未准入则没有operation和异步事件 |
| readEvent WAIT_TIMEOUT/BUFFER_TOO_SMALL | 仅本地读取状态，不取消请求、不宣称上游错误 |
| SDK连接/Invoke失败或回复未知 | Terminal.sdk_transport保留code/origin/phase；无先到期限/取消时outcome=transport_error |
| LSP格式/状态/版本拒绝 | Terminal.lsp保留原状态；outcome=protocol_error；不与SDK成功混淆 |
| LSP存储/可信服务操作失败 | 保留LSP详细状态与提交事实；上层粗类可用transport_error表示后端操作未完成，不能丢失其实际LSP层原因 |
| TA OPEN返回确定的E_BUSY | 保存status/name/stage/retry，side_effect_state=not_sent；这可能是全局snapshot写或TA自身额度竞争，属于未接管请求的确定拒绝，不是SDK结果未知；不得盲重放Invoke，后续重试须走明确的新请求准入策略 |
| HTTP非2xx | HTTP层结论provider_error；保留response_head和已接管的有界原始body；若同时已知致命传输/协议错误按Observer优先规则结束，不承诺错误前排空TA pending |
| 模型failed/incomplete | model_outcome与停止原因分别保留，不能改成TCP错误 |
| 本地cancel/timeout | 对外cancelled/timeout，保留已经知道的model与管理提交事实 |
| consumer lease撤销/回调迟到 | delivery.evidence=unknown_after_lease_expiry，确认字节是下界；不阻塞native回收 |
| SDK/manager清理未知 | cleanup.remote=unknown或local=stalled，不谎称released |

shared admin worker属于runtime；每项management operation自己的context/session、结果缓冲及worker引用全部结束后才可operation_release。释放操作不销毁共享调度worker。请求也各自独占context/session。RuntimeHolder为进程级单例；Service重建只重新attach，onDestroy只detach其消费者，不shutdown整个runtime；STALLED时拒绝绕过旧对象创建新runtime。具体规则见JNI生命周期第8节。

## 7 交接与联调退出条件

| 里程碑 | CA/Java负责人 | TA负责人 | 联合退出条件 |
| --- | --- | --- | --- |
| LC0 本地合同冻结 | 实现严格parser、默认填充、C/JSON映射与mock入口 | 核对转为LSP的字段和提交状态含义 | 正负样例双方理解一致；没有隐含字段或错误域合并 |
| LC1 单方开发 | fake TA +真实native事件队列、JNI copy/ticket、取消 | fake CA +真实TA dispatcher/存储/pump | 不依赖另一方完整实现即可跑契约用例，未知结果不自动重放 |
| LC2 本地双端联调 | SDK封装、profile匹配、完整body分块、observer | 项目manager、TA会话、HTTP/TLS、resource admission | HELLO/管理/OPEN/STEP/FINISH和错误映射对齐；不是只验容器 |
| LC3 并发与恢复 | 双请求、慢消费者、ACK/NACK、SDKabort、Java close | 配额、取消、owner cleanup、TTL/持久化故障 | 真实双请求不串；cancel不杀进程；管理unknown可对账；清理边界有证据 |
| LC4 真实DeepSeek | mock或后续真实灵润按同一API驱动 | 真实TA服务 | 三协议+模型目录、非流式/流式、错误/结束语义完成；身份增强另列，不冒充已完成 |

初始参数只在相应设备压力和故障测试后调整冻结。不能用通过JSON Schema代替状态机、TLS、JNI内存生命周期或设备容量验收。没有达到资源回收硬期限能力时，明确保留STALLED/unknown退出条件，而不是释放仍运行的worker。

## 8 校验材料

本轮脚本与结果位于 ../../artifacts/cursor-opus55-review-20261113-005109/ca-check/；旧结果保留在 functional-design-completion-20261112，不能拿旧计数说明新合同通过：
- generate-local-contract-schema.py：生成schema的设计辅助脚本。
- check-local-contract.py：标准JSON Schema加跨字段/缓冲映射检查。
- local-contract-positive-examples.json：使用假Key的正向输入/输出样例。
- local-contract-negative-results.json：负向拒绝结果。
- local-contract-check-result.json / local-contract-check.log：检查数量和范围。
- local-contract-check-dependencies.txt：jsonschema 4.25.1及实际依赖版本。

执行：

    artifacts/functional-design-completion-20261112/local-contract-venv/bin/python \
      artifacts/cursor-opus55-review-20261113-005109/ca-check/check-local-contract.py

仅在artifact内使用临时venv，没有安装系统Python环境。样例不是生产实现；没有运行SDK、设备、真实存储或模型调用。所有假Key都以FAKE标记，真实Key不得放入这些文件。
