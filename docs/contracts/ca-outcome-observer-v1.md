# CA outcome 与三协议 Observer 合同 v1

状态：2026-11-13功能设计，供两端独立实现；不是运行测试通过声明。配套[本地合同](ca-local-contract-v1.md)、[JNI生命周期](ca-jni-lifecycle-v0.1.md)。Observer只检查服务商响应的完成语义；原始HTTP body逐字节保留，不改写模型输出，不执行工具，不自动重试生成。TA不负责这些业务语义。

## 1 事实来源与两层终态

本表的服务商字段和值以2026-11-13读取的DeepSeek官方资料为基线；到本项目outcome的映射、严格性和容量上限是本项目决定，不能称为服务商的错误分类。官方支持的字段见[Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/)、[Responses](https://api-docs.deepseek.com/api/create-response/)、[Responses流式指南](https://api-docs.deepseek.com/guides/responses_api/)及[Messages](https://api-docs.deepseek.com/zh-cn/api/create-message/)。其中Chat的aborted和Messages的refusal已在当前官方枚举中；下表不将其它厂商同名接口的枚举推测为DeepSeek支持。

Observer记录model_outcome候选；closure coordinator独占最终Terminal提交权。model_outcome只有null/completed/incomplete/provider_error/protocol_error，对应C的0/1/2/3/7。整体outcome可以另为transport_error/cancelled/timeout。get_info的C model_outcome禁止4/5/6，JSON未知为null，不用字符串undecided。

准入成功不代表远端成功。HTTP200、TLS关闭、TA REQUEST_END、SSE收到若干文字或服务商usage均不能独自证明模型完整。JSON模式必须有HTTP完整边界和一个完整合法响应对象；SSE需相应协议结束事件。上层正常Terminal还须经过已承诺BODY的Java消费ACK栅栏。

## 2 确定的错误映射

先验证SDK/GP结果、帧长度、关联/序号及业务回复形状。未验证的回复不填terminal.lsp；关联/容器损坏为protocol_error，SDK传输结果未知为transport_error。管理提交unknown另按本地合同保存，不能由此outcome猜测提交是否发生。

下表覆盖当前注册表全部LSP状态。异常分支是本次操作的首要失败时采用该映射；已经线性化的用户取消/期限或已提交Terminal按第4节处理。

| LSP状态 | 本地outcome或动作 |
| --- | --- |
| OK | 无单独终态；管理成功result后completed，普通请求由HTTP/Observer/消费栅栏判定 |
| E_OUTPUT_CAPACITY | 仅已验证的无副作用GP分支允许同seq扩容一次；仍不成立或无法恢复为protocol_error；管理提交事实另判 |
| E_WIRE_FORMAT、E_VERSION、E_ROLE、E_STATE、E_STALE_EPOCH、E_SEQUENCE、E_REQUEST_ID | protocol_error |
| E_CREDENTIAL_NOT_FOUND、E_VERSION_CONFLICT、E_OPERATION_CONFLICT、E_PROFILE_DENIED | protocol_error，保留具体LSP状态，不自动修正版本或重放 |
| E_CREDENTIAL_REVOKED | 已绑定request且真实TA terminal.end_reason=revoked时cancelled；准入/管理拒绝时protocol_error |
| E_STORAGE、E_STORAGE_NOT_COMMITTED | transport_error；原始LSP状态和管理提交事实分别保留 |
| E_BUSY | transport_error；已验证OPEN拒绝的side_effect_state=not_sent；管理预提交拒绝为not_committed_confirmed |
| E_LIMIT、E_BODY_LENGTH、E_BODY_OFFSET、E_BODY_DIGEST、E_HTTP_PARSE、E_HTTP_LIMIT | protocol_error |
| E_TLS | transport_error |
| E_NETWORK | CA已记录connect_timeout或idle_timeout时timeout，否则transport_error |
| E_DEADLINE | timeout |
| E_INTERNAL | transport_error |

terminal.network_error_code是CA自己已知的上游网络输入分类，值仅dns_failed/connect_failed/connect_timeout/read_failed/write_failed/reset/idle_timeout或null；不是TA或SDK服务端的诊断报告。没有本地事实不得从E_NETWORK猜具体原因。网络连接/停滞期限通过STEP(network_error)报告；总体或消费者期限通过CANCEL(timeout)，network_error_code保持null（除非此前确有网络故障）。普通SDK Invoke失败不伪造该字段。

完整关联、已绑定请求的业务错误必须有progress。致命首次转移只有REQUEST_END与terminal，不能同帧夹带HTTP_BODY/NET_TX；后续错误保留terminal快照且events为空，非致命错误progress.events为空且terminal=null。格式/关联和未绑定OPEN/STATUS错误progress=null；STATUS只查询，不产生REQUEST_END。违反这些规则按protocol_error，不用不可信progress更新计数。

TA end_reason与整体结论独立：consumer_complete/response_consumed是资源释放原因，不自行证明模型成功；cancelled遵守本地取消原因，deadline→timeout，revoked→cancelled，transport_error/internal_error结合已验证LSP与SDK事实映射。不存在end_reason=http_complete；HTTP_COMPLETE仍是合法状态，framing=complete仍是合法事实。

## 3 业务观察规则

### 3.1 共用解析边界

Observer消费CA已接管的原始HTTP_BODY副本，流偏移连续。跨分片UTF-8、JSON转义、SSE行/空行边界由增量解析器处理，不能逐块强制解码。允许合法业务JSON浮点值，不复用metadata禁止浮点/8层规则。响应JSON重复对象key、非法UTF-8、非法JSON或协议终态相互矛盾均为protocol_error。非终态未知扩展字段/事件可保留而不解释，但未知终态值不能升级为成功。

固定首版工程上限：单个非流式响应JSON 4MiB、单个SSE事件1MiB、单行1MiB、JSON嵌套64层、并行内容块128、Chat choice一个(index=0)。这是Observer构建配置，非服务商限制或性能实测；计入native总预算，更新须同步配置/fixture，不由Java任意放宽。超限明确protocol_error，不截断后报成功；不要求为所有SSE累计正文保留完整副本。Chat多choice响应首版明确不支持，不能悄悄只取第一个。完整HTTP_END之前的EOF/缺结束标记和已验证TLS截断分别按下表/传输错误处理。

HTTP非2xx优先记录provider_error候选，保留HEAD和已接管原始body，不要求正文符合成功schema。默认HTTP_COMPLETE及无合法模型终态的MODEL_TERMINAL均等HTTP_END和消费栅栏后提交该候选；明确error事件则可按失败路径立即启动清理，不要求继续读取无限错误正文。若后续观察到致命传输/编码错误，第4节失败优先。合法2xx但错误对象而非成功信封→provider_error；含error且同时声称成功的矛盾信封→protocol_error。纯空白/空对象不证明成功。

### 3.2 Chat Completions（CHAT）

官方finish_reason已列出下列六种，本项目采用如下固定映射。自然停止或工具调用仅表示这一轮生成完成；工具执行成功与内容是否满足用户需求由上层判断。[官方接口](https://api-docs.deepseek.com/api/create-chat-completion/)

| finish_reason | model_outcome | model_stop_reason |
| --- | --- | --- |
| stop、tool_calls | completed | 原值 |
| length、aborted | incomplete | 原值 |
| content_filter、insufficient_system_resource | provider_error | 原值 |
| 未知字符串、JSON终态null/缺失 | protocol_error | 合法可见ASCII且≤128B则保留，否则null |

JSON：合法chat.completion对象，非空id、choices恰有index=0项和message object，finish_reason为上述非null值；等待HTTP完整后锁存。SSE：验证chat.completion.chunk及同一id，非空choices的index只能0；正常content chunk的null reason仅继续；已知非null reason先暂存，只有后续独立`[DONE]`才形成候选，且两者之间无错误或相互冲突reason。usage-only空choices可忽略；单独`[DONE]`为protocol_error，HTTP完整但缺`[DONE]`为incomplete。错误对象（有或无event:error名称）立即provider_error，不等待`[DONE]`。

### 3.3 Responses（RESPONSES）

官方JSON状态包括in_progress/completed/incomplete/failed；SSE结束事件为response.completed/response.incomplete/response.failed，无`[DONE]`，sequence_number递增。[官方接口](https://api-docs.deepseek.com/api/create-response/)、[流式指南](https://api-docs.deepseek.com/guides/responses_api/)

| JSON status / SSE最终event | 必要条件 | model_outcome / stop reason |
| --- | --- | --- |
| completed / response.completed | object=response、非空id、output array；error与incomplete_details均null；event及嵌入status一致 | completed / completed |
| incomplete / response.incomplete | 同上基本信封，error=null；incomplete_details.reason=max_output_tokens或content_filter | incomplete / 原reason |
| failed / response.failed | 同上基本信封；error为有code/message的对象 | provider_error / failed |
| in_progress直到HTTP完整结束 | 没有协议终态 | incomplete / null |
| 未知status/未知incomplete reason、event与status矛盾 | 不推测新增语义 | protocol_error / 合法有限原值或null |

JSON等待HTTP完整；SSE验证type与event名称一致、sequence_number为非负整数且严格递增、response id一致后可在完整最终event锁存。中间output_text.done/工具块done不是整个response完成。`[DONE]`在此协议属于protocol_error。SSE错误对象或显式error事件按provider_error保守失败；这条是本项目防御策略，不声称官方承诺所有这类错误event。EOF未见最终event且HTTP framing已完整→incomplete；传输不完整仍为transport_error。

### 3.4 Messages（MESSAGES）

当前官方stop_reason含end_turn/max_tokens/stop_sequence/tool_use/refusal/null；SSE message_start先带null，message_delta给最终原因，message_stop结束。官方说明超时时可能返回无event名称但包含error的data，未见message_stop的流不完整。[官方接口](https://api-docs.deepseek.com/zh-cn/api/create-message/)

| 最终stop_reason | model_outcome |
| --- | --- |
| end_turn、stop_sequence、tool_use | completed |
| max_tokens | incomplete |
| refusal | provider_error（本项目分类） |
| 未知、终态null或缺失 | protocol_error |

JSON要求type=message、非空id、role=assistant、content array，HTTP完整后按reason锁存。SSE检查event名称与JSON.type一致、message_start唯一及同id、内容块index合法且start/stop成对；message_delta暂存reason，message_stop到达且所有已开始块关闭后才锁存。ping、注释不完成请求；`[DONE]`非法。无message_stop但HTTP完整→incomplete；message_stop缺最终reason/存在未闭合块→protocol_error。无名error对象或error事件→provider_error；前者有官方依据，后者为防御兼容策略。tool input fragments保留原样，不因单段未构成JSON判错，不执行工具。

### 3.5 MODELS

仅HTTP_COMPLETE、JSON模式。2xx完整body须为object=list且data数组中每项具有非空id；完成时整体completed、model_outcome/model_stop_reason=null（它不是模型生成）。非2xx为provider_error，非法/超限JSON为protocol_error。

## 4 优先级、交付与提前关闭

每operation在短锁下记录终止控制的线性化序号。正常候选只在所选HTTP/MODEL策略、已接管正文消费栅栏全部满足且没有失败/取消胜出时提交Terminal。已提交Terminal不重写；其后仅更新清理状态。cancel/timeout若先被接纳则禁止正常完成；已提交终态后cancel返回ALREADY且不反转。多个取消/期限保留首个已接纳原因。因错误触发的内部cleanup CANCEL不能把原先provider/protocol/transport错误改成用户cancelled。

致命错误一旦观察到就锁定失败，优先于尚未提交的正常候选；不为了排空TA pending而继续生产正文/网络事件。TA丢弃的pending不能加入emitted计数；CA已接管bytes维持原offset，允许报告部分交付，禁止伪造完整确认。未lease的数据可丢弃并记dropped，已lease给Java的数据保留到ACK/原lease或显式close；Terminal投递不能越过已开始的BODY callback，native清理不等任意Java回调结束。若强制detach/lease撤销，confirmed仅为下界并标delivery uncertain。

MODEL_TERMINAL仅SSE，在完整合法协议终态已确定completed/incomplete/provider_error后可FINISH(consumer_complete)提前释放，FINISH本身不是模型成功声明。无合法终态的错误对象、protocol_error或传输故障走清理取消，保留原始失败outcome。TA提前关闭不会凭空产生未观察到的未来故障。若另一执行次序先观察到TLS/HTTP致命错误，即使TA pending里含末尾标记也不能改为成功。这两条路径可能因背压/调度产生不同outcome；不得承诺消费者速度不影响“提前关闭”和“观察后续fault”的竞争。HTTP_COMPLETE则必须等HTTP_END及全部已承诺BODY交付；HTTP_END不能越过body。

## 5 受控上游测试profile隔离

| 构建用途 | 固定允许profile / 上游 | Key与信任根 |
| --- | --- | --- |
| 产品或mock驱动真实链路 | deepseek-prod-v1 / 官方api.deepseek.com | 用户显式预设Key；产品根；mock只是上层替身 |
| 受控故障注入测试构建 | lsp-test-fixture-v1 / https://lsp-fixture.test:18443，SNI=lsp-fixture.test，ALPN=http/1.1 | 只接受有限fixture Key集合FAKE-LSP-KEY-A、FAKE-LSP-KEY-B；只信任隔离测试根 |

测试profile沿用四个operation的产品路径及auth方式，只替换固定测试origin/端口/信任根；无redirect或任意override。测试DNS由受控网络把lsp-fixture.test解析到fixture server，TA仍校验固定SNI与测试根。F3实施前生成隔离测试CA，在构建清单冻结根证书SHA-256、证书DNS SAN、server地址、四路径及允许假Key；建议证书源位置fixtures/trust/lsp-test-root.pem（待实现创建，不声称当前存在）。测试私钥仅fixture server持有，不编入CA/TA。

测试CA、TA和fixture server通过HELLO确认测试能力，采用专用namespace和credential ref。v0.6的生产提供商配置通过CREDENTIAL_PUT保存HTTPS前缀与类型，并与凭证版本和请求快照绑定。生产TLS使用其正常证书验证配置。受控fixture使用专用测试根和固定假凭证，服务器仅记录假Key匹配、长度和offset。身份进一步加固沿用后置安排。

离线模型/Schema通过不代表受控TLS、JNI、SDK abort、TA装载或DeepSeek真实调用通过；上述项目分别保留实现门禁。
