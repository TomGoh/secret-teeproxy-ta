# SDK 与项目 manager 生命周期设计 LSP 后端 v1

状态：功能设计草案，接口与状态行为供实现；不是已经存在的SDK能力。适用于灵润APK/:runtime内的CA模块，以及隔离的lsp-manager和LSP TA runtime。设备kernel.bin保持固定，旧GP manager及Trusty服务不修改。身份增强另行处理，本稿不扩展签名方案。

## 1 决定与边界

1. 每个CA请求worker独占一个SDK context/session，管理会话独立。正常取消执行有界业务CANCEL；正在等待SDK调用时可通过调用锁外的transport abort终止连接。
2. 每次逻辑SDK调用使用一个绝对单调deadline，覆盖入队、connect、ECDH/TLS、写入、分片与完整响应；每次底层I/O重算剩余时间，不按阶段重置。
3. abort仅表示已请求中止，worker必须实际返回并join后才能释放其配额和模块引用。无法结束则STALLED/QUARANTINED，不能杀灵润进程或错误释放仍被线程引用的对象。
4. 每个认证VSOCK连接具有独立OwnerKey，不能使用共享的host CID或客户端自报ID作为owner。
5. manager代理I/O结束不代表TA代码结束。正常Close只有TA runtime的worker join证明及本地forward drain共同满足才解绑成功。generation故障由TEE内lsp-supervisor直接持有manager/TA的Child并负责退出/reap；manager不再spawn/reap TA。整实例退出可以证明资源不再活动，但不能把失败中的GP Close伪装成成功。
6. 旧内核不支持新私有572 deadline；不依赖它强杀Invoke。不可协作的TA callback进入隔离状态，保留配额与引用；普通单请求cancel不能杀共享TA、旧manager或整个VM。
7. 项目manager/runtime增加有限的私有生命周期通道处理Open交付未知、Release和join回执。外部GP wire与LSP/1业务帧不因此改变。

## 2 SDK API与socket所有权

以下typed Rust接口是拟新增扩展，现有GP入口不静默改变含义。JNI内部通过这些接口使用SDK，不向业务App暴露raw fd。

```rust
struct Endpoint { cid: u32, port: u32 }
struct Deadline(std::time::Instant); // 绝对值仅在本进程使用
struct CallBudget { deadline: Deadline }
enum AbortReason { Cancelled, CallDeadline, HostShutdown, TransportFailed }
struct OpenOptions { ta_uuid: [u8;16], connection_method: u32 } // v1 GP Open无业务params

struct ContextOptions {
    endpoint: Endpoint,
    max_frame_bytes: usize,
    limits: TransportLimits,
}
struct TransportLimits {
    sdk_connect_open_ms: u32,
    sdk_connect_ms: u32,
    sdk_handshake_ms: u32,
    sdk_call_budget_ms: u32,
    sdk_graceful_close_ms: u32,
    worker_reap_grace_ms: u32,
}
struct AbortHandle { inner: std::sync::Arc<AbortCell> }
struct AbortCell {
    aborted: std::sync::atomic::AtomicBool,
    // 仅短时guard，不是Invoke/TLS锁；禁止在此锁内进行数据读写或等待。
    socket_dup: std::sync::Mutex<Option<std::os::fd::OwnedFd>>,
    wake_fd: std::os::fd::OwnedFd,
}
struct WorkerConnection { /* !Sync；仅所属worker操作TLS和Context */ }
enum Delivery { NotSent, MayHaveExecuted, CompleteReply }
enum WorkerState { Running, Aborting, Joined, Quarantined }
enum SdkErrorKind { Cancelled, TimedOut, Transport, Protocol, Rejected }
struct SdkError { kind: SdkErrorKind, delivery: Delivery }

fn prepare(options: ContextOptions, stop: StopToken)
    -> Result<(WorkerConnection, AbortHandle), SdkError>;
fn connect_and_open(worker: &mut WorkerConnection, open: OpenOptions, budget: CallBudget)
    -> Result<Session, SdkError>;
fn invoke(worker: &mut WorkerConnection, session: &mut Session,
          command: u32, params: &mut Parameters, budget: CallBudget)
    -> Result<Reply, SdkError>;
fn close_and_finalize(worker: &mut WorkerConnection, session: Session,
                      grace: CallBudget) -> Result<CleanupReport, SdkError>;
impl AbortHandle { fn abort(&self, reason: AbortReason) -> AbortAccepted; }
fn poll_reap(worker: &mut WorkerHandle) -> WorkerState;
```

prepare在worker线程内执行：先创建nonblocking/CLOEXEC socket和dup句柄，再注册abort handle，之后才connect。协调器在prepare完成前收到取消时设置StopToken；worker在创建前、注册后及每次I/O前检查它，避免无abort句柄的连接窗口。

socket_dup持有相同open-file-description的独立OwnedFd。abort将aborted原子置位、唤醒eventfd，并在专用短guard内对dup执行shutdown(SHUT_RDWR)。它不关闭worker原fd，不操作TLS对象，不等待Invoke mutex。guard保证shutdown期间该dup不会被取走；worker结束时在同一短guard内take掉dup。后续abort只看到None或aborted，不对记录过的裸整数fd操作。即使原fd数字已被新连接复用，dup仍指向旧socket，不会中止新连接。

dup使用F_DUPFD_CLOEXEC或等价原子CLOEXEC复制；eventfd使用EFD_NONBLOCK|EFD_CLOEXEC。abort是幂等请求，首次atomic swap负责唤醒，eventfd已有待处理通知导致WouldBlock时仍视为已通知；不能在abort路径因重复write等待eventfd空间。shutdown错误单独记录，aborted标志仍然生效；返回AbortAccepted不代表已经唤醒所有平台I/O或完成join。

worker拥有TLS/context/session的drop顺序。强制abort后context永久失效，不发送另一条业务命令或尝试重新握手。正常关闭可在单独graceful-close预算内发送业务FINISH/CANCEL、GP Close及TLS close_notify；预算耗尽即shutdown，不能在析构中无限等待close_notify。

graceful-close从进入清理时起共15000ms且不可重置；其中业务FINISH/CANCEL仍取min(普通sdk_call_budget_ms,grace剩余)，**GP CloseSession只取grace剩余，不再套普通5秒Invoke cap**，Finalize/TLS close_notify也消耗同一剩余值。前序清理耗时过长仍可能让Close结果未知，但不能人为把本可等待8秒的Close硬截为5秒。cleanup_observe_ms不改变该预算。

CA对外业务终态和cleanup状态分开：abort/timeout可先通知上层，cleanup仍为pending。只有worker完成并join后才released；超过reap grace则QUARANTINED，继续保留JoinHandle、buffer和native模块引用并计入有限配额，不准卸载.so或复用该对象。无需阻塞全局服务线程等待join。

## 3 从virga到底层的统一预算

固定virga0.1.1当前在XTransportHandler::connect中阻塞连接VsockStream，并try_clone给XTransport；read_exact/分片重组的循环没有统一deadline。不能只给mbedtls设置5000ms读取超时就认为改造完成。

选择给XTransport的inner stream引入DeadlineSocketIo，保留其包格式、分片与CRC规则：
- worker持有唯一mutable协议状态；所有socket读写经nonblocking fd + ppoll/poll。
- connect的EINPROGRESS、xtransport包头/包体/ACK（若启用）、SM2协商、TLS握手、TLS应用数据、TEEC响应前缀/正文共用当前CallBudget。
- 每次短读/短写/EINTR/WouldBlock后重新读取同一绝对deadline和abort标志。
- poll同时等待socket和wake_fd；abort先检查，不再消费或发布新业务结果。deadline到期返回Timeout，不启动新的相对超时。
- 超时/中止是fatal context状态；即使随后收到完整响应，也不能作为已取消调用的新成功回调。
- virga错误类型保留Cancelled/TimedOut/UnexpectedEof，不能全部格式化成Other字符串后让上层猜错误。
- TLS密码运算及callback为有限工作量，但不是可抢占实时任务；检查其前后deadline。超时后的CPU卡死仍按QUARANTINED处理，不能承诺严格墙钟时限内线程消失。

逻辑预算从CA调度入队时产生。connect/open是一轮总预算：D_open=min(请求总体deadline, 开始连接时刻+sdk_connect_open_ms)。connect、ECDH/TLS、GP Open分别取min(D_open剩余时间, sdk_connect_ms/sdk_handshake_ms/sdk_call_budget_ms)，因此不是把子阶段cap累加。后续每个Invoke取min(请求总体剩余预算,sdk_call_budget_ms)。正常完成后下一次Invoke可有新budget，不能在同一Invoke内部重置。剩余0直接失败，不传0给含有“无限超时”含义的底层API。

Delivery只做保守分类：尚未写任何本次命令字节可以NotSent；一旦可能送达即MayHaveExecuted；完整回复通过GP和LSP校验后才CompleteReply。失败或结果未知不自动重放Open/Invoke。生成请求失败后不重新调用DeepSeek；管理写按业务receipt另行对账。

## 4 manager owner模型

采用直接迁移内部字段，避免Option<u32>的None==None把所有VSOCK连接混成一个owner：

```rust
struct OwnerId { manager_epoch: [u8;16], conn_seq: u64 }
enum SessionOwner {
    Vsock(OwnerId),
    KernelControlPid(u32), // 若保留控制面源码，仍是不同命名空间
}
struct OwnerEntry {
    id: OwnerId,
    phase: AliveOrClosing,
    pending_open: Option<PendingOpen>,
    sessions: Set<SessionKey>,
    channel: AbortHandle,
}
struct SessionKey { instance_epoch: [u8;16], local_id: u32 }
enum ManagedSessionState {
    Open,
    Closing { claim_id: u64, close_sent: bool },
    Quarantined { claim_id: u64 },
    Released,
}
```

project endpoint只构造Vsock owner；不得保留LegacyUnowned兜底。peer CID仅诊断，不参与owner授权。OwnerId由manager分配，manager_epoch启动改变，conn_seq不回绕。项目v1每个连接仅允许一次GP Open；管理连接也只开一个session。第二次Open必须新建context/连接。

v1的一个lsp-manager只管理一个配置固定的LSP TA实例域；不在运行期间把同一owner迁移到别的实例。instance_epoch另行参与SessionKey和所有生命周期消息。连接握手失败不产生已绑定owner；BIND的seq可以有空洞，但在该唯一有序控制流中必须严格递增。新实例或manager重启必须改变对应epoch，不继承旧连接或local session ID。

将dispatcher RequestContext.owner_pid和SessionBinding.owner_pid改为SessionOwner；Open登记、Invoke/Close比较、owner索引和清理都按enum完整值处理。现有KernelControlPid语义不冒充VSOCK所有权；项目版本禁用不需要的kernel控制监听，不要求80e内核迁移新inter-TA协议。

所有owner→session登记与owner Alive检查在同一registry锁内完成。新Open在转发前保留PendingOpen和配额；不能先远端创建成功再临时寻找owner。owner关闭期间迟到的Open结果不得发布给CA，只能进入同一关闭/回收路径。

## 5 VSOCK断连观察

选择一个manager级连接观察器，不给每条连接另建TLS reader：
- 使用受生命周期保护的dup fd观察POLLHUP/POLLERR/POLLRDHUP（后端支持时）。
- 观察器不调用read、recv或MSG_PEEK；只有原连接worker消费VSOCK/xtransport/TLS字节，避免并发破坏framing。
- 原reader收到EOF、TLS fatal、包校验失败、发送失败时，同样调用mark_owner_closing；该状态迁移幂等。
- 支持RDHUP时即使reader正等TA，观察器仍可请求owner关闭并shutdown对应manager→TA代理I/O。
- 不支持RDHUP或该事件不可靠时，采用有限watch_tick与owner_idle_lease。只在一份完整、验证通过的请求被接收时刷新活动时间；POLLIN、半个包或未验证字节不刷新。
- 到期只标Closing并触发回收，不能把lease到期直接当session释放证明。

请求CA必须在LSP允许的heartbeat范围内送空STEP；manager lease大于允许的单次forward预算和heartbeat间隔之和并留调度余量。管理会话空闲时由CA主动关闭，下次管理操作再打开；不靠无意义查询永久续租。

## 6 项目TA runtime私有生命周期通道

### 6.1 目的与端点

现有manager的一轮Unix转发结束，只能证明代理I/O结束；TA callback可能仍在执行。当前cleanup代码在转发失败后也unbind/on_session_closed，这不能用于本项目“真实资源释放”结论。

项目runtime增加一个独立控制线程和reaper。它只管理本项目TA的owner/session，不修改旧TA/runtime。manager与该runtime维持一个有序控制连接，数据Invoke仍走原项目TA Unix listener。候选路径：
- 注册：/run/lsp/gen/<manager_epoch>/registry.sock；
- 数据：/run/lsp/gen/<manager_epoch>/<instance_epoch>.rpc.sock；
- 生命周期：/run/lsp/gen/<manager_epoch>/<instance_epoch>.life.sock；
- 外部VSOCK：CID201、端口10099，部署前验证无冲突；
- 进程名lsp-manager，不包含vsock-manager，防止旧自启脚本宽泛匹配。

路径和权限显式配置，启动只处理自己创建的对象，不能unlink共享/tmp/server.sock或旧监听。epoch用于关联，不是身份密码协议。

### 6.2 帧与共同字段

私有流帧：u32 little-endian JSON字节数（1..4096）+严格UTF-8 JSON object。禁止重复键、float/NaN、未知字段；JSON容器深度最多8。UUID/epoch为32小写hex，u64为规范十进制string。

请求固定字段：
{v:1,rpc_id:u64string,op:enum,manager_epoch:hex32,instance_epoch:hex32,owner_seq:u64string|null,args:object}。

回复固定字段：
{v:1,rpc_id:u64string,op:同请求,manager_epoch:hex32,instance_epoch:hex32,owner_seq:u64string|null,code:enum,snapshot:OwnerSnapshot|null}。

HELLO/PING回复的owner_seq必须为null；其他回复包括错误回复均回显请求的owner_seq。异步事件使用rpc_id="0"、op=OWNER_RELEASED、code=OK、owner_seq为已释放owner的非null序号，其余同回复。普通rpc_id从1开始且连接内不复用。只有一个reader解码所有回复和事件；回复同时匹配pending表中的rpc_id/op/owner_seq及manager_epoch/instance_epoch，不能仅凭rpc_id回填。事件按(manager_epoch,instance_epoch,owner_seq)定位owner记录，再验证RELEASED快照及release_generation；不能用可为空的session_id定位，也不能用rpc_id=0推断owner。关联不匹配不能释放任何对象或配额，并按控制通道故障处理。已FORGET的历史owner事件只能忽略，不得复活记录；同owner同generation的重复证明幂等，已有证明的generation变化为协议错误。

writer串行化完整帧，不能交错写JSON。命令和事件均有有界队列，队列满则关闭控制连接并进入故障处理，不丢弃释放事件后假装已知回收。错误请求若尚无法得到合法rpc_id/op/owner_seq关联字段，则直接关闭连接，不构造缺失owner_seq的错误回复。

OwnerSnapshot固定字段：
{state:enum,session_id:u32|null,open_started:bool,live_workers:u32,joined_workers:u32,app_result:u32|null,release_generation:u64string|null}。
state为BOUND/OPENING/LIVE/CLOSING/QUARANTINED/RELEASED/RETIRED/UNKNOWN。RELEASED要求live_workers=0且所属已启动worker均join；BOUND从未Open的owner释放时joined_workers可0。app_result是业务close/create结果，与worker是否已退出分别记录。

v1每owner最多一个session worker，live_workers/joined_workers因此各为0或1。BOUND/OPENING的session_id和app_result为null；LIVE时session_id为实际local ID、app_result为0。成功Open后在CLOSING/QUARANTINED/RELEASED保留该ID，app_result在Close返回前为null、返回后为Close的GP结果；Open失败的RELEASED保留session_id=null及非零Open结果。从未Open的BOUND直接释放时app_result=null。release_generation只在RELEASED非null，由runtime在join确认/无worker确认时单调分配并保持稳定；其它状态为null。QUERY发现非零app_result时code=TA_ERROR，其余已知owner正常查询code=OK；调用方必须同时检查state，不能将TA_ERROR当作未回收，也不能将OK当作已经join。

code为OK/PENDING/BUSY/STATE/OWNER_RETIRED/OWNER_UNKNOWN/EPOCH_MISMATCH/BAD_FRAME/TA_ERROR。只有结构与epoch全部匹配的RELEASED snapshot才可用于最终回收；RETIRED/UNKNOWN本身不能补造遗失的证明。

### 6.3 命令完整约定

| op | owner_seq / args | 前置与结果 |
| --- | --- | --- |
| HELLO | null / {ta_uuid,backend_contract_id} | 验证配置的项目TA与instance_epoch，绑定唯一manager_epoch；回复OK snapshot=null。不能静默接管仍有旧worker的实例 |
| PING | null / {} | 仅维持控制连接活跃；不延长任何owner/业务请求lease |
| BIND_OWNER | 严格递增conn_seq / {} | 原子建立BOUND记录；必须大于该控制域highest_bound，成功后更新highwater；保留owner配额。旧值拒绝，不重新创建，允许未分配的序号空洞 |
| OPEN_OWNER | 已BOUND的seq / {connection_method:u32,ca_auth_info:null或{ca_uuid,verified}} | 项目GP Open要求无业务params；创建工作安排到独立session worker，立即回复PENDING/OPENING，不能在控制reader等待用户回调。每owner最多一次 |
| QUERY_OWNER | seq / {} | 返回当前快照，不触发回调、不续租；用于等待Open结果或核验释放；未知/退休状态明确区分 |
| RELEASE_OWNER | seq / {reason:explicit_close/peer_closed/deadline/manager_shutdown/lease_expired} | 原子设置closing及取消标志，唯一地安排close；重复请求返回原状态而非再次close。已Opening时callback返回后清理，不发布新LIVE |
| FORGET_OWNER | seq / {release_generation:u64string} | 仅RELEASED且generation相符时删除记录。manager只能在全部代理任务退出且本地binding已回收后发送。highwater保留，因此旧BIND不能重建 |

BIND_OWNER与OPEN_OWNER只通过这条有序控制流发出。BIND序号分配和排队由同一sequencer负责；不能由各连接线程先取号再乱序入队。owner变Closing和Open入队共享一次可线性化检查：Release已赢则不发送Open；已排队Open会先于Release被runtime接收。

FORGET不会制造晚到Open窗口：runtime只有已有BOUND记录才接受OPEN_OWNER；record删除后旧Open被拒绝，旧BIND又被highwater拒绝。manager ownerKey不可复用。此处不需要无界历史tombstone。

HELLO必须是连接首条命令且成功前拒绝其他命令；ta_uuid使用32小写hex，backend_contract_id固定为`lsp-manager-lifecycle/1`。ca_uuid采用teec-protocol中UUID的16字节顺序编码为32小写hex，verified是JSON bool；它仅搬运既有身份字段，不增加认证保证。owner_seq范围为1..u64::MAX；普通rpc_id同范围且严格递增；v、connection_method、session_id、worker计数、app_result均为JSON整数，u32字段不得溢出。所有args均精确按表，额外字段拒绝；空args必须为{}。除HELLO/PING的snapshot=null外，已知owner命令回复完整快照；未知seq返回UNKNOWN，seq≤highwater且记录已不存在返回RETIRED，这两者的session_id/app_result/release_generation为null、计数0，均不能证明释放。错误帧或epoch不符可在完整帧被识别后返回对应code，然后关闭控制连接；不继续消费不可信长度或重复rpc_id。

控制帧头和正文共享3000ms单次绝对收发预算；idle lease由独立timer维护，不靠阻塞read自然超时。任意mutation（BIND/OPEN/RELEASE/FORGET）的超时、写入中断或回复关联失败使该控制连接失效并shutdown，不重发该命令；runtime通过控制EOF/HUP或idle lease对整个旧manager域启动Release。manager保留未知记录及配额，进入RecoveryRequired，不在新连接无条件重放。正常QUERY采用50ms最小间隔且受Open/cleanup总预算限制；单次QUERY传输失败同样关闭连接，不假定还能使用半帧流。业务Open失败结果只有TA_ERROR的app_result或LIVE成功快照才能确定；PENDING不等于Open成功。

### 6.4 异步Open与释放证明

OPEN_OWNER的worker负责ta.open_session，并独占SessionContext和后续Invoke/Close。Open返回后：
- owner仍Live意图且未closing：记录local session ID，QUERY返回LIVE；
- owner已closing：立即进入该worker的Close路径，不对CA发布成功；
- Open错误：记录app_result，worker退出，reaper join后记录RELEASED。

RELEASE_OWNER在控制线程设置取消标志并投递一次高优先级Close。worker未执行Invoke时可立即取Close；正在有限STEP时在返回/安全点落实。旧kernel没有可抢占私有deadline，正在非协作callback时只能停留CLOSING，超过grace标QUARANTINED。

数据listener使用local session ID定位对应OwnerEntry；Invoke admission与closing迁移共用短锁。每owner最多一个在执行或已接纳Invoke，额外请求返回BUSY。Close标志独立于容量1的数据队列；一旦closing，拒绝后续Invoke，丢弃尚未开始的Invoke并完成其失败响应。对已执行callback只能等待其返回。Unix connection handler用有限recv_timeout等待worker答复，owner关闭或自身预算到期即退出I/O；它退出不能销毁仍由session worker持有的context，也不能伪造join。注册socket、数据socket和life socket的半帧读取、响应写入均使用有限绝对预算与独立取消状态；不留下无限read_exact处理线程。

项目数据listener只接收已登记session的Invoke；直接收到OpenSession、CloseSession或RequestCancellation返回NotSupported，不能绕过life通道创建无owner会话。外部GP Open/Close仍由项目manager转换为life命令，外部wire不变。instance内local session ID使用checked单调分配器，范围1..u32::MAX；在调用Open callback前预约，Open失败也永久消耗该ID。Close/Forget/owner删除均不允许回收ID；超出范围拒绝新Open并进入维护状态，不能wrapping_add或回绕0。旧sid查不到、已Closing或属于已退出记录时拒绝，不得落到后来owner；新实例使用新instance_epoch和新socket路径隔离旧数据连接。

reaper持有JoinHandle，仅is_finished后执行join；确认Context drop和worker退出后，记录稳定RELEASED快照和release_generation，并发出一次OWNER_RELEASED事件。Close“已入队”、callback返回前、代理socket已关闭或lease到期均不能产生该证明。请求TA资源清扫同样只能触发Close，不替代join。

控制连接断开或其有限lease到期时，runtime对该manager域所有owner执行同一Release路径并向supervisor报告FATAL。全部session真实join后，StorageWorker结束当前GP操作、关闭快照和anchor、退出并join，runtime协作退出；不能永远保留anchor等一个已不存在的manager。无法协作时由supervisor对自己持有的Child执行有界drain/终止/reap。新manager不能盲目unlink或接管旧实例；完整恢复接口见[项目runtime恢复合同](project-runtime-recovery-v1.md)。单owner失败/取消不触发generation恢复。

runtime的lease/timer线程不调用TA回调，也不等待session锁之外的长操作。runtime owner lease由完整接受的OPEN/Invoke刷新，QUERY/PING不刷新；关闭后的owner不再续租。life reader和数据reader各只消费自己的socket，watcher只看事件。若80e实际后端不支持所选nonblocking/poll/shutdown行为，必须在最小适配验证中失败并补齐该用户态I/O实现；不能把一个有限TTL写入配置就宣称已终止阻塞线程。

## 7 manager Close与in-flight竞争

每个binding包含：
- SessionOwner与instance_epoch；
- forward_io_inflight：仅统计本manager正在执行的代理任务；
- target_unconfirmed：代理失败后仍可能执行的TA工作；
- 唯一CloseClaim及close_sent标志；
- runtime_release_proof（可空）；
- 所有任务持有的Arc引用及配额reservation。

forward_io_inflight只计真正向TA转发Open/Invoke的数据任务；等待终态的GP Close响应者及QUERY观察者持有只读Arc，不计入这个drain计数，否则Close会等待自身退出而死锁。终态发布后它们可回包并退出，不能再提交TA命令；其短期响应缓冲仍计入独立连接/内存额度。

关闭时在短锁内Open→Closing并取得唯一claim，拒绝新Invoke。ReleaseOwner最多发送一次，不把超时当作重新发送Close的许可。已有reader/sender退出时减少forward_io；如果没有完整TA回复则target_unconfirmed保持。不能调用旧cleanup路径无条件unbind。

最终释放条件必须同时满足：
1. 正常Close已确认runtime的该owner RELEASED；generation故障的整实例资源收敛另由supervisor确认其直接持有的TA Child退出/reap，不能据此回GP Close成功；
2. 本manager全部相关代理任务退出；
3. CloseClaim唯一且accounting未做过。

然后按一次原子accounting移除binding、返还session/instance配额、保存本地终态，再FORGET_OWNER。运行中的task仍可持有不可变Arc以读取终态，但不能重新激活会话。旧sid在该manager/instance epoch内不复用；计数溢出明确BUSY/停止分配。

QUERY轮询只在配置的Open/cleanup总预算内进行。正常OWNER_RELEASED事件能完成后续回收；查询预算耗尽进入QUARANTINED，不无限重试写操作或忙轮询。隔离对象继续计入max_sessions/max_owners和内存配额，因此故障不能制造无界遗留对象。

GP Close从manager完成请求校验并锁存唯一CloseClaim时建立D_close=now+manager.cleanup_query_ms（8000ms），它是整个Close远端收尾总预算，包含RELEASE_OWNER控制帧、runtime协作grace、所有QUERY及forward drain；不是先3000ms再加8000ms。每个控制操作取min(其单帧上限,D_close剩余)。收到匹配的RELEASED且forward_io_inflight=0后，才能完成accounting并回GP Close；app_result为0或无callback的正常释放时返回TEEC_SUCCESS，真实Close app_result非零时返回该结果。到D_close仍无证明/未drain时返回TEEC_ERROR_BUSY并保持Quarantined，CA只记录远端清理unknown（可内部保留pending观察状态），不重发Close；BUSY不表示任何之前的业务命令未执行或管理写未提交。控制流失效按通信未知处理并触发supervisor generation恢复。不能用成功响应表示“Close已排队”。

owner记录配额与活动session配额分开：RELEASED的session资源可按证明返还，但owner记录在FORGET成功前仍占max_owner_records。runtime在BIND检查两类额度，避免连续Release而不Forget累积无限记录；控制通道失效时保留的记录也受此上限约束。模型的record_quota演示此规则，生产上限从统一运行配置派生，不能取模型测试中的小整数作为产品默认。

后端数值唯一来源为`docs/design/lsp-backend-config-v1.json`：整个项目manager/TA实例域max_owners=8、max_sessions=8、max_owner_records=16；每owner Invoke admission=1。lifecycle最多16个inflight RPC；manager命令队列32，其中8槽保留RELEASE/FORGET，普通命令最多24；runtime普通回复队列32和释放事件队列16独立计数。认证VSOCK连接最多8，握手中连接另限4。运行状态、Closing、Quarantined均占相应名额；Released仅返还session额度，记录需Forget后返还。CA仍只允许请求worker2/admin1；后端至少保留3个可用slot才能声称满足该并发目标，额外容量只允许有限清理/历史遗留余量，不能绕过CA准入。事件队列须不小于max_owner_records；满队列按控制故障处理，不无界扩容。

## 8 时间预算与失败行为

参考配置初值与[CA本地契约](ca-local-contract-v1.md)的localConfig.timeouts统一，供实现联调，不代表设备性能验收：
- sdk_connect_open_ms=15000；
- sdk_connect_ms=5000，sdk_handshake_ms=10000，sdk_call_budget_ms=5000，均受上述总预算剩余值约束；
- sdk_graceful_close_ms=15000，整个优雅关闭序列共用一次预算，GP Close不再套5秒普通Invoke cap；
- worker_reap_grace_ms=3000，abort后观察worker收尾；
- cleanup_observe_ms=2000，仅CA控制方/UI的状态观察窗口，不是回收宽限；
- manager_forward_ms=3000；
- owner_idle_lease_ms=15000，watch_tick_ms=250；
- runtime_close_grace_ms=3000；
- manager_cleanup_query_ms=8000，从Close开始计的总预算（含Release/Query/grace），不是额外查询窗口；
- lifecycle_control_idle_ms=10000，PING间隔≤2000。

配置加载时验证正数、上限及lease大于允许forward/heartbeat窗口；发布时锁定实测值。deadline是逻辑I/O预算，不承诺不受调度或不可协作代码影响的硬实时回收。

请求总体预算结束后不得继续生成；可独立使用上述不可重置的优雅关闭预算完成资源清理，耗尽再abort并观察worker_reap_grace_ms。任何一个计时到期都不替代join。CA对外cleanup_state=STALLED对应本文仍占额度的内部Quarantined worker，不能因cleanup_observe_ms结束就标released。

| 失败/竞争 | 选择的行为 | 允许宣称 |
| --- | --- | --- |
| 入队或connect前取消 | 不发送命令，worker回收 | NotSent；join后released |
| handshake/写/读中取消或过期 | dup shutdown，context永久失效，原worker退栈 | abort accepted；结果可能未知 |
| SDK worker仍不退出 | Quarantined，保留引用/配额，不卸载native库 | cleanup unknown；不能假join |
| Open结果回包丢失 | PendingOpen仍归owner；Release/Query同owner，不再Open | 没有新的生成或重复Open |
| CA断连而manager正在等待TA | observer标Closing，终止代理I/O，ReleaseOwner | I/O中止不等于TA已停止 |
| Release先于Open完成 | runtime owner已closing；晚Open返回后在worker清理 | 不发布late session |
| Close/断连/lease同时到达 | 同一唯一claim、一次Close callback | 不重复减计数 |
| Close已入队但Invoke卡住 | runtime与manager均Quarantined | binding/worker仍占额度 |
| join证明到达但代理任务未退出 | 保存证明，等待任务refs/drain | 尚未全部released |
| 代理任务已退出但无join证明 | 保留binding，有限Query后Quarantined | 不能把TTL当释放 |
| runtime回收事件丢失 | 有限QUERY查RELEASED；仍未知则隔离 | 不自动重发Close |
| 项目TA进程异常退出 | supervisor通过直接持有的Child确认并reap，整代drain；关联会话均失败 | 不能当GP Close成功 |
| lifecycle断连/manager异常退出 | runtime协作清理并关anchor；supervisor等待旧二者结束后按有限策略启动双新epoch | 不盲目重用sid/epoch、不失去旧TA所有权 |
| 普通单请求cancel | 不杀共享TA、不停旧manager、不重启VM | 其他请求继续按自身状态运行 |

[项目runtime恢复合同](project-runtime-recovery-v1.md)定义lsp-supervisor为唯一恢复主体：manager与TA是其直接child；普通单请求取消不触发generation恢复，manager/life/TA致命故障则对该项目generation有界drain并在真实reap后有限重启。显式ADMIN_RECOVER同样影响本代全部请求，需清楚记录该范围。supervisor本身崩溃丢失Child所有权则Maintenance，不能猜PID、清anchor或启动第二writer。旧服务与VM不重启。

## 9 两条典型时序

### 正常取消

CA协调器锁存cancel → 停止公网I/O和普通队列 → 当前有限STEP返回 → 同worker发送业务CANCEL → CA接收终态 → GP Close映射成manager CloseClaim → lifecycle RELEASE_OWNER → runtime worker Close/drop/exit → reaper join → OWNER_RELEASED → manager在代理任务退出后解绑一次 → CA Close完整返回 → Finalize/worker join → cleanup=released。

### SDK卡住与目标非协作

CA deadline到期 → AbortHandle对独立dup shutdown并wake → 上层timeout、cleanup=pending → manager HUP或lease标owner Closing → 代理Unix I/O终止，但target_unconfirmed保留 → runtime RELEASE_OWNER只排队Close → 回收期限到仍无join → CA/manager/runtime Quarantined → 不重放、不返还错误配额 → 后续真实join事件到达可完成收尾；若永不返回，进入显式项目实例recovery，不影响旧Trusty/GP实例。

## 10 精确最小改动清单

| 组件/源码接点 | 必要改动 |
| --- | --- |
| virga XTransportHandler::connect/from_stream/disconnect | 接受预创建DeadlineSocketIo、保留受控dup AbortHandle；避免阻塞connect与只有&mut disconnect |
| virga XTransport Read/Write与错误映射 | 短读写/分片/ACK共用deadline；保留Cancelled/TimedOut；不改线上包格式 |
| rust-libteec CcClient::init/connect_and_configure | 注入显式端点、budget、abort；ECDH和TLS使用同一受控transport |
| rust-libteec context/session封装 | worker独占、注册稳定地址、独立abort句柄、完整调用预算和Delivery状态；禁止自动重放 |
| 项目manager vsock_server/dispatcher/ta_runtime | OwnerKey替换None-owner、PendingOpen reservation、绑定原子性、断连observer、有限转发预算；supervised模式禁用TA spawn/reap，只attach本代实例 |
| 项目manager cleanup | 与旧无条件unbind策略分开；唯一claim、join证明及I/O drain共同控制回收；Quarantine保留配额 |
| 项目TA runtime ta_manager | owner控制线程、异步Open worker、Close高优先控制、reaper join及有限lease触发 |
| 项目生命周期私有协议 | 本文BIND/OPEN/RELEASE/QUERY/FORGET与异步释放事件，固定版本、路径和closed schema |
| TEE内lsp-supervisor与继承pipe | 直接拥有manager/TA Child；ready/activate/fatal/drain、SIGTERM/SIGKILL与reap、有界restart；详见恢复合同 |
| 镜像与启动配置 | 只增加/修改项目独立用户态文件；旧kernel、vsock9999、旧socket/脚本保持身份 |

## 11 验证与边界

可执行模型位于[SDK生命周期模型](../../artifacts/functional-design-completion-20261112/sdk-lifecycle-model/model_test.py)。已运行146项host检查：120种Close/断连/I/O结束/TA结束/join事件排列，其中50种为合法调度；每条合法前缀检查唯一claim和释放前置条件，非法调度按独立顺序条件识别。另验证pending Open、错误owner、配额与Quarantine、绝对预算不重置、OwnerKey空洞与重用拒绝、释放后未Forget仍占记录额度等。新增的关联检查覆盖回复owner回显、HELLO/PING null、缺失owner事件、多个Open失败/无worker释放（session_id均null）、错误epoch、重复generation、退休事件和join缺失；local sid检查覆盖旧ID不能命中新owner与耗尽不能回绕。

三项实际Linux AF_UNIX实验验证：dup shutdown不作用于复用后的新fd、abort无需取得正在持有的Invoke锁、观察状态变化不消费数据。原沙箱禁止socket发送导致3项错误，已保留sandbox日志；宿主机运行0 failure/error/skip，见[结果](../../artifacts/functional-design-completion-20261112/sdk-lifecycle-model/results.json)。

这些是模型和Linux AF_UNIX证据，不是Android AF_VSOCK、xkernel poll/HUP、实际virga/TLS改造或TA join的验收。关联检查只验证已解码控制信封的owner/epoch/rpc绑定，仍未测试完整私有协议codec。生产实现必须覆盖本文私有协议codec、并发压力、超时故障和新设备回归。身份签名方案不在本稿扩展。
