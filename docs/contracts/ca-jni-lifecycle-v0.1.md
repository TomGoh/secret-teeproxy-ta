# 灵润服务内 CA 的 JNI 与生命周期设计 v0.1

日期：2026-11-12。依据：需求v0.4、当前总体设计与LSP/1通信草案。状态：可评审设计建议，尚无产品实现或设备验证。配套声明：[lsp-ca-ffi-v1-draft.h](lsp-ca-ffi-v1-draft.h)。

## 1 固定边界与选择

生产CA随灵润APK构建，运行于现有:runtime进程，由Java/Kotlin服务层通过窄JNI调用Rust CaRuntimeModule。不得另起daemon、helper或HTTP代理进程。mock采用独立Android测试APK，复用同源CA核心和相同业务ABI；CLI可作补充驱动，不是产品运行依赖。额外模块身份增强按D-008后置，保留现有SDK真实验证行为；若后续启用descriptor方案，产品与mock分别构建绑定用途和UUID，不能由Java运行时切换身份。缺失的SystemAiManager/AiRequest/公共Binder类不进入本接口类型。

建议首版：
- Java主动readEvent拉取，Rust不回调Java、不保存JNIEnv或Java callback引用。
- 输入和输出均copy-only，使用长度明确的UTF-8 byte[]与原始byte[]；不支持异步DirectByteBuffer或原始FD转交。
- 每个请求由Rust内一个独立SDK worker/context/session驱动，同一对象单飞；管理操作单独排队执行。
- 数据面、控制面和清理状态分离。cancel、close、operationGetInfo、beginShutdown不能排在数据队列或SDK Invoke锁之后。
- 引入仅进程内的event ticket/ACK/NACK，解决JNI对象构造失败和Java消费栅栏。这不增加LSP DATA_ACK，不重放TA命令，不改变LSP未知结果整请求失败的规则。

Android官方建议缩小JNI界面，尽量由Java线程进行阻塞native调用并在Java内完成异步通知；JNIEnv不能跨线程共享。本方案采用这一边界。[Android JNI tips](https://developer.android.com/ndk/guides/jni-tips)

## 2 C ABI与Java facade

C声明仅使用固定宽度整数、repr(C)布局、调用期间借用的byte span和opaque值句柄；不暴露Rust Vec/String、C++对象或TEEC裸指针。C header是设计声明，不含产品实现，也不是LSP wire格式。

### 2.1 Java facade建议签名

以下类型只依赖Java标准类型；RuntimeHandle/OperationHandle为不可变值对象。实际JNI导出名可由构建生成，禁止让上层直接传native地址。

    final class CaNative {
        static native RuntimeResult create(byte[] configUtf8);
        static native RuntimeInfo runtimeInfo(RuntimeHandle runtime);
        static native SubmitResult submitRequest(
            RuntimeHandle runtime, byte[] requestMetaUtf8, byte[] body);
        static native SubmitResult submitManagement(
            RuntimeHandle runtime, int managementKind,
            byte[] requestMetaUtf8, byte[] secretUtf8);
        static native ReadResult readEvent(
            RuntimeHandle runtime, OperationHandle operation,
            int timeoutMillis, int metadataCapacity, int bodyCapacity);
        static native int acknowledgeEvent(
            RuntimeHandle runtime, OperationHandle operation,
            long ticket, int disposition, int deliveredBytes);
        static native int cancel(
            RuntimeHandle runtime, OperationHandle operation, int reason);
        static native OperationInfo operationInfo(
            RuntimeHandle runtime, OperationHandle operation);
        static native int closeOperation(
            RuntimeHandle runtime, OperationHandle operation);
        static native int releaseOperation(
            RuntimeHandle runtime, OperationHandle operation);
        static native int beginShutdown(RuntimeHandle runtime);
        static native AwaitResult awaitShutdown(
            RuntimeHandle runtime, int timeoutMillis);
        static native int destroy(RuntimeHandle runtime);
    }

nackEvent只供JNI桥接内部处理“尚未发布给Java的事件构造失败”，不作为普通UI回调失败的重试入口。Java所有timeout/capacity在JNI前验证为非负、在C u32范围内；不允许把负jint直接cast成大u32。Java long中的不透明64位token按原始bits传递，不使用大小符号判断授权。

建议返回对象：
- RuntimeResult：localStatus与runtime handle。
- SubmitResult：localStatus与operation handle；OK只表示本地准入，远端结果异步到达。
- ReadResult：localStatus、requiredMetadata/BodyBytes；OK时含Event。
- Event：kind、eventSequence、ticket、streamOffset、metadataUtf8、bodyBytes。BODY使用原始bytes，禁止按每块强行解UTF-8。
- OperationInfo：执行phase、delivery state、cleanup state、outcome/modelOutcome、confirmed delivered bytes、lease/队列状态。
- 管理写操作另有management_commit_state：not_sent/unknown/committed/not_committed_confirmed；请求及只读QUERY/PROBE为not_applicable，不能与cleanup状态混用。

该事实在C的lsp_ca_operation_info中使用u32 enum（not_applicable=0、not_sent=1、unknown=2、committed=3、not_committed_confirmed=4），在get_info读取；TERMINAL metadata包含相同名称字段，使用上述精确字符串，反映终态生成时的提交事实。后续QUERY对账是新operation，不回写已经发出的Terminal。C布局固定operation_info为72字节，management_commit_state偏移40、reserved偏移44、confirmed delivered计数偏移48、outstanding_ticket偏移64，头文件包含对应size/offset断言。
- AwaitResult：localStatus、runtime info；等待超时不表示已经停止或释放。

requestMeta沿用当前联合评审的业务字段语义，但不包含LSP epoch/nonce/call_seq，这些由CaRuntimeModule管理。完整本地JSON字段、默认值、错误映射和容量见[CA本地功能契约](ca-local-contract-v1.md)及其schema；本页不另定义隐含参数。managementKind为PUT/QUERY/DELETE/PROBE；PROBE是native组合操作（建立会话并HELLO），不新增TA opcode。PUT独有secretUtf8；QUERY/DELETE/PROBE必须为空。

RuntimeConfig包含本构建支持的sdk_profile、后端契约标识、SDK端点、本地容量/期限与provider profile集合，完整字段以本地schema为准，其生产来源由灵润服务控制。它不是已验证模块descriptor的声明，不包含身份根、UUID覆盖或verified开关。额外库身份按D-008后置，不将Java包名、APK安装成功或SDK验签失败后可Open当成生产强化认证。

### 2.2 同步返回不代表远端成功

create只完成本地schema/容量验证、配置复制和调度设施创建，不在调用Java线程上进行VSOCK、握手或TA调用。READY表示本地可准入，不表示TA已连接。远端可用性由异步PROBE或实际操作报告。

submitRequest/submitManagement：
1. 验证参数、句柄、大小及本地队列额度。
2. 成功复制全部输入到Rust拥有的有界存储。
3. 分配operation handle并原子入队。
4. 返回OK。任何前置失败都不产生handle或排队副作用。

Key保存成功只能由MANAGEMENT_RESULT/终态明确确认，不能在submit返回时显示“已保存”。

分配、输入复制、JNI对象构造、用户callback、SDK/network I/O、等待和join均不得在registry/admission/delivery短锁内进行。需要先在短锁下预约容量，锁外复制，再在准入提交点复核shutdown/generation；失败释放预约，不能让大body复制挡住cancel控制路径。

## 3 句柄、归属与ABA防护

### 3.1 Runtime句柄

C ABI中的runtime handle为三个u64：process_epoch_hi、process_epoch_lo、runtime_generation。它们是opaque值，不是地址。process epoch在该进程/库实例中生成；runtime_generation单调递增，耗尽时拒绝新建，不能回绕。v1同进程最多一个活跃runtime，旧runtime清理完毕前不能通过重新create绕开STALLED worker。

所有调用通过内部注册表查句柄，验证process epoch、generation和对象状态，再取得临时强引用。不能将Java long转换为Box/Arc/TEEC指针直接解引用。

注册表持有稳定的Arc/Box对象；TEEC_Context及session引用的存储地址在CloseSession/FinalizeContext完成前保持稳定，不能因HashMap扩容或结构体移动改变地址。销毁顺序仍为session先关闭、context后finalize，最后才释放底层存储。

### 3.2 Operation句柄

operation handle含完整runtime owner handle、slot和slot generation，共40字节。与传入runtime不匹配返回OWNER_MISMATCH。slot复用时generation递增；溢出退休该slot。对象关闭、释放或进程重启后，旧handle不能命中新对象。

Java不得持久化这些handle；长期可恢复数据是credentialRef和管理operation_id，不是native操作handle。callerCorrelationId与LSP request_id也不能作为native handle。

### 3.3 Ticket

每个operation最多一个未确认event ticket。ticket在该operation内每次lease时单调递增，NACK后再次读取同一事件取得新ticket但保持eventSequence。回绕时终止/拒绝，不复用。

ACK对同一最近已结算ticket、相同disposition和字节数可返回ALREADY；旧ticket或同ticket不同确认内容明确拒绝。这是有界局部幂等，不保留无限ticket历史。

句柄检查防止误用和陈旧引用，不构成抵御同进程任意native代码的安全隔离承诺。

## 4 字节、缓冲与JNI对象所有权

### 4.1 输入只在调用期间借用

C函数入参pointer+len仅在本次调用期间有效；成功submit前复制，函数返回后不保留Java数组、JNI critical pointer或调用方内存。JNI使用GetByteArrayRegion等复制方式，不跨排队、网络、SDK Invoke、condvar等待持有GetPrimitiveArrayCritical区域。Key通过byte[]传递，避免用JNI Modified UTF-8字符串接口表达协议UTF-8。[JNI函数规范](https://docs.oracle.com/en/java/javase/21/docs/specs/jni/functions.html)

Java调用方须保证native方法返回前不同时修改输入数组；返回后可以复用/清理。C API不会自动擦除调用者缓冲。JNI临时secret副本和Rust拥有的排队secret在不再需要时主动清理；不据此宣称可以清除输入法、UI String或SDK内部所有历史复制。

v1提交完整body并复制，受max_request_body及全局内存限额约束。Java原数组、JNI临时副本和Rust队列副本的峰值必须计入设计预算，不能只按LSP单帧16KiB估算整个调用。

### 4.2 输出为调用者拥有的副本

C read_event将完整metadata/body复制到调用者提供的缓冲。JNI再创建Java拥有的byte[]。不返回指向Rust Vec或p1的DirectByteBuffer；JavaGC不能控制TEEC缓冲生命周期。

每个stage的长度明确：
- LSP p1及pending由Rust掌握。
- native event queue保留事件与body。
- JNI输出临时缓冲由当前JNI调用拥有。
- Java Event中的byte[]属于Java。
- event lease在ACK/NACK/撤销前继续计入native信用；额外Java队列必须有自己的显式上限。

调用方ACK后仍故意保留全部Java数组的内存，不属于native库可强制回收的范围；不能声称对任意调用方行为保证整个ART进程内存有界。

### 4.3 BUFFER_TOO_SMALL无副作用

read_event发现缓冲不足时：
- 返回BUFFER_TOO_SMALL及所需长度；
- ticket/eventSequence输出为0；
- 不pop、不创建lease、不修改输入输出offset；
- 不向部分缓冲写入有效事件。

调用方扩容后重试是本地取事件，不是重发LSP命令。该peek不预留事件；若期间cancel获胜，下次read可能看到取消/closed而非原事件。所需长度必须不超过runtime报告的事件最大值，超出则是内部协议错误，不能无限分配。

### 4.4 Java分配失败不丢事件

JNI调用C read_event取得ticket后，构造Java Event/byte[]。只有完整Java对象可返回时才向Java发布。

若NewByteArray/NewObject失败或出现待处理Java异常：
1. 不将半个Event返回。
2. 通过纯native nack_event结算该ticket（不会调用SDK）。
3. 未取消时事件仍在队首；再次read取得新ticket，同eventSequence。
4. 若cancel已受理但ticket仍有效，NACK以零已消费字节结算并丢弃，不重排；close或lease超时已撤销则返回TICKET_REVOKED。
5. 保留Java异常返回，不为打印正文或重新分配错误字符串而加重OOM。

不能对已经交给Java消费者、可能产生副作用的事件使用NACK重放。普通callback失败应取消并按已知消费量结算，不能“再回调一次试试”。

## 5 拉取、Java回调与消费栅栏

### 5.1 线程安排

- Rust SDK worker和网络调度线程不调用JNI。
- Java建立专门EventPump线程/有限线程池来调用readEvent。
- 每operation同时只允许一个readEvent；多reader返回E_BUSY，不默默分流事件。
- Java由自己的SerialExecutor按operation顺序调用上层consumer；不在Binder主线程或UI线程做阻塞read。
- 每operation最多一个未ACK事件，所以正常情况下只需一个pending Java投递槽；不得采用无限Handler.post队列。
- cancel/close/query可从另一线程并发调用，不等待EventPump、consumer callback或SDK Invoke mutex。

Android JNI的线程局部JNIEnv不能跨worker保存。本方案中JNI操作仅发生在进入native方法的Java线程；无需为Rust数据面worker建立Attach/Detach和跨线程Java callback体系。[Android JNI tips](https://developer.android.com/ndk/guides/jni-tips)

### 5.2 一个事件的正常生命周期

QUEUED → LEASED_BY_READ → JAVA_OBJECT_READY → CONSUMER_ACCEPTED → ACKED。

read返回后，Rust保留lease计费。Java按序把BODY交给受限consumer；consumer正常接受整块后ACK_DELIVERED，deliveredBytes等于BODY长度，metadata/control事件为0。之后才获取下一事件。

ACK_DELIVERED不是JNI复制成功，也不是任意Handler.post成功；必须由串行适配器确认正文确实成功交给约定消费者后发出。若约定消费者是另一条有界传输队列，应显式定义其接管语义和容量，而不能把无界异步投递当作消费完成。

“接受”必须在adapter契约中定义：例如既有Binder回调成功交给对端队列，而不是用户已经看见文字。若远端Binder没有消费ACK，不能宣称知道UI实际渲染完成。每一层保持有界队列和顺序，外部报告应说明消费边界。

正常Terminal必须等全部已承诺正文ACK之后才可被readEvent取到。Observer可先锁存模型结果，TA可先FINISH，但不越过这个Java消费栅栏。

### 5.3 取消遇到正在执行的callback

Java通过短dispatch gate记录“是否允许开始新的callback”和inFlight ticket；不能持有该gate执行用户callback。cancel设置禁止新投递，native立即停止网络与普通工作入队。已经在线性化点前开始的callback可完成，不能安全强杀任意Java代码。

cancel本身保留已建立的一个ticket直至ACK/NACK或原lease期限；不会仅因cancel就撤销。若旧ticket仍有效，callback结束后的ACK可增加确认消费字节，然后只产生cancelled/timeout终态，不能恢复completed。ACK_DROPPED仅用于cancel_pending且ticket有效：deliveredBytes是已知成功交付前缀0..body_len，其余计dropped；control事件为0。close/lease撤销后的ACK_DROPPED也返回TICKET_REVOKED，不能修正已提交快照。若consumer长期不返回，lease/consumer deadline使native撤销ticket、清理自身队列，confirmed delivered count保留最后确认值，并标记delivery_uncertain。

该状态下cleanup可继续，不依赖UI恢复；Java SerialExecutor若已经卡死，终态callback本身也可能无法投递。控制线程可通过operationInfo看到结果。不能为了回调期限杀灵润进程，也不能虚构“timeout一定让任意Java callback在某毫秒内返回”。

本地Terminal元数据建议显式带delivery_evidence=confirmed/unknown_after_lease_expiry。它是JNI/app侧的诊断语义，不新增LSP wire字段；late ACK不能改写已经提交的终态快照。

同一operation的Java callback必须串行；Terminal callback不能越过已经开始执行的BODY callback。native产生终态快照、SDK/内存清理完成和Java最终投递完成是三个不同边界。ticket撤销后若旧callback可能已执行部分，confirmed delivered bytes仅为已确认下界，必须设置delivery_uncertain；不能把late ACK静默丢弃后仍声称精确计数。对已detach的consumer可以不再投递Terminal，但应保留诊断事实。纯copy模式下native资源释放不影响已有Java byte[]，只有旧handle失效。

## 6 精确状态与操作顺序

### 6.1 三条正交状态轴

执行phase：
QUEUED → SETUP → UPLOADING → ACTIVE → FINALIZING → TERMINAL。
管理操作可从SETUP直达FINALIZING/TERMINAL。取消/错误可从任意未终态阶段进入FINALIZING。

交付状态：
OPEN ↔ LEASED → DRAINING → TERMINAL_AVAILABLE → DONE。
close将其转为DETACHED；不再为该consumer新发事件。

本地清理状态：
LIVE → REQUESTED → SDK_CLOSING → LOCAL_RELEASED；
若SDK调用无法退出则为STALLED，保留对象并持续记录，不以free解决阻塞。

outcome、model_outcome、delivery_evidence、remote_cleanup_status与这些状态分开。TA REQUEST_END不等同本地worker释放；本地worker释放也不证明远端manager完成清理。

### 6.2 竞态表

| 竞争 | 必须固定的行为 |
| --- | --- |
| submit与beginShutdown | 同一准入锁线性化；先shutdown则无handle/无复制入队，先submit则归shutdown清理 |
| readEvent与cancel | 先成功建立lease的read可完成返回；Java闭合gate禁止新consumer投递。cancel不等待该read |
| Java构造OOM与cancel | 正常NACK重排；cancel_pending且ticket有效则零消费结算并丢弃；close/lease已撤销返回TICKET_REVOKED |
| ACK与cancel | 在ticket仍有效时按已知消费结算；取消结果不反转为成功；已撤销返回TICKET_REVOKED |
| callback成功与消费期限 | 先ACK则计入确认字节；先撤销则后续结果不再改写终态，记录delivery_uncertain |
| 模型终态与cancel | 模型锁存不等于外部成功；正文ACK栅栏之后才参与正常终态提交，取消先赢则保留model_outcome并报取消 |
| close与read | close关闭consumer并唤醒reader；此前已线性化的read可能返回副本，Java close标记负责丢弃，不能再调用listener |
| release与活跃SDK/FFI | 返回E_BUSY；不释放、不复用slot。只有全部本地引用与worker静止后退休generation |
| destroy与其它调用 | global registry entry进入destroying后拒绝新调用；旧调用还持强引用则E_BUSY，不能提前释放 |
| 管理取消与持久化 | 已发PUT/DELETE可能已提交；取消只终止本地等待，不保证撤销。保存为operation_id/ref/version待QUERY对账 |

### 6.3 close不是destroy

closeOperation是非阻塞消费者关闭：禁止新read交付、撤销所有尚未结算lease、丢弃未承诺队列、请求取消与清理。已返回Java的副本不受native回收控制，late ACK安全返回撤销/陈旧结果并保留消费不确定性。它不join SDK线程、不free context。handle继续允许query/release，重复close返回ALREADY。

releaseOperation在本地SDK worker、context、buffer和其它活跃FFI使用全部结束后退休handle；否则E_BUSY。Java RuntimeAdapter持有自己的operation登记表和后台reaper，完成后调用release；不把这一义务交给业务UI凭记忆实现。正常Terminal ACK之后仍需清理并release。

Cleaner/finalizer只能触发非阻塞close作为兜底，不能等待网络或执行destroy，也不能替代显式生命周期。

## 7 取消、超时与SDK abort

cancel的同步OK仅表示本地取消已受理：
1. 原子决定取消原因并关闭新的数据交付准入；
2. 停止该operation的socket读写及待发送数据；
3. 将业务CANCEL/SDK shutdown交给对应worker或独立abort控制路径；
4. 更新终态和cleanup事实，等待实际worker退出；
5. CloseSession/FinalizeContext完成或中止后，才能标为LOCAL_RELEASED。

同context仍保持单飞。abort必须能在不等待Invoke mutex的路径上安全shutdown底层连接，并与原worker的fd/session归属同步，避免fd关闭后复用造成误关闭另一请求。不能使用pthread_cancel、杀helper或杀整个灵润服务实现单请求取消。

abort采用[SDK/manager生命周期契约](sdk-manager-lifecycle-v1.md)中独立OwnedFd dup、短锁shutdown与wake_fd的确定方案；真正close与context回收由原worker收尾。不能把一个裸fd整数排入另一线程稍后close，也不能在调用仍可能使用TEEC_Context时free它。abort后该context永久失效，新请求只能新建context。

请求overall deadline从native接收准入时开始，用native单调时钟计算；排队、身份验证、SDK连接/握手、上传、响应消费均计入。readEvent的timeout只限定该次等事件，返回WAIT_TIMEOUT不自动取消操作。awaitShutdown超时同样不代表清理完成。Java Thread.interrupt不保证打断native SDK I/O，应通过显式cancel/close唤醒控制路径。

SDK目前5秒read timeout不构成完整硬deadline。若abort未实现或未验证，runtime可报告STALLED与cleanup pending/unknown，但不能承诺时限内free SDK context。内部deadline不能通过无限retry/reset被延长。

共享单飞admin worker，但每个管理operation独占新context/session：dispatch时创建，Open/HELLO后立即执行一次PUT/QUERY/DELETE，之后Close/Finalize；PROBE只HELLO后关闭。禁止跨用户思考时间复用idle context。operation_release须等待本项context/session及worker引用全部结束，不能仅等管理回复。

LSP CANCEL只属于request角色，因此不能为了取消management operation而向admin session发送该opcode。管理操作的本地cancel按下列规则处理：queued取消保证未发送；inflight PUT/DELETE在SDK abort时可能已经提交，保留非秘密operation_id/ref/expected_version并标commit_state=unknown；已收到成功receipt后取消不回滚其提交。QUERY/PROBE取消不产生写入效果。admin worker始终单飞，abort只针对当前operation拥有的context。未知写之后先在新context只读QUERY；E_BUSY时暂停dispatch未开始的后续写，保留队列Key的原有界预算与原deadline，到期清零，禁止延长或自动重放未知写。只读探测确认存储栅栏退出后才恢复后续原始写，详见本地合同第6.1节。结果未知时只凭元数据QUERY对账，不保留Key用于后台自动重试；确需重新预设时通过显式输入流程取得Key。

## 8 Runtime两阶段shutdown与进程死亡

### 8.1 进程RuntimeHolder及显式停用

主App ClassLoader持有进程级RuntimeHolder单例（单一配置、一个native runtime generation、operation登记表和后台reaper）。Service.onCreate仅attach；onDestroy仅detach该Service消费者并按caller gone关闭其操作，不调用runtime beginShutdown/destroy。Service重建重新attach既有runtime。创建过程由Holder短锁线性化，不能并行create两套runtime。CLOSING/STALLED仍保留Holder，拒绝新工作，不能通过Service重建绕过泄漏或失控worker；只有QUIESCENT、全部operation release且destroy成功后，显式重新启用才可创建新generation。

以下两阶段关闭只用于显式管理停用、进程主动退出的尽力流程或整个runtime不可恢复的故障处置；进程被杀时不保证该流程运行：

1. RuntimeHolder停止接受新的业务请求，记录需要保留的非秘密ref/operation_id。
2. beginShutdown原子将runtime置为CLOSING，拒绝新submit、detach各consumer、请求每operation取消，唤醒reader；同步返回，不join。
3. 后台调用awaitShutdown有限等待。结束条件包括所有SDK workers、socket任务、清扫器和ABI活跃调用实际停止；超时保持CLOSING/STALLED并返回WAIT_TIMEOUT。
4. reaper释放已LOCAL_RELEASED的operation记录。
5. runtime达到QUIESCENT且无operation handle/其它ABI调用时，destroy才移除registry并free。
6. library不得在仍有Rust/SDK线程运行时dlclose；不能为快速停止而强行释放其仍引用的对象。

beginShutdown会放弃外部consumer；如产品希望发送服务关闭错误，应由Java服务在其既有串行回调通道中完成。不要在Rust shutdown里临时回调Java或阻塞等待UI。

v1固定由主App ClassLoader调用一次System.loadLibrary，不支持热卸载、动态ClassLoader重复加载或在service onDestroy中dlclose。JNI_OnLoad只注册入口和必要类/方法信息，不发起SDK或网络操作；可以缓存JavaVM和必要的全局类引用，但不缓存JNIEnv或用户callback。正常关闭由显式生命周期完成，JNI_OnUnload不承担阻塞回收任务。service onDestroy不保证运行，beginShutdown本身也不得阻塞主线程。

### 8.2 Android进程突然死亡

Android不保证onDestroy、Cleaner或JNI卸载回调一定执行。进程死亡时OS关闭fd，远端manager应按连接owner清理请求session；TA lease提供应用资源兜底。不能把本地回调当作这个机制成立的证据。

永久Key可能已提交而回复未收到。Java应在管理submit之前保存非秘密operation_id/ref/期望版本等对账信息；新进程重新create runtime后QUERY，不恢复旧native handle，也不自动重发生成。

当前LSP临时Key按namespace/TTL而非创建management session绑定。正常关闭可尽力DELETE；进程突然死亡不能保证即时DELETE。请求session由owner cleanup处理，临时Key由TTL清扫最终回收。若要求跨session的一整个App实例死亡即刻撤销所有临时Key，需要另行设计owner group；本提案不暗中宣称当前wire已有这一能力。

## 9 函数线程、阻塞与所有权表

| 函数类别 | 允许线程 | 阻塞范围 | 所有权/副作用 |
| --- | --- | --- | --- |
| runtime_create | 初始化后台线程优先 | 有界本地校验、分配、线程创建；不做SDK/network | config复制；READY仅本地可准入 |
| submit_request/management | 服务后台/Binder工作线程 | 输入复制与短队列锁；不等待远端 | OK后输入归Rust副本，失败不入队；PUT秘密需清理 |
| runtime/operation_get_info | 任意服务线程 | 短snapshot锁 | 不消费事件、不join、不推进TLS |
| read_event | 专门Java EventPump | 仅有界condvar等待；不持关键锁跨wait | 足够缓冲才创建lease；复制输出；不ACK |
| ack_event/nack_event | EventPump或Java消费线程/JNI异常清理 | 短delivery锁；不做SDK | ACK消费本地事件，NACK仅未发布对象的本地重排 |
| cancel | 控制线程，包括UI转发的短调用 | 短控制锁，不等待consumer/SDK | 受理本地取消；回收状态由get_info查询 |
| operation_close | 服务生命周期/Cleaner兜底 | 非join | detach+取消，handle仍可query/release |
| operation_release | 后台reaper | 短registry检查 | 仅静止后退休handle，否则E_BUSY |
| begin_shutdown | RuntimeHolder显式停用控制线程 | 短状态变化及有限对象标记 | 拒绝新工作、唤醒、请求取消，不join |
| await_shutdown | 后台shutdown线程 | 用户给定有限等待 | 超时仍持有runtime，禁止free |
| runtime_destroy | 后台shutdown线程 | 短registry检查 | QUIESCENT且无引用时free；不能部分free |

JNI函数不把异常信息、API Key或业务正文写入全局last_error字符串。同步localStatus与异步业务Terminal采用不同错误域：INVALID_HANDLE、BUFFER_TOO_SMALL等是本地ABI结果；GP错误/LSP业务错误/HTTP状态通过事件metadata分层呈现。正常HTTP401/429不能作为native submit的同步返回值。

所有extern C入口需隔离可捕获panic/unwind。不能承诺catch_unwind处理panic=abort、OOM abort或UB；共享状态受损时runtime进入FAILED并有序关闭，不能继续使用被破坏对象。任何异常不得穿过C/JNI ABI。

## 10 必须测试的场景

| ID | 场景 | 必须断言 |
| --- | --- | --- |
| JNI-01 | 系统缺失公共Framework类，mock仍以自身类型加载测试.so | prod/mock复用同源核心与ABI；create/submit/事件接口无账号/AICore依赖，Java不能伪造验证结果或运行时切换身份；额外descriptor强化另验 |
| JNI-02 | 两runtime generation、旧operation slot复用、跨进程旧句柄 | OWNER/GENERATION检查拒绝，不能解引用裸地址或命中新对象 |
| JNI-03 | submit后立即修改/释放Java输入数组 | 已准入数据不变；异步工作不使用Java借用指针 |
| JNI-04 | Key预设失败、取消、排队拒绝 | 无secret副本遗留到日志/持久配置，本库拥有的副本按路径清理 |
| JNI-05 | event缓冲不足，再cancel再扩大缓冲read | 首次无pop/无lease；重读遵守新状态，不承诺原peek保留 |
| JNI-06 | JNI构造Event或byte[]注入OOM | 正常NACK重排；cancel时零消费丢弃或已撤销返回TICKET_REVOKED；无重复远端Invoke；不返回半个对象 |
| JNI-07 | 一个operation两个read线程 | 一个成功，另一个BUSY；ticket/eventSequence不分叉 |
| JNI-08 | 重复ACK/NACK、旧ticket、不同字节数 | 最近相同确认可ALREADY；冲突/旧票拒绝；NACK新票但同eventSequence |
| JNI-09 | Observer快、Java消费者慢 | 正常Terminal不越过BODY ACK栅栏；队列与副本总量有界 |
| JNI-10 | callback在执行时cancel或消费期限到期 | 不开始新callback；native清理不等UI；迟到ACK不能复活完成结果 |
| JNI-11 | 取消 queued/setup/upload/SDK阻塞/网络/交付各阶段 | 控制路径都能受理；不kill服务；cleanup事实不冒充已完成 |
| JNI-12 | 管理queued取消、inflight PUT/DELETE abort、QUERY取消与已提交后取消 | queued保证未发；admin不发LSP CANCEL；未知提交按operation_id/ref QUERY，不留Key自动重试；不回滚已提交结果；未知写先QUERY；E_BUSY暂停未发写且原deadline不变 |
| JNI-13 | close与read/ACK/submit并发 | 不UAF；已返回Java副本不借用native；关闭不触发新的listener |
| JNI-14 | SDK abort关闭fd同时另一请求创建socket | 无fd复用误关闭；不破坏其它context/session |
| JNI-15 | beginShutdown与submit/read并发 | 统一准入线性化；read被唤醒；无新SDK工作漏出 |
| JNI-16 | awaitShutdown超时、SDK仍运行，随后destroy | destroy明确BUSY，内存和库保持；worker真实退出后才可释放 |
| JNI-17 | 任意C/JNI边界注入panic/Java exception | 不unwind跨FFI；分类本地错误或原Java异常，不继续使用破坏状态 |
| JNI-18 | App强杀，永久管理结果未知且临时Key尚存 | 连接owner回收请求、TTL回收临时Key；不依赖onDestroy |
| JNI-19 | 字节块中间拆UTF-8，JSON中含非ASCII和NUL语义边界 | 使用UTF-8 bytes，不误用Modified UTF-8；无逐块强制字符串化 |
| JNI-20 | 消费者保留已ACK数组、队列压力 | 库只承诺自身与adapter已配置预算；不虚报任意应用堆内存受控 |

这些为测试规格，尚未执行。header-only C11/C++17语法检查只说明声明可被编译器接受，不是JNI实现、Rust布局互操作、取消时限或设备运行证据。

## 11 与当前设计的最小整合点

1. 主设计增加服务内CaRuntimeModule及Java EventPump/SerialConsumer两条边界，移除任何独立helper回退。
2. 保持LSP无DATA_ACK；把本地ticket的范围写清，避免CA/TA实现者把Java消费ACK编码成新的TA命令。
3. 操作结果、消费结果与清理结果分层；将“确认消费计数”和“消费lease失效后的未知”纳入app-facing结果。
4. 明确runtime READY仅本地准入，TA能力/身份/网络就绪需异步结果。
5. SDK可中止I/O和manager owner cleanup按详细契约适配与实测；额外库身份仅在实际准入阻塞时列入必要适配，不构成默认首版gate。
