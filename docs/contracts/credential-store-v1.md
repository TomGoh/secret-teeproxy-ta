# 凭证库与 receipt 提交设计 v1

状态：外部评审后的功能设计提案，待双方确认、实现和设备验证。适用固定 kernel.bin 基线对应的 80e0e923c2fbcaef038edb4c551960a702aa73fa 接口；不修改内核，不增加身份增强。配套 [LSP/1](ca-ta-protocol-v1-draft.md) 与 [存储源码证据](../../artifacts/functional-design-completion-20261112/storage-evidence.md)。

## 1 首版唯一算法

采用 **GP 对象中的 vault 双完整快照 + 长持独占 anchor**。每份快照包含全部永久凭证记录，每条记录把 Key、状态、单调版本和最后一条 operation receipt 放在一起。不是分别写 Key 文件与 receipt 文件，也不使用 rename 或公开 fsync 构造事务。

选择全 vault 快照而不是每 ref 多对象事务的原因：首版永久记录规模有界，管理写入本来串行；一次完整快照包含所有当前索引与保留的tombstone，可避免对象枚举不完整或损坏对象被底层删除后，把存储异常误当成空库。合法GC后的absent不提供历史证明。两槽用于保存提交前后两个完整版本，**不提供坏槽时自动回退旧 Key 的恢复策略**。

正常中断后只有旧完整快照或新完整快照时可确定恢复；任一 READY 槽坏、缺失、读取失败或版本关系异常时隔离整个 vault，返回存储错误。不能用另一槽“看起来可读”就恢复已删除的旧 Key。

首版将活跃配额与退休记录保留分开，避免正常新增/删除或保存前测试累计64次后永久耗尽：

| 配置字段 | 值 | 计数与作用域 |
| --- | --- | --- |
| max_persistent_live_refs | 64 | 当前全vault的永久live记录 |
| max_persistent_records | 192 | 永久live + 尚保留的deleted记录 |
| max_temporary_live_refs | 64 | 当前TA实例的临时live记录 |
| max_temporary_records | 192 | 当前实例的临时live + deleted/expired记录 |
| tombstone_retention_ms | 600000 | 退休记录最短保留窗口；只有到期才有资格GC |
| max_snapshot_bytes | 524288 | 永久完整候选快照的实际编码字节上限 |

Key仍为1至4096字节。新建触及真实live上限返回E_LIMIT；live尚有余量但总记录槽位被待回收退休记录占满时返回暂时E_BUSY，不能为新写FIFO提前淘汰未到期receipt。更新原live不新增记录；DELETE把已有live原槽位改为tombstone，立即释放live配额且不增加总记录数。真实候选快照在写前测量长度，超限返回E_LIMIT，不发送截断数据。

按当前闭合字段、64字节namespace/profile、32字符ref/opId、64字符内部指纹、u64最大十进制版本和4096字节Key计算，64 live + 128 tombstone的规范快照为439931字节，距512KiB上限余84357字节。该结构上界保证DELETE不需要另找记录槽或额外快照容量；后续字段或编码改变必须重算，不能仅沿用计数上限。以上是格式/模型结果，不是设备性能结论。

## 2 实际 GP 接口和适配规则

所选候选 rust-libutee 0.2.2 源码为 2a42b2976e57f72ca555c493e41c784d37b10285。xtee-utee 0.2.3 使用该库的存储 API。最终构建仍要锁定确切来源和产物，不能只依赖 crate 版本字符串。

| API | 本设计用途 | 不能假设的语义 |
| --- | --- | --- |
| TEE_OpenPersistentObject | 打开 anchor/快照，明确flags | SUCCESS之外不能读输出；SUCCESS也必须检查handle非NULL |
| TEE_CreatePersistentObject | 将完整新快照作为initial_data写入目标槽，使用OVERWRITE | 错误返回不代表绝对未提交；不能先删目标槽 |
| TEE_GetObjectInfo1 + TEE_ReadObjectData | 校验长度并分块读完整记录 | count只在SUCCESS时可信；短读/额外字节不是空库 |
| TEE_WriteObjectData + TEE_SeekObjectData | 仅初始化阶段把anchor从BOOTSTRAP改为READY | 不用它原地逐字段修改Key/receipt |
| TEE_CloseObject | 释放当前线程拥有的handle | 返回void，不是提交/flush屏障；异常可能触发TEE_Panic |
| TEE_RenamePersistentObject | 首版不使用 | 内核存在no-overwrite rename，但可能rename提交后再报错 |
| TEE_CloseAndDeletePersistentObject1 | 正常凭证DELETE不使用 | 永久DELETE写tombstone，不能物理删除槽或receipt |
| Allocate/Start/GetNext/Free Enumerator | 诊断/测试可用，正常算法不依赖 | 枚举结束的ITEM_NOT_FOUND不能用来掩盖枚举中途损坏 |

固定内核源码的 create/write 会同步对象 htree 并提交目录；下层 pwrite 调用 VFS fsync(true)。这些是源码层面的同步调用事实，不是掉电测试结果；GP没有需要本模块额外调用的公开fsync接口。

关键防御适配：
- 初始化输出handle为NULL；Open/Create即使返回SUCCESS但handle仍NULL，也按E_STORAGE处理，不调用Read(NULL)或返回absent。
- GetObjectInfo1失败时忽略其已复制的info；Read失败时忽略count和数据。
- 记录总长先限制在MAX_SNAPSHOT_BYTES；按不超过32 KiB的小块读取，最终验证dataSize、记录长度、checksum、vault_id和记录结构，不接受截断/尾随数据。
- SDK对非预期错误和Close失败可能调用TEE_Panic。该路径不是普通Result，也不能假定catch_unwind可恢复；进入第10节的实例故障路径。

## 3 跨实例单写者与线程归属

TA必须从固定内核认可的 /tee/ta/{项目UUID}.ta 规范路径运行，以取得正确TA UUID存储上下文。不能挪到任意 /tee/lsp 路径后仍假定具有相同GP身份。

创建一个长期 StorageWorker 线程。它持有对象ID `lsp.v1.vault.anchor` 的GP句柄：
- storageID = TEE_STORAGE_PRIVATE；
- flags = ACCESS_READ | ACCESS_WRITE | ACCESS_WRITE_META，即0x7；
- 不设置 SHARE_READ、SHARE_WRITE；
- 句柄持有到整个TA实例停止服务之后才关闭。

固定内核的 POBJS 是全局表，按TA UUID、object ID和后端匹配；ACCESS_WRITE_META具有排他性。即使两个manager分别启动同UUID进程，第二实例Open/Create该anchor也应得到ACCESS_CONFLICT并拒绝启动vault，不得删除或覆盖anchor解锁。manager的single_instance只作为部署配置，不作为唯一互斥依据。

GP对象句柄表是当前线程上下文的一部分。**所有Open/Create/Read/Write/Seek/Close，包括anchor，从同一个StorageWorker执行；不把GP handle发给其他会话线程。** 会话线程通过有界任务队列请求管理操作，推理读取已验证的内存快照及撤销标记，不等待GP I/O。

正常退出：停止准入、取消依赖对象 → 等StorageWorker正在进行的GP调用结束 → 在原线程关闭快照handle → 最后关闭anchor → 线程退出。内核线程退出路径也调用TEE资源清理，但真实异常退出释放仍需设备probe确认。锁未释放就拒绝新writer，不采取强行删除anchor或忽略冲突的方式恢复。

## 4 对象、编码与初始化

固定三个GP对象ID，均远小于64字节限制：

| object ID | 内容 |
| --- | --- |
| lsp.v1.vault.anchor | schema=1、随机vault_id、BOOTSTRAP/READY状态、应用层checksum；也是独占锁对象 |
| lsp.v1.vault.0 | 完整永久记录快照 |
| lsp.v1.vault.1 | 完整永久记录快照 |

anchor固定64字节、LE，结构`<8sHHI16s32s`：magic[8]=LSPANC1加NUL；format:u16=1；length:u16=64；state:u32（0=BOOTSTRAP，1=READY）；vault_uuid[16]按UUID显示顺序；checksum[32]=SHA256(ASCII("LSP-ANCHOR-v1") || 0x00 || 前32字节)。任何长度、magic、版本、状态、UUID或checksum异常均拒绝。两个状态均写完整64字节，不依赖truncate，也不会留下旧JSON尾部。普通运行期间READY anchor内容不再修改。checksum仅检测应用记录完整性，不增加底层安全性保证。

快照头固定64字节，LE，结构 `<8sHHIQII32s`：
- magic[8] = LSPVLT1 加一个NUL；
- format:u16=1、header_len:u16=64；
- payload_len:u32、vault_generation:u64；
- record_count:u32、reserved:u32=0；
- checksum[32] = SHA256(ASCII("LSP-VAULT-CHECK-v1") || 0x00 || 头前32字节 || payload)。

payload为严格UTF-8 JSON：`{vault_id,records:[...]}`。键按字节序排序、无额外空白；记录按(namespace,credential_ref)排序；所有u64使用无前导零的十进制字符串。结构及数量验证先于进入内存状态。每条永久记录包含：
`namespace, ref, profile, version, state(live/deleted), key_b64, receipt`。
live有Key，deleted必须key_b64=null。receipt含operation_id、operation、committed_version、内部fingerprint；receipt版本必须等于该记录当前管理版本。fingerprint按LSP附录A计算，不返回给CA。临时凭证永不写入此payload。快照最多192条且最多64条live；退休保留截止时间只在运行时维护，不写墙钟或跨启动的单调时钟值。每次写入仍校验整个候选的实际长度与结构。

**普通启动禁止自动初始化。** anchor缺失返回E_STORAGE（not_initialized），不是“空的凭证库”。初始化是部署工具显式请求的一次性维护启动模式，仍运行同一规范TA路径，不新增LSP opcode：

1. 确认没有READY anchor；若anchor缺失但已有快照对象，拒绝覆盖。
2. 用无OVERWRITE的Create取得排他BOOTSTRAP anchor；竞争者失败。
3. 建立两份相同的generation=0空快照，关闭并分别重开校验。
4. 同一anchor handle Seek(0)，写相同格式的READY anchor，读回验证。
5. 只有全部成功，才允许普通服务启动。

初始化中断后，普通服务继续拒绝；显式维护模式只可续写一个有效BOOTSTRAP状态下的空generation=0快照。发现非空记录、未知格式、坏anchor或不一致vault_id时停止，不当作首次使用。READY状态禁止重新初始化。初始化模式不是普通CA可调用的“清空数据”接口。

## 5 启动恢复与状态

取得独占anchor后：
1. 校验anchor为READY。
2. 分别读取两个槽；任何GP错误、NULL handle、缺失、坏checksum、格式/内容违规都进入QUARANTINED。
3. 两槽vault_id必须等于anchor；generation差只能是0或1。
4. 相同generation必须包含完全相同的规范记录；否则隔离。
5. 两槽都有效时选择较大generation。初始化两槽同为0时选slot0作为比较基准。
6. 载入永久记录；对每条仍存在的永久deleted记录，以本次加载时TA单调时间重新设置600000ms保留截止点。重启只延长保留，不扣除重启前已经过的时间；不依赖墙钟。临时表为空；产生新ta_epoch，旧请求会话不恢复。

仅在整个vault通过以上校验后，表中没有某ref才能回答absent。absent只表示当前不可用：可能从未存在，也可能已被正常GC，不能证明某次历史PUT/DELETE已提交或未提交。READY anchor存在但两槽都丢失也不能回答空库。底层Read报损坏并删除对象后，下次Open产生ITEM_NOT_FOUND仍被本规则识别为坏槽，不会恢复旧Key。

整个vault状态为 STARTING、READY、MUTATING、QUARANTINED、STOPPING。QUARANTINED禁止新的OPEN/管理变更，QUERY返回读取错误而非absent；必要时使既有对象失败，不能继续以旧缓存宣传持久化正常。

## 6 PUT DELETE 提交算法与可观察结果

管理变更由StorageWorker串行处理。内存状态检查与发布只持短锁，不跨GP I/O持vault长锁。

### 6.1 验证与准备

1. 完成调用准入、字段、大小检查。
2. 同namespace/ref先比较最后receipt：同operation_id且fingerprint相同，返回该receipt与当前状态，不重新写入、不做CAS；内容不同返回冲突。
3. receipt查重之后，无记录DELETE直接返回E_CREDENTIAL_NOT_FOUND，不把absent当虚拟version=0执行CAS，也不视作历史删除成功。无记录PUT要求expected_version=0。对存在的记录，先检查expected_version，冲突返回E_VERSION_CONFLICT。
4. CAS匹配后，若记录仍为deleted/expired，新PUT和新DELETE均返回E_CREDENTIAL_REVOKED，不改版本、不续保留；同末条operation_id的合法重试已在步骤2命中。temporary属性创建后不可改变。GC后服务端不再记得该ref历史，不能宣称永久检测旧ref重用；受信CA契约要求每次新预设生成fresh随机ref/opId，绝不复用旧ref，未知写入只QUERY而不自动重发。
5. 仅新建记录按第1节分别检查live与total数量配额，更新原live和DELETE不因现有数量达到上限而拒绝。然后构造新完整内存候选：显式PUT的profile与Key一并版本化，旧请求仍保留旧profile/Key快照；该记录版本+1；vault_generation+1（仅永久操作）。u64用尽或编码超限在调用存储前拒绝。DELETE把原live槽位改为不含Key的tombstone和delete receipt，不增加总记录数。提交发布时起保留600000ms；对其他已有tombstone保留原截止点，不因本次全量快照写入而重置。
6. 序列化并验证候选完整记录及size，选较旧generation槽为目标；两槽同为0时选slot0。当前最新槽绝不在本轮写入。

### 6.2 写入与对账

7. 管理任务准入时已按第6.5节置全局mutation fence；此时保持fence但不持长锁。新OPEN、QUERY及其他管理变更立即返回E_BUSY（不等待存储）。已OPEN的请求继续使用其固定快照。
8. 确认目标槽旧handle已关闭，用 `TEE_CreatePersistentObject(... flags=0x407, attributes=NULL, initial_data=完整候选 ...)` 覆盖目标槽；禁止先DELETE、分开写Key/receipt或通过rename提交。
9. 关闭取得的handle，然后重新打开两槽，完整读取并校验。Create的返回值不是最终提交分类依据：返回错误也可能已发布，返回成功后读回仍可能失败。
10. 根据下表确定结果；只在确定后发布内存状态和解除fence。失败路径不再补写、清理坏槽或“回滚”候选。

| 对账结果 | commit_state | 行为 |
| --- | --- | --- |
| 新generation、完整内容与本次candidate完全一致，两槽均有效 | committed | 发布新内存快照和最后receipt；DELETE同时发布该ref撤销；可正常回包 |
| 两槽仍完整且选择结果与进入操作前的base完全一致 | not_committed | 不改变内存版本/receipt，解除fence，返回明确未提交错误 |
| 任一读失败/缺失/损坏，或出现非base非candidate的内容/版本 | unknown | 隔离vault，撤销依赖请求，返回需要对账的未知结果；不回到旧Key |
| SDK panic/TA退出/调用时限已到但StorageWorker还在运行 | unknown | 不并发重发；fence保持到原工作真实结束或实例退出后恢复 |

GP函数在返回前后发生进程中断，恢复后按第5节选择完整快照，receipt与Key来自同一版本。完整candidate已存在时即使客户端未收到成功，也按已提交处理；只要最后receipt仍保留，原始expected_version的同操作重试先命中receipt，不产生v+1。CA对结果unknown的管理意图只QUERY，不依赖重放发现是否已提交；GC后的历史证据边界见第6.6节。

### 6.3 磁盘发布与内存发布之间的线性化

在storage调用开始到最终内存发布/隔离之间，OPEN/QUERY/其他写入都经过mutation fence。它们不能观察“磁盘已新、内存仍旧”的中间状态。

已OPEN请求持有不可变Key版本快照。PUT更新不会切换其Key；DELETE只有在已确定提交并发布撤销标记后，才使所有版本的该ref在途请求进入revoked。该点同时发布新管理状态，发生在DELETE成功回复之前。已交给CA/网络的字节无法收回，不宣称撤回服务商已受理的调用。

如果在磁盘candidate提交后、内存发布前TA崩溃，所有旧会话一并失效；重启读回candidate，永久删除状态和receipt恢复，不恢复旧在途请求。

管理调用方退出不撤销已经开始的存储操作。原任务可以完成，新的管理连接在fence解除后QUERY。超时返回unknown不意味着StorageWorker已经停止；只有确实读回base时才返回not_committed。

### 6.4 LSP 映射

- committed：正常管理result，receipt明确已提交。
- not_committed：E_STORAGE_NOT_COMMITTED（0x1207）；不表示可由CA留存Key后台盲重试，后续显式重试仍按operation_id/CAS规则。
- unknown：E_STORAGE + retry=reconcile_management。
- QUERY或启动读取失败：E_STORAGE + retry=none；这是查询失败，不伪造absent，不声称该次读取做了持久化变更。
- 字段/CAS/配额拒绝沿用对应错误码，保证存储调用尚未发生。

提交结果和存储健康分开记录。存储恢复后QUERY得到已提交receipt，可以结束此前unknown；若保留证据不足，unknown不能被猜成not_committed。

### 6.5 管理等待预算与排队撤销

backend固定management_reply_wait_ms=2000，小于manager的3000ms转发预算；不是等待GP完成的无限超时，也不是宣称底层调用可在2秒内中断。该预算从TA接受管理变更任务进入本地任务槽时计算。

首版全vault最多接纳一个未完成永久变更任务（包括QUEUED与RUNNING，内部GC也共用这个槽位），额外变更在准入前返回E_BUSY。准入与置mutation fence在同一短临界区完成，防止此前unknown操作仍排队等待时，另一个QUERY误把旧状态当成最终未提交。任务保存自身Key副本、candidate/base和operation标识，不借用会话worker或GP调用者的临时缓冲。独立清扫器仅在槽位空闲时提交GC，不另开writer；管理调用不能撤销已经RUNNING的GC。

任务状态：QUEUED → RUNNING → DONE_COMMITTED / DONE_NOT_COMMITTED / DONE_ERROR；QUEUED也可原子转WITHDRAWN。StorageWorker从队列取任务时用同一个状态锁/CAS把QUEUED转RUNNING，只有成功取得的任务才可发起GP调用。

| 2000ms等待到期或会话退出时的状态 | 确定行为 |
| --- | --- |
| QUEUED，等待者原子撤销获胜 | 置WITHDRAWN，释放任务Key副本/配额和fence；本次明确未发送到存储，仍可回复时返回E_BUSY（stage=credential），不使用结果unknown |
| RUNNING，不能原子撤销 | 仍可回复时返回E_STORAGE + reconcile_management；保持fence与任务所有权，StorageWorker继续处理和发布；不能清除Key或复用任务槽 |
| DONE_* | 返回已经确定的结果；不因计时器稍后到达把known结果变成unknown |
| GP调用卡死或panic | 等待者不能join或无限等待；返回/保留unknown，按第10节STALLED/实例恢复处理 |

随后StorageWorker成功完成时仍发布快照/receipt并清除fence，新的管理连接才能QUERY对账。写入最终失败且读回base时可以确定not_committed；读回损坏则隔离。该完成不依赖原会话仍存在。

管理Close/cancel只撤销尚未RUNNING的任务，或放弃等待/回包；不销毁StorageWorker、不关闭其线程局部GP handle、不释放已开始操作使用的Key副本。已OPEN请求在fence期间继续固定快照；确认DELETE后的撤销点仍为第6.3节的内存发布。持久存储任务没有被“短STEP”承诺覆盖，管理会话等待本身必须遵守本节的有限预算。

### 6.6 退休记录保留与回收

退休记录用于在有界窗口内保留最后receipt和拒绝旧ref复活，不是无限历史日志。永久deleted、临时deleted/expired统一保留至少600000ms；独立清扫器只收集已到期记录。创建请求既不触发提前GC，也不以FIFO淘汰尚未到期记录。达到总记录上限时允许返回E_BUSY；清扫时机与存储故障可能延长等待，不能承诺第600000ms立即出现空位。

永久退休截止点是TA内存中的单调时钟值：本实例DELETE在确认提交并发布时设为now+600000；启动恢复的每条deleted记录重新设为load_now+600000。无关PUT/DELETE、GC写其他记录和receipt重放都不能重置既有截止点。重启只会延长保留，频繁重启可能延长容量占满时间，不能依赖墙钟或猜测停机时长提前释放。更新与删除过期判定使用同一短临界区的当前状态。

永久GC由同一个StorageWorker执行，与管理写入采用相同的mutation fence、双完整快照与读回规则：

1. 准入时固定base和本次已到期集合；若没有到期项，不写存储、不增加generation。
2. candidate只移除该集合，保留其他记录及其Key、版本、receipt原样；vault_generation+1，验证实际编码长度和结构。
3. 覆盖较旧槽并按第6.2节重新读两槽。只有确认candidate提交，才原子发布新catalog和删除相应运行时截止点。
4. 确认仍为base时保留原记录/截止点，清扫器后续可重新尝试；结果unknown、坏槽或读取失败时隔离vault，不能为了释放配额直接删内存记录或回退另一槽。

GC不产生面向CA的新operation receipt，不修改幸存记录的最后receipt，也不增加LSP opcode。清扫器使用有限调度间隔和退避，不能忙循环占用唯一任务槽；具体间隔可调，600000ms是最短保留时间而非精确删除时刻。其磁盘提交与内存发布同样由fence保护，已OPEN的固定快照不因普通GC被替换。

临时GC在内存短临界区移除到期deleted/expired记录，不写永久快照，不增加vault_generation。TTL到期先执行expired转换、清除catalog Key并撤销该ref在途请求，然后从该转换发布时起计算600000ms保留；不能把原TTL截止点直接当作GC截止点。临时记录的保留承诺只适用于当前ta_epoch，TA重启后临时Key与receipt仍按既有契约全部失效。

**撤销对象独立于catalog条目存活。** OPEN请求持有该ref生命周期的独立撤销Arc；DELETE/TTL使它永久置revoked。删除catalog条目和截止点不能解除旧Arc的撤销，也不能让后来创建的同名条目复用旧Arc。GC只回收catalog占用；它不代表立即擦除仍被取消中请求引用的Key副本，也不提供底层物理擦除证明。

GC以后QUERY absent只证明当前不可用，既不证明从未存在，也不证明此前PUT/DELETE已提交或未提交。CA可据当前不可用解除本地绑定，但原管理意图的提交事实仍为UNKNOWN；未知意图只QUERY，不自动重发或恢复旧Key。新预设始终使用fresh随机ref/opId。服务端只在退休条目仍保留时保证拒绝该ref复活和最后receipt查重；有界GC之后不再保存历史，不能宣称永久检测蓄意旧ref重用。窗口外重用检测属于后置增强，当前由受信CA不复用ref的契约约束。

## 7 临时凭证与并发对象

临时凭证位于TA进程的独立内存表，归namespace/ref，不归创建它的management session；关闭该session不删除。PUT/DELETE的Key、版本和receipt在同一个短临界区更新，返回前完成内存发布，不修改vault_generation。

- TTL从成功内存发布时在TA单调时钟上计算，范围按协商max_temporary_ttl_ms。
- 到期把状态置expired、擦除本表Key并标记所有该ref在途对象撤销；版本/最后receipt保持不变，重复原PUT返回当前expired状态及原receipt，不续期。
- 针对live的显式DELETE版本+1并产生delete receipt；对已expired/deleted的新DELETE遵守第6.1节CAS后REVOKED，不续保留。本epoch内保留deleted/expired非秘密tombstone至少600000ms。live上限64、含退休记录的总上限192；DELETE沿用原槽位，退休后由独立清扫器按第6.6节回收。
- 更新同ref必须保持temporary=true；更新生效后新OPEN使用新版本，旧请求快照继续，直到DELETE/TTL撤销。
- TA重启临时表和receipt全部消失。CA不能据QUERY absent自动用旧ref重放PUT；重新预设用新ref和显式Key输入。
- 永久和临时引用在当前实例中不得冲突；不同namespace可以使用不同记录，但配额按全vault计。

正常查询在内存验证快照中完成。StorageWorker是唯一GP所有者；会话线程不接触它的handle。撤销标记是请求共享的非秘密状态，不依靠跨线程复用GP句柄。

## 8 存储契约、故障范围与恢复路径

算法所需的底层功能契约：
1. GP成功写入并完成内部同步后，在TA进程重启后仍能读取相应完整对象；失败可能发生在发布前或发布后，应用必须读回。
2. 对一个快照对象的更新不破坏另一对象和已持有的anchor；正常更新中断后对象为旧/新完整记录，或明确可检测的错误/损坏。
3. 同TA UUID相同anchor的META独占Open在不同实例之间有效；持有者退出后可释放。
4. GP对象命名空间与实际TA UUID一致，所存数据随正常用户态更新保留。

源码支持这些契约的调用路径，但仍需要固定设备probe确认。不承诺来自本模型的断电持久化、磁盘坏块容错或底层安全性证明。checksum只是应用记录完整性检查，不是抗恶意篡改的新密码保证。

**正常崩溃恢复**：重新取得anchor，读取两个有效槽并选择最高generation；base或candidate都可判定，自动继续正常服务。此路径不需要rename、回放历史请求或回退存储。

**读写损坏/缺槽隔离**：首版不提供自动修复。停止该vault服务，保留原始disk/存储证据和版本，排除正在运行的旧StorageWorker；修复下层可用性后重新只读加载。只有同一vault_id的两个完整、相邻且一致的快照重新可读，才恢复READY。不能把旧有效槽复制覆盖坏槽，不能为了继续运行清空instance/data，也不能把代码回退同时做成凭证数据回退。

若存储内容永久不可恢复，则保持不可用，交付可定位诊断。重新初始化属于显式数据恢复/废弃旧库的维护操作，必须保留证据、作废旧客户端引用与namespace、由用户重新提供Key创建新ref；不属于普通启动或自动重试。首版不宣称从损坏中无损恢复所有Key。

若独占或持久化probe失败，项目功能门禁不通过：模块测试可以继续，设备永久托管不得伪报完成，也不静默降级为临时存储；固定kernel保持不动，报告所需最小用户态适配或不具备的底层契约，不能擅自换存储算法或去写Android明文副本。

## 9 只读根盘上的实际存储装载方案

### 9.1 本设备选路已经确定

真实只读/proc/mounts显示 /dev/vdb 挂为 / 且ro，没有/data。Android侧 /metadata/xkernel_vm/data.img 的超级块位置只读检查未发现ext4 magic；只能说明该区域无ext4超级块，不能推断整盘为空。因此**不使用、不格式化、不修改该既有data.img**，也不执行旧/sbin/vdc-mount中的首次格式化分支。

固定80e的GP REE后端不是目录可配置的外部RPC：common/file_ops直接访问本地VFS，CFG_TEE_FS_PARENT_PATH固定/tee/，目录文件为/tee/dirf.db，数据文件为/tee/下十六进制编号。仅新增TA或传递object ID不能把它重定向到/data。

**首版确定采用独立项目数据盘 + 全局早期bind装载。** kernel.bin哈希、现有instance.img/data.img和原有前三块设备顺序不变；必要变更包含disk.img内启动配置、用户态launcher的附加盘选项、一个新的项目数据镜像。不是“只改disk.img”。

### 9.2 Android侧附加专用盘

1. 离线在新路径生成16 MiB的lsp-data.img，仅对不存在的新文件执行格式化；不得把既有data.img复制后mkfs或用其作为输出路径。设备目标路径拟定/metadata/xkernel_vm/lsp-data.img；宿主空间预算、原launcher/rc哈希和Android分区改动见[平台集成合同](platform-integration-v1.md)。本次/metadata实际可用50330KiB，原64MiB初值已撤销。
2. 格式固定ext4、block=4096、inode=256、label=LSPDATA，独立随机filesystem UUID写入发布清单及guest只读配置。feature集合与已核对根盘一致：has_journal、ext_attr、resize_inode、dir_index、filetype、extent、flex_bg、sparse_super、large_file、huge_file、dir_nlink、extra_isize；不启用metadata_csum、64bit等未经本基线核验的额外feature。生成后由dumpe2fs检查真实集合，不只相信mkfs参数。
3. launcher新增项目专用可选参数--lsp-data（目前不是已实现功能），需要system_ext Rust二进制和rc的构建/部署。可选镜像校验/打开成功才在原三个--block之后追加第四个ro=false块设备；失败按原三盘启动并报告LSP不可用，不调整instance/rootfs/data的序号、模式或文件，不拖住共享VM的既有服务。
4. guest预期为/dev/vdd，但启动helper以固定filesystem UUID核验唯一块设备，不能只相信vdd名称。重复UUID、找不到目标、大小/格式不符均失败。
5. lsp-data.img首次部署后就是运行数据，不再随APK/disk.img更新重复覆盖；更换用户态代码时继续附加同一数据盘。保留其持久化与备份责任，但不把镜像内容/真实Key放进普通构建日志。

与GP对象内部vault_uuid不同，ext4 UUID用于选定附加块设备。启动helper不使用mkfs、fsck -y、擦除或自动修复。

离线新文件的格式化命令应使用`-O none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize`清空工具默认feature后显式加入上述集合，并用`-b 4096 -I 256 -E lazy_itable_init=0,lazy_journal_init=0 -L LSPDATA -U <发布清单UUID>`固定关键参数。只对已确认不存在的普通输出文件创建16777216字节镜像；运行路径/data.img、instance.img和任何块设备均不接受为格式化目标。mke2fs的none语义已经由本机手册确认，实际生成与guest挂载仍需门禁验证。

### 9.3 guest挂载布局

修改后的只读rootfs预先包含两个空目录/tee-ro和/lsp-data，以及项目启动helper。 同时在离线镜像预建/run/lsp → /tmp/lsp的符号链接；不全局重挂/run。早期helper只创建/tmp/lsp/gen（0700），具体代目录由supervisor独占创建：/run/lsp/gen/<manager_epoch>/registry.sock及同目录<instance_epoch>.rpc.sock、.life.sock。只处理本项目拥有的socket及epoch目录，不能unlink旧/tmp/server.sock或其它服务路径；发现未匹配的已有/run/lsp配置时失败而非覆盖。固定80e提供普通ext4 mount、MS_BIND、MS_BIND|MS_REMOUNT；初始bind继承源mount属性，支持目录/文件同类型映射，普通fork继承同一mount namespace。无需内核补丁。

在**任何GP持久存储调用及manager/TA启动之前**执行：

1. 确认没有已启动的GP writer；检查现有mount布局。若已经是本项目预期映射，只验证并返回；若/tee已有其它挂载或有未知writer，不覆盖它，停止LSP启动。
2. 以read-write ext4方式将已核验的新项目卷挂到/lsp-data。失败即停止，不尝试格式化，也不改挂原有vdc。
3. 将原始只读/tee非递归bind到/tee-ro，并显式bind-remount只读。它保存当前disk.img中的原始代码视图。
4. 在项目盘创建/lsp-data/gp-reefs及所需挂载占位项。将这个目录bind到/tee，得到可写GP根目录。GP的dirf.db与编号文件此后落到专用盘。
5. 把/tee-ro/ta只读bind回/tee/ta；把现有/tee-ro/biometrics只读bind回/tee/biometrics；将新增项目代码/config目录/tee-ro/lsp只读bind回/tee/lsp，保证supervisor、manager和backend.json不会被顶层覆盖隐藏；若本发布清单有/tee-ro/lib，同样只读bind回/tee/lib。将原只读vsock-manager文件bind到/tee/vsock-manager的空文件占位。对已见的旧服务/tee/data路径加只读空目录保护，目录存在性差异及fallback行为纳入平台合同兼容清单。所有代码别名继承只读属性，并在完成后验证。
6. 校验/tee顶层可写来自指定项目卷，/tee/ta等代码来自当前disk的只读映射；已有TA/manager二进制哈希保持，项目TA位于规范/tee/ta/{uuid}.ta。只有此时才允许启动原有服务及LSP组件，再进行显式vault初始化。
7. 不把TA代码复制到长期数据盘形成随版本残留的第二份代码；disk.img升级后只读别名自然指向新镜像。数据盘中的ta/biometrics/lib空目录和manager占位只是挂载目标，不能直接作为代码源。

/tee/dirf.db和十六进制数字文件名属于共享GP后端保留空间；部署清单不得安排同名代码文件。运行中不得重新切换/tee挂载。

示意：

```text
只读 disk.img:
  /tee-ro/ta/...       -- RO bind --> /tee/ta/...（原规范路径）
  /tee-ro/biometrics   -- RO bind --> /tee/biometrics
  /tee-ro/lsp          -- RO bind --> /tee/lsp（项目supervisor/manager/config）
  /tee-ro/vsock-manager-- RO bind --> /tee/vsock-manager
专用 lsp-data.img:
  /lsp-data/gp-reefs   -- RW bind --> /tee
                                      ├─ dirf.db
                                      ├─ 0,1,2,...（GP后端编号文件）
                                      └─ 上述RO代码子挂载
原 instance.img/data.img：保持原样，不参与这个映射
```

### 9.4 启动入口、全局影响与失败处理

离线rootfs可见/etc/profile按顺序加载/etc/profile.d；已有30-tee-ta-autostart.sh和vsock_manager_autostart.sh会启动TA/manager。固定kernel entry/init.sh在有OpenRC时执行/sbin/init，否则进入login shell；不能因为/etc/inittab里有vdc-mount就认为当前已执行（实测/data未挂载）。

因此项目补丁同时覆盖两条启动入口：
- /etc/profile.d/00-lsp-storage.sh以子进程调用同一个幂等helper，不source其主体、不exit/exec替换PID1；等待上限5000ms，只有确认退出/回退才进入基线模式。后续项目/GP autostart按ready、baseline或RECOVERY_REQUIRED分别处理，不能把超时当作已经回退。
- /etc/inittab的sysinit在服务启动前调用同一helper；原vdc-mount自动格式化项在项目镜像中停用或替换为只报告现状的非破坏检查，避免未来OpenRC路径意外格式化未知既有卷。
- helper以/tmp下的启动互斥和实际/proc/mounts验证避免多login shell重复叠挂；不凭一个ready文件就接受挂载状态。

这不是仅对LSP进程可见的目录调整。80e的REE_FS_STATE目录缓存和POBJS为全局状态，不能给LSP单独unshare后另挂/tee，再假定与其它GP客户端完全隔离。**本方案让所有GP调用者在首次使用前共享同一个新的RW后端，同时保持原代码路径只读不变。** 既有Trusty服务可能走另一套存储接口，不能据名称认为无影响，需实际回归。

本次离线/tee只有ta、vsock-manager、biometrics，未见dirf.db或GP编号数据文件；真实/proc/mounts也没有/tee覆盖层。对于未来不同基线若发现已有GP数据，应停止直接启用本方案，先做明确迁移，不自动以空项目库覆盖它。

部分挂载失败且尚无GP调用者启动时，可以逆序卸载本次挂载，恢复原/tee视图，保留项目数据盘，禁用LSP并保持基线原服务路径。已存在GP调用或缓存时不做热卸载/重挂，停止项目启动并进入受控VM维护流程。不得清除data.img、instance.img或已存在GP数据解决失败。

### 9.5 升级和回退

用户态更新继续保留同一个lsp-data.img、ext4 UUID、vault_uuid和GP数据，不覆盖其内容。代码回退仍保留兼容的挂载helper与数据盘附件；不能把/tee退回只读原目录后宣称所有GP持久化仍可用。

若需要彻底退回原始平台布局，应先受控停止全部相关GP用户，归档项目数据盘并明确停用新增持久化能力；不是在线取消一个请求，也不删除数据盘。未知vault schema拒绝加载，不能通过代码回退重置generation或恢复旧凭证。

### 9.6 装载门禁

首版部署必须证明：
- launcher实际追加第四盘，前三盘路径、顺序、RO/RW标志与kernel.bin哈希不变；
- 新卷UUID/feature匹配并可RW挂载，原data.img没有被格式化/修复/覆盖；
- /tee后端RW且代码别名RO，TA规范路径身份仍成立；/run/lsp解析到/tmp/lsp且项目socket可创建，不改变其它服务socket；
- 挂载发生于首个GP存储调用之前，重入helper不叠挂，失败不热切已有后端；
- 写入测试GP对象、关闭TA/重启VM后可读取；old services的启动、KeyMint/相关存储操作和manager使用者按原基线回归；
- disk更新/代码回退不会覆盖项目数据盘，恢复材料可用。

源码和本地镜像核对证明存在这些接口及启动接点；本轮未实际附盘、挂载或重启，不能把这些门禁写成通过。

## 10 StorageWorker 故障与单实例证明

正常TA退出前StorageWorker最后关闭anchor。若GP调用卡住或TEE_Panic使线程不返回：
- 将实例vault标记不可用，停止新OPEN/写入，依赖请求失败或撤销；
- 不强行释放仍被调用使用的对象，不关闭另一个线程猜测得到的GP句柄；
- 不删除anchor、不忽略ACCESS_CONFLICT，不启动第二writer；
- 由[项目恢复合同](project-runtime-recovery-v1.md)中的唯一supervisor对自己直接持有、尚未reap的Child执行整代drain/必要终止；两个Child都真实reap且存储条件可恢复后才启动新代。manager不能猜PID停止TA；ownership丢失进入维护。存储损坏/anchor冲突不自动循环重启，不重启VM或修改kernel.bin。
- 如果这一恢复机制尚未验证，状态保持STALLED/unknown，不能承诺固定毫秒内释放。

这属于全vault的致命存储故障，不是普通请求取消。普通请求取消仍走LSP业务取消，不终止共享TA实例。

## 11 必须执行的真实接口 probe

所有探针使用独立测试TA UUID/namespace和假Key，不能覆盖系统现有TA对象。

1. 规范路径获得TA上下文；创建、关闭、重开、读取完整对象及记录长度验证。
2. 两个同UUID实例争抢META anchor：第二个必须ACCESS_CONFLICT；第一个正常退出/异常退出后再取得，期间绝无双写。
3. 同一个StorageWorker handle跨调用有效；把该数值传到另一线程只作为负向测试，不在生产依赖。
4. 完整initial_data OVERWRITE返回后重开验证；在对象/目录发布附近注入失败，分类base、candidate或unknown，不据返回码推断。
5. TEE_WriteObjectData仅用于bootstrap anchor状态更新；验证正常读回、线程退出后的对象恢复。
6. 请求OPEN并发管理PUT/DELETE，mutation fence使新OPEN/QUERY BUSY，老请求版本固定，DELETE成功前后撤销点唯一。
7. 损坏槽、删除槽、损坏后底层自行移除对象，以及SUCCESS+NULL异常适配，均不能变成absent或旧Key复活。
8. TA重启后永久receipt恢复，临时Key消失；保存成功但回包丢失按原operation_id对账。
9. SDK panic/管理连接abort/进程退出后锁和GP资源回收，以及GP调用仍运行时禁止第二writer。
10. 永久/临时各自超过64次创建与退休后经到期GC仍可继续使用；64 live与192总记录的错误分类、满表DELETE沿用原槽位、未到期receipt不能因新建而被淘汰。
11. 永久GC写中断遵循同样的base/candidate/unknown分类；重启重起永久退休窗口，无关快照不续窗口，GC后旧请求撤销不解除；absent不作为历史管理操作提交证据。

本轮没有执行这些设备probe；它们是算法落地门禁，不能用以下模型替代。

## 12 可执行设计模型

[storage_model.py](../../artifacts/functional-design-completion-20261112/storage_model.py) 用内存磁盘模拟GP对象，执行明确故障切点。运行：

```bash
python3 artifacts/functional-design-completion-20261112/storage_model.py
```

2026-11-12原版44项正向场景通过；6项独立负向对照全部被断言捕获：提前ACK、先CAS再查重、Key/receipt分开提交、忽略坏槽回退、损坏当空库、取消anchor排他。这份源文件、结果与日志保留原样，代表修订前的验证记录。

模型使用可读的符号operation标签和假Key来关注事务状态，不是完整LSP codec或GP实现。模拟的“成功对象写入持久”是显式输入假设，不能由模型结果循环证明。结果见 [storage-model-results.json](../../artifacts/functional-design-completion-20261112/storage-model-results.json)。

2026-11-13配额/回收修订使用独立的 [storage_model_gc.py](../../artifacts/cursor-opus55-review-20261113-005109/storage-gc/storage_model_gc.py)：

```bash
python3 artifacts/cursor-opus55-review-20261113-005109/storage-gc/storage_model_gc.py
```

修订模型66项正向场景、11项独立负向对照全部通过。其中42项为旧回归，另24项覆盖有界回收、永久/临时各130轮使用、满配额DELETE、GC故障切点、重启保留窗口、独立撤销与absent歧义；旧版2项“退休永久计数不回收”假设已被本次规则替代，未伪作继续通过。新增5个负向对照分别注入FIFO提前淘汰、每次快照重置保留截止点、GC解除旧撤销、absent误判DELETE已提交、absent误判PUT未提交，均由对应断言捕获。最大字段候选的439931字节为规范格式大小计算，不是GP吞吐或掉电持久性测试。

详见本轮 [结果](../../artifacts/cursor-opus55-review-20261113-005109/storage-gc/storage-model-results.json) 与 [规则差异和证据边界](../../artifacts/cursor-opus55-review-20261113-005109/storage-gc/README.md)。

