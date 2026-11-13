# 灵触—灵润—xkernel 密钥保护 MVP 需求 v0.5

日期：2026-11-13。用途：当日开发与领导Demo。用户已经确认本版场景、协议收敛与单路优先；实现和设备验收尚未完成。本文覆盖旧v0.4中要求首版三协议、双并发和共享系统VM集成的执行优先级；旧稿保留为后续扩展参考。

## 1 今天必须完成的闭环

用户在系统设置中配置官方DeepSeek提供商与deepseek-flash；Key通过灵润进程内CA写入xkernel TA，后续请求仅使用引用。灵触按既有双Alt加圈选交互，选择文字摘要、理解、翻译或润色；灵润通过CA把请求送入TA，TA注入认证并处理上游TLS，Android CA仅转发公网密文字节，响应经TA解密后按原raw回调回到灵触展示。复制仍是本地功能。

不涉及账号登录，不增加独立Android CA服务/HTTP代理/native helper，不要求先完成非阻塞身份或ACL强化，不接管Android系统KeyMint/HAL。TA内Key持久存储、真实TLS、错误时无明文旁路不能为了赶时间省略。

## 2 实际请求范围与优先级

主入口固定为`persist.sys.magictouch.system_ai_raw=true`下的`SystemAiManager.submitCloudRaw`。用户已设置此属性，不把属性false当备用通路；false实际选择灵触自身OpenAI客户端，而非灵润普通submit，可能绕开本项目。

| 优先级 | 场景 | 必须覆盖的请求/行为 |
| --- | --- | --- |
| P0 | 文字摘要、文字理解、翻译、润色 | 同一OpenAI Chat Completions协议，POST /chat/completions（等价/v1路径由固定profile统一），stream=true；SYSTEM+USER文本，提示词/温度/输出预算不同 |
| P0 | 保存Key与模型选择 | PUT/QUERY及必要DELETE；保存前测试用临时引用；GET /models及JSON响应亦经TA，不留绕过TA取Key的路径 |
| P0 | 本地复制 | 无模型请求；识别阶段可能本地OCR，复制写剪贴板；不计作TA/DeepSeek成功 |
| P0 | 响应及失败 | raw HTTP状态、Content-Type、SSE字节；JSON错误体、null字段、正常[DONE]、截断、超限、取消；不因已有文字假报完整成功 |
| 后续独立项 | 图片理解 | 与文字理解不同：USER文字+图片AiInput/FD，需多模态编码和大小验收；当前主演示固定文字材料，图片不得冒充已验收 |
| 后置 | Responses、Messages、其它厂商/文件/网页动作、UI逐字显示 | 不阻塞本次单路文字Demo |

当前灵触长文本判定为非空白字符至少80或至少3个文本块；只有长文本才同时出现五项菜单。短文本只有理解/翻译/复制。首演准备普通中英文长段落，不拿短词、链接、图片或文档菜单混验五动作。

## 3 并发的最新决定

用户确认：CA和TA预留并发扩展，当前不做完整并发实现。MVP两端各自执行`max_concurrent_requests=1`，额外生成在准入前明确返回E_BUSY；不无限排队，不覆盖旧TLS/Key/缓冲。管理写与生成之间也先用明确串行准入，不要求首版管理并行。

仍必须有request_id、ta_epoch、session_nonce、call_seq、独立RequestContext、明确所有权和限额协商；只有真的清理结束才返还请求位。CANCEL/超时不能排在阻塞的数据队列后；取消已受理不等于SDK/TA已释放。旧结果不得落到新请求，不能用一个可复用全局relay覆盖在途对象。保留现有wire字段与命令，不为单路版另造不可扩展协议；以后把限额增到2还须实现和验证真实隔离，不能只改数字宣称支持。

## 4 当日验收

| 编号 | 验收条件 |
| --- | --- |
| MVP-01 | .18上独立protected xkernel VM真实启动，固定kernel身份正确；不改系统HAL/原镜像/既有VM；断开调试终端后仍可用 |
| MVP-02 | 整合CA的同包同签名灵润覆盖安装后，原系统设置入口仍可打开、原灵触可重连；公共Framework/Binder契约不变 |
| MVP-03 | Key写入TA且读取非秘密状态可确认；Android持久配置仅有引用/版本；受保护请求不调用旧取钥/HTTPS旁路 |
| MVP-04 | 同一Key完成四种文字动作并在真实灵触显示；复制正确且不依赖模型调用 |
| MVP-05 | 单路连续至少20次成功完成且不积累请求/连接；第二个请求明确忙，第一条不受影响 |
| MVP-06 | 一次取消/超时后能重新请求；没有旧回包串入新任务、没有未知生成自动重放 |
| MVP-07 | 停止本项目专用可信VM后模型请求明确失败；恢复同一instance/data后Key引用可继续使用，无需重新录入；不伪装成功或回退直连 |
| MVP-08 | 演示前固定材料、模型、产物、CID配置与网络预检通过；记录未通过项，不能以mock/模型检查代替设备结果 |

20次是首版稳定性门槛，不是绝对可靠性保证。上游网络与服务商不可控，必须有预检、有限等待和明确恢复步骤；不做静默换模型/直连等假成功兜底。

## 5 当前证据

.18更新后已存在51个所需Framework类及灵润服务；普通submit真实调用deepseek-flash返回了唯一标记、完成事件和54/20 token用量，但文本前多11个null。它证明基础服务/凭证可用，不是灵触raw或TEE通路验收。

实际灵触APK反编译确认：raw解析已有JSON null防护，先聚合SSE后展示；它不严格要求[DONE]/finish_reason。当前OpenAI Chat编码也没有把App的max_output_tokens发送给上游。两项均在设计中处理：raw完成语义必须补齐，输出预算必须验证实际发包，而不是把选项值当已经生效。

额外raw探针已编译，但签名时compiler连接超时，尚未执行。尚未操作真实屏幕圈选、启动新的xkernel、迁移Key或替换灵润；临时测试App及设备诊断JAR已清理，用户raw开关和配置保持不变。

配套：[MVP实现设计](magictouch-deepseek-mvp-v0.5.md)、[给CA同事的任务单](CA-INTEGRATION-HANDOFF-MVP-v0.5.md)。
