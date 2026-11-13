# 给CA与灵润整合同事：MVP任务单 v0.5

2026-11-13。可直接作为当前分工入口。目标是当天打通领导Demo，首版单路；并发仅预留扩展。完整方案见[主设计](magictouch-deepseek-mvp-v0.5.md)，跨团队接口见[LSP/1](contracts/ca-ta-protocol-v1-draft.md)。

## 1 你需要实现什么

目标链路：灵触圈选长文字→四个AI动作→`SystemAiManager.submitCloudRaw`→灵润:runtime内CA→xkernel TA→DeepSeek→原raw回调→灵触结果面板。复制是本地操作，不接模型。

请先改`KylinCloudInferenceRuntime.generateRawBlocking()`的自定义provider分支，复用当前消息编码，在读取Android Key和创建带认证的HttpsURLConnection之前转入TeeProviderExecutor。输入给CA的是固定profile、key_ref/version和不带Key的UTF-8 body；输出是HTTP元数据/raw字节或明确错误。

生产CA必须随灵润APK加载；不能开独立CA daemon、HTTP代理或native helper。普通请求不得取Key后交给TA，也不能CA自己完成DeepSeek TLS。CA负责公网DNS/TCP与密文字节搬运，TA负责认证与TLS。

## 2 先做的最小集合

- 同包、同签名APK中加入native库，运行于:runtime；SDK默认/proc/self/exe身份只记录真实结果，非阻塞强化后置，不伪造验证通过。
- endpoint从开发配置读取实际AVF CID和10099端口，不写死201。运行中不更换endpoint；重建前收敛旧请求。
- 首版两端最多1个活跃生成，额外请求E_BUSY。请求ID、session/epoch、call_seq、独立上下文与容量协商保留；真实清理之前不返还名额。
- 保存Key：PUT→确认receipt/QUERY→持久化引用与TEE_REQUIRED→清理目标旧凭证。未知只QUERY，不自动重发。UI成功必须对应可信存储确认。
- Raw请求：OPEN→分块BODY_CHUNK→COMMIT→公网TCP/STEP循环→正确FINISH；取消使用独立控制路径，不等整轮网络结束才处理。
- HTTP状态、Content-Type、正文顺序保留；处理null/usage-only SSE，不改写正文。检查[DONE]/finish_reason；网络EOF或截断不能冒充模型完成。
- 对同一受保护provider，普通推理和/models也复用同一执行器，未支持入口明确拒绝；不保留明文取钥旁路。
- 修正Chat输出预算实际编码：App max_output_tokens目前未发给上游，需明确映射并验收；不把UI选项当已生效。

## 3 两端对接常量和责任

| 项目 | 固定约定 |
| --- | --- |
| wire | LSP/1.0；64B固定头+JSON+payload |
| TA UUID | c86d23b9-e568-509e-a9b2-0ad40668caf5 |
| GP | CMD_EXCHANGE=0x1000；ParamTypes=0x0265 |
| 容量 | p0≤16384B；p1预留32768B；JSON≤4096B |
| TA入口输出容量 | 当前SDK把p1容量放values.a，data初始为空；实际回复写data，p2与frame长度必须相等 |
| endpoint | 本次AVF实际CID；port10099；HELLO核对后端组合 |
| 上游 | 官方DeepSeek、deepseek-flash、CHAT SSE；MODELS GET/JSON |
| 首版并发 | 1；HELLO如实报告1，超额忙；不是宣称已经支持2 |
| 失败 | 无Key直连回退、无未知生成重放、无提前释放活跃SDK对象 |

TA侧负责TA/持久存储/认证与TLS/VM部署，CA侧负责APK模块/SDK客户端/公网socket/灵润适配；不要自行修改旧secret-proxy命令号与本协议混用。内部JNI方法可按团队习惯封装，跨团队wire和生命周期不可单边改动。

SDK实现起点已经选定，避免双方分别追上游HEAD：

| 组件 | 固定提交 |
| --- | --- |
| CA：openkylin/rust-libteec | 1a6c7619bfd1690a426b92115a68d76caa282638 |
| TA runtime：openkylin/xtee-rust-sdk | 6966f624e15d572eea8f08ecd13656349f0c81fe |
| TA syscall：openkylin/rust-libutee | 2a42b2976e57f72ca555c493e41c784d37b10285 |
| 项目manager：openkylin/xtee-apps | f571294dd0898f2e82e0522d43bd045056bcc129 |

这些是源码起点，不是已经实机通过的组合。必要适配用独立patch/源码锁记录；若首次probe证明必须调整版本，先通知另一端并同步合同。CA SDK入口参考用户给出的https://gitee.com/openkylin/rust-libteec，旧demo的525cadc版本不能被当成以上版本的已验证替代。

单路不意味着取消可阻塞：同一context只由原worker调用；控制方提交cancel标志，worker在短STEP间处理，必要时锁外中止transport。旧worker未结束时不可free、重用名额或清零仍被借用的Key缓冲。TA也要拒绝第二个请求，旧OpenSession“清空全局relay”的行为不能原样保留。

## 4 APK与设置集成

保留`com.kylinos.magicsmoothservice`、`.settings.SystemAiSettingsActivity`及SYSTEM_AI_SETTINGS action，公开Binder/Framework接口与hash不改。当前真实系统已补齐51个公共类；不要把编译桩打入APK。

同签名`adb install -r`更新，保留UID/用户配置，不改/system；不要pm clear、卸载预装灵润或备份含Key的整份数据。开发包debuggable用于run-as写非秘密endpoint文件。安装后从原系统设置入口检查，再让灵触重连；不把安装成功当成接口成功。

独立测试App应调用同一灵润服务，只有测试驱动，没有复制CA实现。当前灵触会拒绝任务中再圈选，因此首版只测顺序稳定；未来双并发用两SDK请求单独证明。

## 5 今天给TA侧的最小交付

1. 可构建同签名APK及native产物/源码版本。
2. 正常设置入口仍能配置提供商、迁移/导入Key和显示非秘密托管状态。
3. 一次raw真实请求的ID、HTTP状态、完成事实与取消结果；不含Key、认证头或思考正文。
4. 清晰列出SDK连接/TA接口阻断，不用mock结果或普通submit结果替代raw+TA验收。

本任务单先保障单路真实链路。图片理解、其它模型协议、完整并发、强身份和全自动系统化部署后置。
