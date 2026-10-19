# 原生防护事件覆盖扩展

2026-10-19，本阶段补齐既有 Defender 与 Sysmon 采集器遗漏的原生证据。复用 Windows 事件订阅、现有 XML 工具、bookmark、EventBus 和 RuleEngine，没有增加扫描器或第三方运行依赖。

## Defender ASR

| 原生事件 | 标准操作 | 规则 | 行为 |
| --- | --- | --- | --- |
| 1121 | ASR_BLOCKED | EDR-521 | high / alert，防护规则阻断 |
| 1122 | ASR_AUDITED | EDR-522 | low / log，审核观察 |
| 1129 | ASR_WARN_BYPASSED | EDR-523 | medium / alert，用户在警告模式下放行 |

这些含义经 [微软 ASR 文档](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events)及 Context7 的 Microsoft Defender 官方文档核对。本机只读枚举 Defender provider 模板确认三者包含 `ID`、`User`、`Path`、`Process Name`，没有行为进程 PID。

`asr_rule_id` 保留原始 GUID，复用 `detection_user`、`detection_path`、`process_name`。System/Execution PID 保存在独立 `defender_provider_pid` 中；事件 PID 为零，身份和创建时间保持未知。ASR 操作不以 Defender 引擎作为处置目标。旧的 1116/1117/5001/5007 映射保持原有行为。

规则要求 `DEFENDER`、来源 `defender_log`、对应事件 ID 和操作一致，GUID 必须是完整的标准格式，允许成对大括号及大小写。缺少或损坏 GUID 的原生日志仍可采集，但不触发这三条规则。不同 ASR GUID 覆盖不同技术，本批没有强行映射成单一 ATT&CK 技术。审核不代表阻断，阻断也不证明感染，用户放行不证明利用成功。

## Sysmon ProcessTampering

[微软 Sysmon 文档](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)将事件 25 定义为进程映像篡改，包括 hollowing 及相关映像替换。现有 Sysmon 订阅新增该 ID；保留原有 ImageLoad、ProcessAccess、CreateRemoteThread、NamedPipe 四个可选事件开关的行为。

事件映射为独立用户态类型 `PROCESS_TAMPERING`（59），不产生进程启动或停止。要求非零 UInt32 `ProcessId`、非空 Image 和原始 Type；可用的 ProcessGuid 继续走既有身份字段。`process_tampering_type` 原样保留未来类型，记录时间不当作进程创建时间。新增事件常量不改变驱动报文布局，也不要求驱动生成此事件。

EDR-524 要求来源 `sysmon`、原生 ID 25、对应标准类型、有效 PID 文本、Image 和 Type；级别 high，动作 alert。T1055.012 仅作调查关联，具体篡改机制需结合原始 Type 和其他证据判断。本批四条规则不执行终止、隔离或删除。

## 使用与验证

启用现有 `enable_defender_log` 或 `enable_sysmon`；相应源须已安装、可读取并生成事件。Sysmon 自身配置需包含 ProcessTampering。本阶段不修改系统防护策略、安装 Sysmon、运行攻击样本或加载驱动。

新增 `edr_sysmon_tamper_tests`，扩展 `edr_defender_tests`；CTest 为两个目标显式传入正式规则路径。测试先证实现有解析器拒绝上述事件，再验证解析到正式规则的正反例、XML 转义、错误 PID、字段缺失、审核/阻断/放行隔离、提供方身份隔离、旧事件兼容和订阅开关组合。生产采集器与测试使用同一订阅查询函数。

生产分发通过 `ProcessTreeBuilder::Observe()` 保持已有更新行为，但不从新类型 59 推断父子关系，避免缺少父 PID 的篡改事件把已知祖先和映像覆盖为未知。回归用例先证实旧分发行为会清空祖先、改变映像及创建虚构根记录，再验证修复，且真正的后续进程启动仍可更新父 PID。

完整 Release 构建通过；58 项 CTest 中 57 项通过、1 项生产隔离恢复测试因权限跳过、0 失败；控制台 182 项通过。现有产品 selftest 的有效、未来、过期和撤销 feed 四种场景均退出零，FIM IOC 规则分别命中 1/0/0/0。生产规则共 517 条，248 个 ATT&CK 技术；采集器、检测器和解析器数量保持不变。独立复核发现的进程树问题已用上述回归修复并复核。

查询测试对两个实际订阅函数生成的 XPath 调用原生 `EvtQuery`，使用存在的 Application 日志验证语法，不以 Sysmon 频道缺失作为通过条件。测试中的 XML 输入和规则联动验证不代替生产日志生成或真实攻击链验证；本机 provider 模板查询只读取事件定义，不触发防护操作。
