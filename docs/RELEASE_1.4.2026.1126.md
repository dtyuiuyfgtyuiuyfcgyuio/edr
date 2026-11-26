# EDR 1.4.2026.1126 源码预览

本版提供 EDR 代理和控制台的源码。Windows x64 稳定安装包仍可从 [1.3.2026.1020](https://github.com/dtyuiuyfgtyuiuyfcgyuio/edr/releases/tag/v1.3.2026.1020) 下载。

## 主要变更

- 控制台将事件和告警写入并同步到磁盘后，才更新去重状态、查询索引和广播。写入失败后可重试，批次重试跳过已提交的记录。每个状态目录由单个控制台实例写入。
- 告警、事件和分诊账本启动时各加载最近最多 64 MiB，进程索引随事件窗口裁剪。修正 MCP 事件调查分页提示，默认从最新的 incident 开始。
- 移除 Webhook 日志中的目标 URL 和原始异常文本，补上七个原生采集器的线程启动失败回滚。新增 Windows 日志重放回归，覆盖拒收、重开检查点及补送。
- 添加 Windows x64、Node 24 与规则 lint 回归门禁。生产规则保留原有 ID 和评分行为，门禁拦截新增的 lint 警告。

## 验证范围

本地通过控制台 217 项、MCP 30 项、Syslog 接收器 22 项，以及可移植 C++ 事件总线和规则 lint 单元测试。规则目录包含 526 条规则，lint 为 0 个错误和 23 个已记录警告。

Windows CI 验证 MSVC 构建、CTest 和 Node 套件。管理员安装、SYSTEM 开机启动、真实 Windows 遥测、签名驱动加载和 Driver Verifier 仍待专用虚拟机验收。步骤见 [发布验收记录](https://github.com/dtyuiuyfgtyuiuyfcgyuio/edr/blob/v1.4.2026.1126/packaging/windows/release_verification.md)。
