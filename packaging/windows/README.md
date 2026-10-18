# Windows x64 安装包

`edr.iss` 使用 Inno Setup 6.7.3 构建独立离线安装器。用户态代理和本地控制台默认选中；测试签名驱动默认关闭。要求 Windows 10 2004 / Windows 11 x64；驱动为 ALL 变体，实际加载必须在准备好的测试 VM 验证。

## 构建

先构建当前 Release `edr.exe`，再用单独构建树以 `EDR_DRIVER_FEATURES=ALL` 构建 `edrdrv`。驱动须先签名；脚本接收签名 SYS 与公开 CER，不接收或打包 PFX、私钥。安装器当前未做发布代码签名。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File packaging\windows\build_installer.ps1 `
  -BuildDir build `
  -IsccPath C:\Tools\InnoSetup\ISCC.exe `
  -DriverPath C:\Build\signed\edrdrv.sys `
  -DriverCertificate C:\Build\signed\edr-test-signing.cer `
  -NodeLicense C:\Tools\node-LICENSE.txt `
  -CrtDirectory 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Redist\MSVC\14.44.35112\x64\Microsoft.VC143.CRT' `
  -BuildVerificationInstaller
```

需要 x64 Node.js/npm、Inno 编译器、VC143 可再发行 CRT 目录及对应 Node 版本的 LICENSE。npm 根据 lockfile 执行 `ci --omit=dev --ignore-scripts`；目标机不需要安装 Node/npm/Visual Studio。未注册的 Visual Studio 环境须显式传 `CrtDirectory`。

`dist/` 输出安装 EXE、SHA-256、公开驱动证书、载荷 manifest 和中文说明。每个载荷文件记录 SHA-256；配置模板清除原有凭据，三角色密钥在目标机首次安装时生成。临时目录和验证安装器位于 `.omo/installer-20261018/`，不随正式包发布。

## 生命周期与权限

- 正常安装限于受保护的 Program Files，数据在 `%ProgramData%\EDRAgent`，只授予 SYSTEM/Administrators。拒绝 UNC、重解析路径、外来数据目录及不属于本安装的同名服务/任务。
- 复用代理 `--install-service/--uninstall-service` 注册 `edr` 自动启动服务；控制台通过 SYSTEM 启动任务运行。代码和依赖位于 Program Files，任务参数绑定该安装的 launcher 与数据目录。
- 控制台 launcher 调用现有 `createRuntime`，指定数据目录、`127.0.0.1:8080` 和随机 ingest/read/admin 密钥。agent 原始告警与 console 导入告警分开；native incident 与 console 读取同一个 `console/incidents.jsonl`。
- 修复保留用户配置和密钥；添加组件只迁移必要设置。已有组件须保留选中，不隐式卸载。需要删除时使用卸载入口。
- 安装启动检查控制台带密钥的 HTTP 访问和代理服务状态。系统集成失败返回非零，显示错误，保留文件用于修复/卸载；只尝试撤销本次新建的系统对象。
- 驱动要求 Authenticode 有效、签名 thumbprint 与构建期值一致，运行中的 Code Integrity 报告 test-signing。没有自动导入证书、修改启动安全或重启；内核仍执行其后续校验。
- 卸载先停止本安装消费者；驱动忙时拒绝继续。程序文件移除，配置/密钥/账本保留。卸载不修改证书信任或启动设置。

## 验证

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\installer_package_tests.ps1 -PayloadDir <构建输出的payload目录>
node tests\installer_smoke_test.js '<验证安装后的目录>'
```

`BuildVerificationInstaller` 以同一脚本/载荷编译 `StagingTest` 版本：当前用户安装，数据目录 `{app}\TestData`，强制 `StageOnly` 跳过 SCM、SYSTEM 任务和驱动注册。用它实测文件安装、修复、卸载与数据保留；smoke 核对文件 hash、打包 Node 启动、鉴权/规则读取、真实代理 selftest 和控制台优雅退出。

上述证据不替代管理员安装、SYSTEM 启动或驱动加载验收；权限 CTest skip 单列。工作区日志不随源码发布。

接口依据：[Inno 组件](https://jrsoftware.org/ishelp/topic_componentssection.htm)、[生命周期与退出码](https://jrsoftware.org/ishelp/topic_scriptevents.htm)、[x64 驱动架构限制](https://jrsoftware.org/ishelp/topic_setup_architecturesallowed.htm)。
