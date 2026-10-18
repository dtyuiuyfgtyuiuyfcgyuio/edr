# EDR

Windows 端点检测与响应原型，包含 C++17 代理、本地 Web 控制台、可选内核驱动，以及离线 Windows x64 安装器。

## 安装包

在本仓库的 **Releases** 下载 `EDR-Setup-1.0.2026.1018-x64.exe`，使用旁边的 `.sha256` 校验。Windows 10 2004 / Windows 11 x64，正常安装需要管理员权限。

默认安装代理、本地控制台、Node.js 与 VC++ 应用本地运行库。驱动需要手动勾选；当前驱动仅有测试签名，目标测试虚拟机须事先准备好测试签名与证书信任。安装器不会修改 Secure Boot、启动安全或证书信任。安装器本身尚未做发布代码签名。

程序位于 `%ProgramFiles%\EDR Agent`，配置、密钥和日志位于 `%ProgramData%\EDRAgent`。控制台仅监听 `http://127.0.0.1:8080`；通过开始菜单 **Console access keys (administrator)** 查看目标机独立生成的访问密钥。修复保留配置和密钥，卸载保留历史数据。

详细步骤见 [安装说明](packaging/windows/INSTALL.txt)，构建与验收范围见 [安装器文档](packaging/windows/README.md)。

## 能力

- 多源遥测：进程、文件、注册表、网络、DNS、Windows 事件日志及系统状态采集。
- 行为增强、JSON 规则匹配、MITRE ATT&CK 映射、威胁情报、事件关联和可选行为基线。
- 512 条规则，覆盖 248 个 ATT&CK 技术；36 个采集器、167 个检测器和 10 个解析器。
- 有界队列、持久化上报、重放检查点、采集健康状态和告警审计。
- 本地 Web 查询、事件调查、规则覆盖查询、鉴权和手动响应接口。
- 真实进程处置、隔离及驱动阻断需要显式启用；发布配置中的自动响应和真实响应通道保持关闭。

采集结果受权限、系统审计策略、频道和组件开关影响。统计异常属于调查线索。此项目是原型/测试版本，应先在测试虚拟机验收。

## 从源码构建

需要 Visual Studio 2022 C++ Build Tools、MSVC v143、Windows SDK 10.0.22621.0、CMake 3.20+ 和 Ninja。在 x64 开发者终端执行：

```powershell
chcp 65001
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DEDR_IMONITOR=OFF
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
```

运行代理：

```powershell
.\build\edr.exe --selftest --config config\edr.config.json
.\build\edr.exe --console --config config\edr.config.json --rules rules\rules.json
```

配置文件是已清除凭据的模板，上报默认关闭。需要上报时，设置本机接收端与独立的 ingest 密钥；不要把运行密钥提交到仓库。

`iMonitorSDK` 是外部可选依赖，没有包含在本仓库中。需要启用时自行获取上游 [iMonitorSDK](https://github.com/wecooperate/iMonitorSDK)，检出 `3f3d8774808c16bb066aea0201f4bed3fb71ae07` 到 `iMonitorSDK/`，安装 ATL 后使用 `-DEDR_IMONITOR=ON`。无 SDK 时使用 `OFF`。

## 本地控制台开发

需要 x64 Node.js。以下命令只在当前终端生成临时开发密钥；安装版会自动生成并保护密钥。

```powershell
npm ci --prefix console --ignore-scripts
$env:EDR_CONSOLE_MODE = 'development'
$env:EDR_BIND_HOST = '127.0.0.1'
$env:PORT = '8080'
$env:EDR_INGEST_API_KEY = node -p "require('crypto').randomBytes(32).toString('hex')"
$env:EDR_READ_API_KEY = node -p "require('crypto').randomBytes(32).toString('hex')"
$env:EDR_ADMIN_API_KEY = node -p "require('crypto').randomBytes(32).toString('hex')"
node console\server.js
```

通过 `X-API-Key` 携带对应角色密钥。生产部署应使用现有 production/TLS 配置要求；开发设置只适用于本机测试。

```powershell
npm test --prefix console
```

## 驱动与打包

安装 WDK 后，在独立构建目录使用 `-DEDR_DRIVER_FEATURES=ALL`，构建 `edrdrv` 目标。首次签署驱动、证书管理和测试虚拟机准备由部署者完成；不要提交 PFX 或私钥。使用 [打包脚本](packaging/windows/build_installer.ps1) 传入已签署 SYS、公开 CER、Node LICENSE、VC143 CRT 目录和 Inno Setup 6.7.3 编译器。

## 验证与发布范围

安装包本地验收记录：C++ CTest 56 项通过、1 项权限跳过；控制台 182 项通过。文件验证安装器完成安装、同路径修复、卸载和数据保留检查；676 个默认载荷文件哈希、控制台鉴权、代理自测及优雅退出通过。管理员服务安装、SYSTEM 开机启动、真实驱动加载和 Driver Verifier 尚未实测。

本仓库是筛选后的源码快照，不包含原本地 Git 历史、AI/代理指令、内部施工文档、工作区记忆、运行日志、告警账本、个人环境配置或签名私钥。测试中的固定密钥、哈希和路径为合成测试样例。发布附件中的 CER 仅包含公开证书，密钥在目标机生成。

更新日期：2026-10-18。

发布副本额外排除了包含静态 TLS 私钥样例的单个 HTTPS 测试文件；本地完整 182 项测试结果不代表发布副本的测试数量。发布副本已独立配置并构建代理，控制台 181 项测试全部通过。WebSocket 测试在运行时生成握手 nonce。
