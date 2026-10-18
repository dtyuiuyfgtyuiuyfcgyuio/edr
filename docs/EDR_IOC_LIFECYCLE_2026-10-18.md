# IOC 生命周期

在现有自定义情报 feed 中，可以为每个指标设置生效时间、到期时间与撤销状态。沿用 `threat_intel.enable`、`feed_path`、`reload_poll_seconds`、既有匹配面和 EDR-439/440，无需新增采集组件。

```json
{
  "feed": "operator-feed",
  "indicators": [
    {
      "id": "TI-WINDOW-001",
      "type": "domain",
      "value": "c2.example.invalid",
      "confidence": "high",
      "source": "operator",
      "valid_from": "2026-10-18T00:00:00Z",
      "valid_until": "2026-10-25T00:00:00.1234567Z",
      "revoked": false
    }
  ]
}
```

示例为保留域名；日期只说明格式，不代表实时情报。

| 字段 | 行为 |
| --- | --- |
| `valid_from` | 可选字符串，事件时间达到该值才有效，包含起点。省略时无下界。 |
| `valid_until` | 可选字符串，事件时间达到该值即失效，不包含终点。省略时无上界；同时设置起点时必须严格晚于起点。 |
| `revoked` | 可选布尔，默认 false；true 时不匹配。撤销通过现有原子加载/热重载生效并清理旧关联证据。 |

时间格式为严格 UTC `YYYY-MM-DDTHH:mm:ssZ` 或带 1–7 位秒小数的形式；精度上限 100ns。非法日历时间、非 `Z` 时区、超过七位小数、内嵌 NUL、错误字段类型、零 FILETIME 或空/倒置窗口都会返回加载错误。不会截断精度或跳过错误条目。候选失败不替换已经验证的活动 feed，错误由既有加载返回值和热重载日志明确报告。

指标有效性按**事件时间**评估，因此保留完整时间的旧事件可在其历史有效窗口内匹配。`revoked=true` 则阻止当前 feed 中该指标的所有匹配。这里是自定义 feed 对生命周期字段的支持，不提供完整 STIX Bundle/TAXII 导入，也不维护跨 feed 版本的永久撤销记录。

过期证据不会继续提高进程分数。例如同一可靠进程先命中哈希和域名，哈希到期后再命中地址时，只由仍有效的域名和地址计算分数，不再保留哈希加分或输出过期哈希 ID。其他有效证据不会随过期哈希一起丢弃。

无时间戳事件只匹配无时间边界的指标，并执行单事件评分。同一进程的迟到事件同样执行单事件评分，不借用或覆盖未来证据。无可靠进程身份时仍不跨事件关联。生命周期仅影响检测证据，不执行响应处置。

实现复用项目 JSON、事件日志时间解析与 Windows `SystemTimeToFileTime`，不新增运行依赖或日期解析器。命名与有效期概念参考 [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)；日历验证使用 [Windows API](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-systemtimetofiletime)。

## 验证

```powershell
ctest --test-dir build -R threat_intel --output-on-failure
```

既有 `tests/threat_intel_detector_tests.cpp` 新增六组回归：精确时间边界、七类指标入口、非法字段整份拒绝、过期证据移除且保留有效证据、迟到/无时间戳隔离、热重载撤销。正式规则测试额外验证 EDR-439 不再受过期哈希推动，EDR-440 仍接收有效网络证据。旧格式 feed、CIDR、热重载、进程身份和容量回归继续执行。

2026-10-18 验收结果：Release 构建通过；完整 CTest 57 项中 56 通过、1 项权限跳过、0 失败；本地控制台 182 项通过，筛选后的 GitHub 副本 181 项通过。发布副本排除了含静态 TLS 私钥样例的一个测试文件。双方代理均完成真实 selftest 链路的四种 feed 检查：有效 feed 产生 20 条 EDR-440，未来生效、过期和撤销 feed 分别产生零条 EDR-440；这些为注入事件，不发送真实 DNS 请求。

新版安装包 `EDR-Setup-1.1.2026.1018-x64.exe` 的 SHA-256 为 `663ae40110a021a2d66c66d0b940fd3c0f07e180cd741097fa561c6b33b013a6`。同一载荷的文件验证安装器完成安装、修复、卸载和配置/密钥/历史保留检查；676 个默认文件哈希、控制台鉴权、规则查询与优雅退出通过，打包代理也通过上述四种 feed 检查。

权限跳过项为 `edr_quarantine_restore_native_tests`。管理员服务安装、SYSTEM 开机启动、真实驱动加载和 Driver Verifier 尚未实测。安装器未做发布代码签名，可选驱动沿用测试签名版本且默认不选中。
