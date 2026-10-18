// Self-protection (anti-tamper / self-integrity) headers
// Categories implemented:
//  1) 自身完整性：进程镜像哈希 + SSDT hook 监控
//  2) 反调试/反分析：无用户模式调试检测 + ETW 会话完整性
//  3) 关键组件自我监控：收集器故障回退 + 空链防御 + 健康心跳扩展
#pragma once
#include <windows.h>
#include <string>
#include <vector>
namespace edr {
  class SelfProtection {
  public:
    bool CheckProcessIntegrity();    // 进程镜像哈希
    bool MonitorSSDTHooks();         // SSDT hook 监控
    bool DetectUserModeDebugger();   // 反调试
    bool VerifyETWSessionIntegrity(); // ETW 完整性
    bool CollectorFailover();        // 收集器故障回退
    bool NullChainGuard();           // 空链/空指针防御
    bool ExtendHealthHeartbeat();    // 健康心跳扩展
  };
}
