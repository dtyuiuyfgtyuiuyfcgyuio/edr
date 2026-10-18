#include <winsock2.h>
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <vector>

#include "iMonitorSDK.h"
#include "iMonitorProtocol.h"
#include "collector.h"
#include "config.h"
#include "edr_event.h"
#include "imonitor_mapping.h"

namespace edr {

static uint64_t HooksNow100ns() {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

static std::wstring HooksModuleDirectory() {
    std::vector<wchar_t> path(MAX_PATH);
    for (;;) {
        DWORD length = GetModuleFileNameW(nullptr, path.data(),
                                         static_cast<DWORD>(path.size()));
        if (length == 0) return {};
        if (length < path.size() - 1) {
            std::wstring result(path.data(), length);
            size_t slash = result.find_last_of(L"\\/");
            return slash == std::wstring::npos ? std::wstring() : result.substr(0, slash);
        }
        path.resize(path.size() * 2);
    }
}

class HooksCallback : public IMonitorCallback {
public:
    std::atomic<EventBus*> bus{nullptr};
    std::atomic<bool>* stopped = nullptr;

    void OnCallback(IMonitorMessage* raw) override {
        EventBus* sink = bus.load();
        if (raw == nullptr || sink == nullptr || stopped->load()) return;
        Event event;
        event.ts100ns = raw->GetHeader()->Time != 0 ? raw->GetHeader()->Time : HooksNow100ns();
        event.source = "imonitor_hooks";
        event.fields[field::kSource] = event.source;
        if (!MapIMonitorMessage(event, raw)) return;
        sink->Push(event);
    }
};

class HooksCollector : public ICollector {
public:
    explicit HooksCollector(const Config& cfg)
        : m_enableRpcCreateProcess(cfg.enableHooksRpcCreateProcess),
          m_enableWindowsHook(cfg.enableHooksWindowsHook),
          m_enableServiceHooks(cfg.enableHooksService),
          m_enableCoCreateInstance(cfg.enableHooksCom),
          m_enableInjectionHooks(cfg.enableHooksInjection),
          m_enableHandleHooks(cfg.enableHooksHandle),
          m_enableInputHooks(cfg.enableHooksInput),
          m_enableSystemHooks(cfg.enableHooksSystem),
          m_enableSurveillanceHooks(cfg.enableHooksSurveillance),
          m_enablePowerShellHooks(cfg.enableHooksPowerShell) {}

    ~HooksCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_started) return true;
        m_stopped.store(false);
        m_callback.bus.store(bus);
        m_callback.stopped = &m_stopped;

        std::wstring dllPath = HooksModuleDirectory();
        if (!dllPath.empty()) dllPath += L"\\iMonitor64.dll";

        HRESULT hr = m_manager.Start(&m_callback,
            dllPath.empty() ? IMONITOR_MODULE_NAME : dllPath.c_str());
        if (FAILED(hr)) {
            std::fprintf(stderr, "[edr-hooks] Start failed: 0x%08lX\n",
                         static_cast<unsigned long>(hr));
            m_callback.bus.store(nullptr);
            return false;
        }

        cxMSGUserSetMSGConfig config{};

        if (m_enableRpcCreateProcess)
            config.Config[emMSGHookRpcCreateProcess] = emMSGConfigSend;

        if (m_enableWindowsHook)
            config.Config[emMSGHookSetWindowsHookEx] = emMSGConfigSend;

        if (m_enableServiceHooks) {
            config.Config[emMSGHookCreateService] = emMSGConfigSend;
            config.Config[emMSGHookStartService] = emMSGConfigSend;
            config.Config[emMSGHookChangeServiceConfig] = emMSGConfigSend;
        }

        if (m_enableCoCreateInstance)
            config.Config[emMSGHookCoCreateInstance] = emMSGConfigSend;

        if (m_enableInjectionHooks) {
            config.Config[emMSGHookMapViewOfSection] = emMSGConfigSend;
            config.Config[emMSGHookSetContextThread] = emMSGConfigSend;
            config.Config[emMSGHookQueueApcThread] = emMSGConfigSend;
            config.Config[emMSGHookWriteProcessMemory] = emMSGConfigSend;
            config.Config[emMSGHookReadProcessMemory] = emMSGConfigSend;
        }

        if (m_enableHandleHooks)
            config.Config[emMSGHookDuplicateHandle] = emMSGConfigSend;

        if (m_enableInputHooks)
            config.Config[emMSGHookSendInput] = emMSGConfigSend;

        if (m_enableSystemHooks) {
            config.Config[emMSGHookShutdownSystem] = emMSGConfigSend;
            config.Config[emMSGHookSetSystemTime] = emMSGConfigSend;
        }

        if (m_enableSurveillanceHooks) {
            config.Config[emMSGHookGetClipboardData] = emMSGConfigSend;
            config.Config[emMSGHookSetDeskWallpaper] = emMSGConfigSend;
            config.Config[emMSGHookUseCamera] = emMSGConfigSend;
            config.Config[emMSGHookKeyLogger] = emMSGConfigSend;
        }

        if (m_enablePowerShellHooks)
            config.Config[emMSGHookPowerShell] = emMSGConfigSend;

        hr = m_manager.InControl(config);
        if (FAILED(hr)) {
            std::fprintf(stderr, "[edr-hooks] message configuration failed: 0x%08lX\n",
                         static_cast<unsigned long>(hr));
            m_stopped.store(true);
            m_manager.Stop();
            m_callback.bus.store(nullptr);
            return false;
        }

        m_started = true;
        std::fprintf(stderr, "[edr-hooks] hooks collector started "
                     "(rpc=%d, windows_hook=%d, service=%d, com=%d, "
                     "injection=%d, handle=%d, input=%d, system=%d, "
                     "surveillance=%d, powershell=%d)\n",
                     m_enableRpcCreateProcess, m_enableWindowsHook,
                     m_enableServiceHooks, m_enableCoCreateInstance,
                     m_enableInjectionHooks, m_enableHandleHooks,
                     m_enableInputHooks, m_enableSystemHooks,
                     m_enableSurveillanceHooks, m_enablePowerShellHooks);
        return true;
    }

    void Stop() override {
        m_stopped.store(true);
        if (m_started) {
            m_manager.Stop();
            m_started = false;
        }
        m_callback.bus.store(nullptr);
    }

private:
    MonitorManager m_manager;
    HooksCallback m_callback;
    std::atomic<bool> m_stopped{true};
    bool m_started = false;
    bool m_enableRpcCreateProcess;
    bool m_enableWindowsHook;
    bool m_enableServiceHooks;
    bool m_enableCoCreateInstance;
    bool m_enableInjectionHooks;
    bool m_enableHandleHooks;
    bool m_enableInputHooks;
    bool m_enableSystemHooks;
    bool m_enableSurveillanceHooks;
    bool m_enablePowerShellHooks;
};

ICollector* CreateHooksCollector(const Config& cfg) {
    return new HooksCollector(cfg);
}

} // namespace edr