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

static uint64_t Now100ns() {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

static std::wstring ModuleDirectory() {
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

class MonitorCallback : public IMonitorCallback {
public:
    std::atomic<EventBus*> bus{nullptr};
    std::atomic<bool>* stopped = nullptr;

    void OnCallback(IMonitorMessage* raw) override {
        EventBus* sink = bus.load();
        if (raw == nullptr || sink == nullptr || stopped->load()) return;
        Event event;
        event.ts100ns = raw->GetHeader()->Time != 0 ? raw->GetHeader()->Time : Now100ns();
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        if (!MapIMonitorMessage(event, raw)) return;
        sink->Push(event);
    }
};

class IMonitorCollector : public ICollector {
public:
    IMonitorCollector(bool enableProcessOpen, bool enableRemoteThread,
                      bool enableCredentialMonitor, bool enableInjectionDeep)
        : m_enableProcessOpen(enableProcessOpen),
          m_enableRemoteThread(enableRemoteThread),
          m_enableCredentialMonitor(enableCredentialMonitor),
          m_enableInjectionDeep(enableInjectionDeep) {}

    ~IMonitorCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_started) return true;
        m_stopped.store(false);
        m_callback.bus.store(bus);
        m_callback.stopped = &m_stopped;
        std::wstring dllPath = ModuleDirectory();
        if (!dllPath.empty()) dllPath += L"\\iMonitor64.dll";
        HRESULT hr = m_manager.Start(&m_callback,
            dllPath.empty() ? IMONITOR_MODULE_NAME : dllPath.c_str());
        if (FAILED(hr)) {
            std::fprintf(stderr, "[edr-imonitor] Start failed: 0x%08lX\n",
                         static_cast<unsigned long>(hr));
            m_callback.bus.store(nullptr);
            return false;
        }

        cxMSGUserSetMSGConfig config{};
        config.Config[emMSGProcessCreate] = emMSGConfigSend;
        config.Config[emMSGProcessExit] = emMSGConfigPost;
        config.Config[emMSGFileCleanup] = emMSGConfigPost;
        config.Config[emMSGRegSetValue] = emMSGConfigSend;
        config.Config[emMSGWFPTcpConnect] = emMSGConfigSend;
        config.Config[emMSGWFPUdpConnect] = emMSGConfigSend;
        if (m_enableProcessOpen)
            config.Config[emMSGProcessOpen] = emMSGConfigSend;
        if (m_enableRemoteThread)
            config.Config[emMSGThreadCreate] = emMSGConfigPost;
        if (m_enableCredentialMonitor) {
            config.Config[emMSGHookReadProcessMemory] = emMSGConfigSend;
            config.Config[emMSGFileRead] = emMSGConfigPost;
        }
        if (m_enableInjectionDeep) {
            config.Config[emMSGHookQueueApcThread] = emMSGConfigSend;
            config.Config[emMSGHookSetContextThread] = emMSGConfigSend;
            config.Config[emMSGHookWriteProcessMemory] = emMSGConfigSend;
        }
        hr = m_manager.InControl(config);
        if (FAILED(hr)) {
            std::fprintf(stderr, "[edr-imonitor] message configuration failed: 0x%08lX\n",
                         static_cast<unsigned long>(hr));
            m_stopped.store(true);
            m_manager.Stop();
            m_callback.bus.store(nullptr);
            return false;
        }
        if (m_enableCredentialMonitor) {
            /* Driver-side "first read per handle" filter keeps hive-read
             * telemetry bounded; failure is not fatal. */
            cxMSGUserSetSessionConfig session{};
            session.FilterFileReadOnlyFirstEvent = 1;
            hr = m_manager.InControl(session);
            if (FAILED(hr)) {
                std::fprintf(stderr,
                    "[edr-imonitor] session configuration (file read filter) failed: 0x%08lX\n",
                    static_cast<unsigned long>(hr));
            }
        }
        m_started = true;
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
    MonitorCallback m_callback;
    std::atomic<bool> m_stopped{true};
    bool m_started = false;
    bool m_enableProcessOpen;
    bool m_enableRemoteThread;
    bool m_enableCredentialMonitor;
    bool m_enableInjectionDeep;
};

ICollector* CreateIMonitorCollector(bool enableProcessOpen,
                                    bool enableRemoteThread,
                                    bool enableCredentialMonitor,
                                    bool enableInjectionDeep) {
    return new IMonitorCollector(enableProcessOpen, enableRemoteThread,
                                 enableCredentialMonitor, enableInjectionDeep);
}

} // namespace edr
