/*
 * collector_reg_baseline.cpp - Optional (default OFF) Run-key baseline
 * differ. Snapshots the well-known autostart keys and emits REG_WRITE
 * events for values that appear or change. This is a fallback only; the
 * kernel registry callback is the primary source.
 */
#include <windows.h>

#include <atomic>
#include <map>
#include <string>
#include <thread>

#include "collector.h"
#include "config.h"
#include "edr_event.h"

namespace edr {

class RegBaselineCollector : public ICollector {
public:
    explicit RegBaselineCollector(uint32_t periodMs) : m_periodMs(periodMs) {}
    ~RegBaselineCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) {
            return true;
        }
        m_bus = bus;
        m_stop.store(false);
        try {
            m_thread = std::thread(&RegBaselineCollector::Run, this);
        } catch (...) {
            m_stop.store(true);
            m_bus = nullptr;
            return false;
        }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

private:
    using Snapshot = std::map<std::string, std::string>; /* "key\\value" -> data preview */

    static void ReadKey(HKEY root, const wchar_t* subkey,
                        const char* displayPrefix, Snapshot& out) {
        HKEY key = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
            return;
        }
        for (DWORD i = 0;; i++) {
            wchar_t name[256];
            DWORD nameLen = (DWORD)std::size(name);
            BYTE data[512];
            DWORD dataLen = sizeof(data);
            DWORD type = 0;
            LONG rc = RegEnumValueW(key, i, name, &nameLen, nullptr, &type,
                                    data, &dataLen);
            if (rc != ERROR_SUCCESS) {
                break;
            }
            std::string id = std::string(displayPrefix) + "\\" +
                             WideToUtf8(name, nameLen);
            std::string preview;
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                preview = WideToUtf8((const wchar_t*)data,
                                     dataLen / sizeof(wchar_t));
            } else {
                preview = "<binary:" + std::to_string(type) + ":" +
                          std::to_string(dataLen) + ">";
            }
            out[id] = preview;
        }
        RegCloseKey(key);
    }

    static Snapshot TakeSnapshot() {
        Snapshot s;
        ReadKey(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", s);
        ReadKey(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", s);
        ReadKey(HKEY_CURRENT_USER,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", s);
        ReadKey(HKEY_CURRENT_USER,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", s);
        return s;
    }

    void Run() {
        Snapshot baseline = TakeSnapshot();
        while (!m_stop.load()) {
            for (uint32_t t = 0; t < m_periodMs && !m_stop.load(); t += 100) {
                Sleep(100);
            }
            if (m_stop.load()) {
                break;
            }
            Snapshot current = TakeSnapshot();
            for (const auto& kv : current) {
                auto it = baseline.find(kv.first);
                if (it != baseline.end() && it->second == kv.second) {
                    continue;
                }
                Event ev;
                ev.type = EDR_EVT_REG_WRITE;
                FILETIME ft;
                GetSystemTimePreciseAsFileTime(&ft);
                ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) |
                             ft.dwLowDateTime;
                ev.fields[field::kType] = "REG_WRITE";
                ev.fields[field::kRegKey] = kv.first;
                ev.fields[field::kRegValue] = kv.second;
                if (m_bus != nullptr) {
                    m_bus->Push(ev);
                }
            }
            baseline = std::move(current);
        }
    }

    uint32_t m_periodMs;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
};

ICollector* CreateRegBaselineCollector(uint32_t periodMs) {
    return new RegBaselineCollector(periodMs);
}

} // namespace edr
