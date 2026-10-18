/*
 * collector_driver.cpp - Driver event collector.
 *
 * Single thread, one OVERLAPPED request at a time:
 *   loop { DeviceIoControl(FETCH, OVERLAPPED) -> GetOverlappedResult
 *          -> validate magic/version/length -> TLV parse -> EventBus
 *          -> immediately re-issue FETCH (always pending) }
 * If the device cannot be opened the collector retries silently every 30s
 * (graceful degradation to fallback collectors). The worker exclusively owns
 * the device, OVERLAPPED, and buffer. Stop() signals a separate event; the
 * worker cancels and drains any pending request before releasing them (M4).
 *
 * M2 command-line enrichment: for PROCESS_START events the agent tries
 * OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) +
 * NtQueryInformationProcess(ProcessCommandLineInformation) +
 * ReadProcessMemory on the returned target-process string pointer, within
 * a ~2ms budget. On any
 * failure/timeout the event keeps EDR_FLAG_COMMAND_LINE_ABSENT and the
 * command_line field is omitted.
 */
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "collector.h"
#include "collector_runtime_health.h"
#include "config.h"
#include "driver_event_parser.h"
#include "edr_event.h"
#include "edr_ioctl.h"

namespace edr {

/* ---- native API declarations (ntdll, resolved at runtime) ---- */

typedef LONG NTSTATUS_NT;
#define NT_SUCCESS_NT(s) ((s) >= 0)

typedef struct _UNICODE_STRING_NT {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer; /* lives in the TARGET process address space */
} UNICODE_STRING_NT;

typedef NTSTATUS_NT (WINAPI* NtQueryInformationProcess_t)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

/* Returns a UNICODE_STRING_NT whose Buffer is a target-process pointer. */
static const ULONG kProcessCommandLineInformation = 60;

class DriverCollector : public ICollector {
public:
    DriverCollector() = default;
    ~DriverCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) {
            return true;
        }
        HANDLE probe = CreateFileA(EDR_USERMODE_PATH,
                                   GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (probe == INVALID_HANDLE_VALUE) {
            m_health.RecordSourceError();
            std::fprintf(stderr, "EDR driver collector: device unavailable (%lu)\n",
                         GetLastError());
            return false;
        }
        CloseHandle(probe);
        m_bus = bus;
        m_stop.store(false);
        m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (m_stopEvent == nullptr) {
            m_health.RecordSourceError();
            return false;
        }
        try {
            m_thread = std::thread(&DriverCollector::Run, this);
        } catch (...) {
            m_health.RecordSourceError();
            CloseHandle(m_stopEvent);
            m_stopEvent = nullptr;
            return false;
        }
        return true; /* runs degraded until the device appears */
    }

    void Stop() override {
        m_stop.store(true);
        if (m_stopEvent != nullptr) {
            SetEvent(m_stopEvent);
        }
        if (m_thread.joinable()) {
            m_thread.join();
        }
        if (m_stopEvent != nullptr) {
            CloseHandle(m_stopEvent);
            m_stopEvent = nullptr;
        }
    }

private:
    void Run() {
        m_health.WorkerStarted();
        struct ActivityGuard {
            CollectorRuntimeHealth& health;
            ~ActivityGuard() { health.WorkerStopped(); }
        } activity{m_health};
        std::vector<uint8_t> buffer(EDR_FETCH_BUFFER_SIZE);
        OVERLAPPED overlapped = {};
        overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (overlapped.hEvent == nullptr) {
            m_health.RecordSourceError();
            std::fprintf(stderr, "EDR driver collector: CreateEvent failed (%lu)\n",
                         GetLastError());
            return;
        }
        HANDLE handle = nullptr;
        bool pending = false;

        while (!m_stop.load()) {
            if (handle == nullptr) {
                handle = CreateFileA(EDR_USERMODE_PATH,
                                     GENERIC_READ | GENERIC_WRITE,
                                     0, nullptr, OPEN_EXISTING,
                                     FILE_FLAG_OVERLAPPED, nullptr);
                if (handle == INVALID_HANDLE_VALUE) {
                    m_health.RecordSourceError();
                    handle = nullptr;
                    WaitForSingleObject(m_stopEvent, 30000);
                    continue;
                }
                m_health.MarkSourceAvailable();
            }

            if (!pending) {
                ResetEvent(overlapped.hEvent);
                DWORD bytes = 0;
                BOOL ok = DeviceIoControl(handle, IOCTL_EDR_FETCH_EVENT,
                                          nullptr, 0, buffer.data(),
                                          (DWORD)buffer.size(), &bytes,
                                          &overlapped);
                if (ok) {
                    if (bytes > 0) {
                        m_health.RecordSnapshotSuccess();
                        ParseBuffer(buffer.data(), bytes);
                    }
                    continue;
                }
                if (GetLastError() != ERROR_IO_PENDING) {
                    m_health.RecordSourceError();
                    HandleIoError(handle, overlapped, pending);
                    continue;
                }
                pending = true;
            }

            HANDLE waits[] = {overlapped.hEvent, m_stopEvent};
            DWORD wait = WaitForMultipleObjects(2, waits, FALSE, 1000);
            if (wait == WAIT_TIMEOUT) {
                continue; /* keep waiting for the same request */
            }
            if (wait == WAIT_OBJECT_0 + 1) {
                CancelIoEx(handle, &overlapped);
                DWORD bytes = 0;
                GetOverlappedResult(handle, &overlapped, &bytes, TRUE);
                pending = false;
                break;
            }
            if (wait != WAIT_OBJECT_0) {
                m_health.RecordSourceError();
                HandleIoError(handle, overlapped, pending);
                continue;
            }

            DWORD bytes = 0;
            BOOL completed = GetOverlappedResult(handle, &overlapped,
                                                  &bytes, FALSE);
            pending = false;
            if (!completed) {
                m_health.RecordSourceError();
                HandleIoError(handle, overlapped, pending);
                continue;
            }
            if (bytes > 0) {
                m_health.RecordSnapshotSuccess();
                ParseBuffer(buffer.data(), bytes);
            }
        }

        if (pending) {
            CancelIoEx(handle, &overlapped);
            DWORD bytes = 0;
            GetOverlappedResult(handle, &overlapped, &bytes, TRUE);
        }
        if (handle != nullptr) {
            CloseHandle(handle);
        }
        CloseHandle(overlapped.hEvent);
    }

    static void HandleIoError(HANDLE& handle, OVERLAPPED& overlapped,
                              bool& pending) {
        if (handle != nullptr) {
            if (pending) {
                CancelIoEx(handle, &overlapped);
                DWORD bytes = 0;
                GetOverlappedResult(handle, &overlapped, &bytes, TRUE);
                pending = false;
            }
            CloseHandle(handle);
            handle = nullptr;
        }
    }

    void ParseBuffer(const uint8_t* data, DWORD len) {
        size_t off = 0;
        while (off + sizeof(EDR_EVENT_HEADER) <= len && !m_stop.load()) {
            EDR_EVENT_HEADER hdr;
            memcpy(&hdr, data + off, sizeof(hdr)); /* never cast (M5) */
            if (hdr.magic != EDR_EVENT_MAGIC ||
                hdr.version != EDR_EVENT_VERSION ||
                hdr.length < sizeof(EDR_EVENT_HEADER) ||
                off + hdr.length > len) {
                m_health.RecordParseError();
                break; /* malformed stream: drop the rest of the batch */
            }
            ParseEvent(hdr, data + off + sizeof(EDR_EVENT_HEADER),
                       hdr.length - (uint32_t)sizeof(EDR_EVENT_HEADER));
            off += hdr.length;
        }
        if (off != len && off + sizeof(EDR_EVENT_HEADER) > len)
            m_health.RecordParseError();
    }

    void ParseEvent(const EDR_EVENT_HEADER& hdr, const uint8_t* tlv,
                    uint32_t tlvLen) {
        Event ev;
        bool malformed = false;

        if (!ParseDriverEvent(hdr, tlv, tlvLen, ev, malformed)) {
            m_health.RecordParseError();
            return; /* malformed TLV tail: drop this event */
        }

        ObserveDriverStatsHealth(m_health, hdr.type, hdr.reserved);

        if (hdr.type == EDR_EVT_PROCESS_START &&
            (hdr.flags & EDR_FLAG_COMMAND_LINE_ABSENT) != 0) {
            TryEnrichCommandLine(ev);
        }

        if (m_bus != nullptr) {
            m_health.RecordEventSubmitted(!m_bus->Push(ev));
        }
    }

    /* M2: best-effort command line read, ~2ms budget, failure => absent. */
    void TryEnrichCommandLine(Event& ev) {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(2);

        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                     PROCESS_VM_READ,
                                     FALSE, ev.pid);
        if (process == nullptr) {
            return; /* stays absent */
        }

        std::wstring cmdline;
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto ntQuery = ntdll ? (NtQueryInformationProcess_t)GetProcAddress(
            ntdll, "NtQueryInformationProcess") : nullptr;

        if (ntQuery != nullptr) {
            UNICODE_STRING_NT us = {};
            NTSTATUS_NT st = ntQuery(process, kProcessCommandLineInformation,
                                     &us, sizeof(us), nullptr);
            if (NT_SUCCESS_NT(st) && us.Buffer != nullptr &&
                us.Length > 0 && us.Length < 8192) {
                cmdline.resize(us.Length / sizeof(wchar_t));
                SIZE_T read = 0;
                if (!ReadProcessMemory(process, us.Buffer, cmdline.data(),
                                       us.Length, &read) ||
                    read != us.Length) {
                    cmdline.clear();
                }
            }
        }
        CloseHandle(process);

        if (std::chrono::steady_clock::now() > deadline) {
            return; /* budget exceeded: treat as absent */
        }
        if (!cmdline.empty()) {
            ev.fields[field::kCommandLine] = WideToUtf8(cmdline.c_str());
            ev.flags &= ~EDR_FLAG_COMMAND_LINE_ABSENT;
        }
    }

    EventBus* m_bus = nullptr;
    CollectorRuntimeHealth m_health;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    HANDLE m_stopEvent = nullptr;

public:
    CollectorHealthSnapshot GetHealthSnapshot() const override {
        return m_health.Snapshot();
    }
};

ICollector* CreateDriverCollector() {
    return new DriverCollector();
}

} // namespace edr
