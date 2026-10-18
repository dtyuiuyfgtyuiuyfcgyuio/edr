/*
 * collector_lsass_sam.cpp - Detect LSASS/SAM credential access.
 */
#include "collector_lsass_sam.h"

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <chrono>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "collector.h"
#include "edr_event.h"
#include "event_bus.h"

#ifndef SystemHandleInformation
constexpr SYSTEM_INFORMATION_CLASS SystemHandleInformation =
    static_cast<SYSTEM_INFORMATION_CLASS>(16);
#endif

namespace edr {
namespace {

constexpr DWORD kLsassAccessStrict = PROCESS_VM_READ;

std::string WideToUtf8(const wchar_t* wide, size_t length) {
    if (wide == nullptr || length == 0) return std::string();
    int needed = WideCharToMultiByte(
        CP_UTF8, 0, wide, static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return std::string();
    std::string result(static_cast<size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, wide, static_cast<int>(length),
                            result.data(), needed, nullptr, nullptr) != needed)
        return std::string();
    return result;
}

std::string GetProcessImagePath(DWORD pid) {
    HANDLE process =
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return std::string();
    std::vector<wchar_t> path(32768);
    DWORD size = static_cast<DWORD>(path.size());
    std::string result;
    if (QueryFullProcessImageNameW(process, 0, path.data(), &size))
        result = WideToUtf8(path.data(), size);
    CloseHandle(process);
    return result;
}

class LsassSamCollector : public ICollector {
public:
    LsassSamCollector(uint32_t pollMs, uint32_t dedupMs)
        : pollMs_(pollMs), dedupMs_(dedupMs) {}

    bool Start(EventBus* bus) override {
        bus_ = bus;
        stop_ = false;
        worker_ = std::thread([this] { Loop(); });
        return true;
    }

    void Stop() override {
        stop_ = true;
        if (worker_.joinable()) worker_.join();
    }

private:
    void Loop() {
        while (!stop_) {
            Poll();
            std::this_thread::sleep_for(std::chrono::milliseconds(pollMs_));
        }
    }

    uint64_t NowFileTime() const {
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) |
            ft.dwLowDateTime;
    }

    void GetProcessImage(DWORD pid, std::string& image, std::string& commandLine) {
        image.clear();
        commandLine.clear();
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        for (BOOL ok = Process32FirstW(snapshot, &entry); ok;
             ok = Process32NextW(snapshot, &entry)) {
            if (entry.th32ProcessID == pid) {
                std::wstring path = entry.szExeFile;
                size_t slash = path.find_last_of(L"\\/");
                std::wstring base = slash == std::wstring::npos
                    ? path : path.substr(slash + 1);
                image.assign(base.begin(), base.end());
                break;
            }
        }
        CloseHandle(snapshot);
    }

    void Poll() {
        DWORD lsassPid = FindLsassPid();
        if (lsassPid == 0) return;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        for (BOOL ok = Process32FirstW(snapshot, &entry); ok;
             ok = Process32NextW(snapshot, &entry)) {
            DWORD pid = entry.th32ProcessID;
            if (pid == 0 || pid == 4 || pid == lsassPid || pid == GetCurrentProcessId())
                continue;
            std::wstring base = entry.szExeFile;
            std::transform(base.begin(), base.end(), base.begin(), towlower);
            if (base == L"lsass.exe" || base == L"csrss.exe" ||
                base == L"services.exe" || base == L"smss.exe" ||
                base == L"wininit.exe" || base == L"winlogon.exe" ||
                base == L"svchost.exe")
                continue;
            CheckHandleToLsass(pid, lsassPid);
        }
        CloseHandle(snapshot);
    }

    DWORD FindLsassPid() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;
        DWORD pid = 0;
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        for (BOOL ok = Process32FirstW(snapshot, &entry); ok;
             ok = Process32NextW(snapshot, &entry)) {
            std::wstring base = entry.szExeFile;
            std::transform(base.begin(), base.end(), base.begin(), towlower);
            if (base == L"lsass.exe") {
                pid = entry.th32ProcessID;
                break;
            }
        }
        CloseHandle(snapshot);
        return pid;
    }

    void CheckHandleToLsass(DWORD pid, DWORD lsassPid) {
        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                                      FALSE, pid);
        if (!hProcess) return;

        auto ntQuery = GetNtQuerySystemInformation();
        if (!ntQuery) { CloseHandle(hProcess); return; }

        DWORD needed = 0;
        ntQuery(SystemHandleInformation, nullptr, 0, &needed);
        if (needed == 0) { CloseHandle(hProcess); return; }

        std::vector<BYTE> buffer(needed * 2);
        ULONG returnLength = 0;
        NTSTATUS status = ntQuery(
            SystemHandleInformation, buffer.data(),
            static_cast<ULONG>(buffer.size()), &returnLength);
        if (status != 0) { CloseHandle(hProcess); return; }

        auto info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(buffer.data());
        for (ULONG i = 0; i < info->HandleCount; ++i) {
            const SYSTEM_HANDLE_TABLE_ENTRY_INFO& h = info->Handles[i];
            if (h.ProcessId != pid) continue;

            HANDLE dup = nullptr;
            if (DuplicateHandle(hProcess, reinterpret_cast<HANDLE>(h.Handle),
                                GetCurrentProcess(), &dup,
                                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0) == FALSE)
                continue;

            DWORD targetPid = GetProcessId(dup);
            if (targetPid == lsassPid) {
                DWORD granted = h.GrantedAccess;
                if ((granted & kLsassAccessStrict) == kLsassAccessStrict) {
                    EmitLsassRead(pid, lsassPid, h.Handle, granted);
                }
            }
            CloseHandle(dup);
        }
        CloseHandle(hProcess);
    }

    void EmitLsassRead(DWORD pid, DWORD lsassPid, USHORT handle, DWORD access) {
        auto key = std::make_pair(pid, handle);
        uint64_t now = NowFileTime();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = lsassDedup_.find(key);
            if (it != lsassDedup_.end() &&
                (now - it->second) < (static_cast<uint64_t>(dedupMs_) * 10000ULL))
                return;
            lsassDedup_[key] = now;
        }

        std::string image, commandLine;
        GetProcessImage(pid, image, commandLine);

        Event ev;
        ev.type = EDR_EVT_PROCESS_READ;
        ev.ts100ns = now;
        ev.pid = pid;
        ev.source = "credential_monitor";
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "PROCESS_READ";
        ev.fields[field::kImage] = image.empty() ? "unknown" : image;
        ev.fields[field::kTargetPid] = std::to_string(lsassPid);
        ev.fields[field::kCrossProcess] = "true";
        std::string lsassImage = GetProcessImagePath(lsassPid);
        if (!lsassImage.empty())
            ev.fields[field::kTargetImage] = lsassImage;
        ev.fields[field::kCommandLine] = commandLine;
        ev.fields[field::kAccessMask] = std::to_string(access);
        ev.fields[field::kHandleId] = std::to_string(handle);
        if (bus_) bus_->Push(ev);
    }

    EventBus* bus_ = nullptr;
    uint32_t pollMs_;
    uint32_t dedupMs_;
    std::atomic<bool> stop_{false};
    std::thread worker_;
    std::mutex mutex_;
    std::map<std::pair<DWORD, USHORT>, uint64_t> lsassDedup_;

    /* Native API typedefs */
    typedef NTSTATUS(NTAPI* NtQuerySystemInformationFn)(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);

    struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
        USHORT ProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR ObjectTypeIndex;
        UCHAR HandleAttributes;
        USHORT Handle;
        PVOID Object;
        ULONG GrantedAccess;
    };

    struct SYSTEM_HANDLE_INFORMATION {
        ULONG HandleCount;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
    };

    static NtQuerySystemInformationFn GetNtQuerySystemInformation() {
        static NtQuerySystemInformationFn fn =
            reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(
                GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        return fn;
    }
};

} // namespace

ICollector* CreateLsassSamCollector(uint32_t pollMs, uint32_t dedupMs) {
    return new LsassSamCollector(pollMs, dedupMs);
}

} // namespace edr
