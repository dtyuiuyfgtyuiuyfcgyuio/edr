/*
 * system_snapshot.cpp - Emergency-response system state snapshot.
 *
 * Collects process list, network connections, listening ports, services,
 * shares, and startup persistence (Run keys) and prints a text report.
 * Read-only. The implementation was rebuilt after the original translation
 * unit was emptied; the public API in system_snapshot.h is unchanged.
 */
#include "system_snapshot.h"

#include <windows.h>
#include <iphlpapi.h>
#include <lm.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "json_lite.h"

namespace edr {
namespace {

std::string WideToUtf8Local(const wchar_t* wide) {
    if (wide == nullptr) return "";
    int needed = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0,
                                     nullptr, nullptr);
    if (needed <= 0) return "";
    std::string out(static_cast<size_t>(needed) - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), needed, nullptr,
                        nullptr);
    return out;
}

std::string NowUtcString() {
    SYSTEMTIME st = {};
    GetSystemTime(&st);
    char buffer[64] = {};
    std::snprintf(buffer, sizeof(buffer),
                  "%04u-%02u-%02uT%02u:%02u:%02uZ",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                  st.wSecond);
    return buffer;
}

std::string ServiceStateString(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED: return "stopped";
    case SERVICE_START_PENDING: return "start_pending";
    case SERVICE_STOP_PENDING: return "stop_pending";
    case SERVICE_RUNNING: return "running";
    case SERVICE_CONTINUE_PENDING: return "continue_pending";
    case SERVICE_PAUSE_PENDING: return "pause_pending";
    case SERVICE_PAUSED: return "paused";
    default: return "unknown";
    }
}

void AppendProcesses(std::ostringstream& out, uint32_t maxDepth) {
    out << "[Processes]\n";
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        out << "(unavailable)\n";
        return;
    }
    std::map<DWORD, DWORD> parents;
    std::map<DWORD, std::string> images;
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            parents[entry.th32ProcessID] = entry.th32ParentProcessID;
            images[entry.th32ProcessID] = WideToUtf8Local(entry.szExeFile);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    std::map<DWORD, uint32_t> depths;
    for (const auto& item : parents) {
        DWORD pid = item.first;
        uint32_t depth = 0;
        DWORD cursor = pid;
        std::vector<DWORD> chain;
        while (cursor != 0 && depth < maxDepth &&
               depths.find(cursor) == depths.end() && chain.size() < 64) {
            chain.push_back(cursor);
            auto parent = parents.find(cursor);
            if (parent == parents.end()) break;
            cursor = parent->second;
            if (cursor == pid) break; /* cycle guard */
            ++depth;
        }
        uint32_t resolved = depth;
        if (!chain.empty()) {
            DWORD top = cursor;
            auto found = depths.find(top);
            if (found != depths.end()) {
                resolved = found->second + static_cast<uint32_t>(chain.size());
            }
        }
        depths[pid] = resolved;
    }

    for (const auto& item : images) {
        uint32_t depth = depths[item.first];
        out << item.first << " " << parents[item.first] << " ";
        for (uint32_t i = 0; i < depth; ++i) out << "  ";
        out << item.second << "\n";
    }
}

void AppendConnections(std::ostringstream& out) {
    out << "[Connections]\n";
    ULONG size = 0;
    if (GetTcpTable2(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER ||
        size == 0) {
        out << "(unavailable)\n";
        return;
    }
    std::vector<BYTE> buffer(size);
    if (GetTcpTable2(reinterpret_cast<PMIB_TCPTABLE2>(buffer.data()), &size,
                     FALSE) != NO_ERROR) {
        out << "(unavailable)\n";
        return;
    }
    auto* table = reinterpret_cast<PMIB_TCPTABLE2>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_TCPROW2& row = table->table[i];
        char local[64] = {};
        char remote[64] = {};
        std::snprintf(local, sizeof(local), "%lu.%lu.%lu.%lu:%u",
                      (row.dwLocalAddr >> 0) & 0xFF,
                      (row.dwLocalAddr >> 8) & 0xFF,
                      (row.dwLocalAddr >> 16) & 0xFF,
                      (row.dwLocalAddr >> 24) & 0xFF,
                      static_cast<unsigned>(ntohs(static_cast<u_short>(
                          row.dwLocalPort))));
        std::snprintf(remote, sizeof(remote), "%lu.%lu.%lu.%lu:%u",
                      (row.dwRemoteAddr >> 0) & 0xFF,
                      (row.dwRemoteAddr >> 8) & 0xFF,
                      (row.dwRemoteAddr >> 16) & 0xFF,
                      (row.dwRemoteAddr >> 24) & 0xFF,
                      static_cast<unsigned>(ntohs(static_cast<u_short>(
                          row.dwRemotePort))));
        out << "tcp " << row.dwOwningPid << " " << local << " -> " << remote
            << " state=" << row.dwState << "\n";
    }
}

void AppendListeners(std::ostringstream& out) {
    out << "[Listeners]\n";
    ULONG size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) !=
            ERROR_INSUFFICIENT_BUFFER ||
        size == 0) {
        out << "(unavailable)\n";
        return;
    }
    std::vector<BYTE> buffer(size);
    if (GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        out << "(unavailable)\n";
        return;
    }
    auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_UDPROW_OWNER_PID& row = table->table[i];
        char local[64] = {};
        std::snprintf(local, sizeof(local), "%lu.%lu.%lu.%lu:%u",
                      (row.dwLocalAddr >> 0) & 0xFF,
                      (row.dwLocalAddr >> 8) & 0xFF,
                      (row.dwLocalAddr >> 16) & 0xFF,
                      (row.dwLocalAddr >> 24) & 0xFF,
                      static_cast<unsigned>(ntohs(static_cast<u_short>(
                          row.dwLocalPort))));
        out << "udp " << row.dwOwningPid << " " << local << "\n";
    }
}

void AppendServices(std::ostringstream& out) {
    out << "[Services]\n";
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr,
                                       SC_MANAGER_ENUMERATE_SERVICE);
    if (manager == nullptr) {
        out << "(unavailable)\n";
        return;
    }
    DWORD needed = 0;
    DWORD returned = 0;
    EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, nullptr, 0, &needed, &returned,
                          nullptr, nullptr);
    if (needed == 0) {
        CloseServiceHandle(manager);
        out << "(unavailable)\n";
        return;
    }
    std::vector<BYTE> buffer(needed);
    if (!EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               SERVICE_STATE_ALL, buffer.data(),
                               static_cast<DWORD>(buffer.size()), &needed,
                               &returned, nullptr, nullptr)) {
        CloseServiceHandle(manager);
        out << "(unavailable)\n";
        return;
    }
    auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(
        buffer.data());
    for (DWORD i = 0; i < returned; ++i) {
        out << WideToUtf8Local(services[i].lpServiceName) << " "
            << WideToUtf8Local(services[i].lpDisplayName) << " "
            << ServiceStateString(services[i].ServiceStatusProcess
                                      .dwCurrentState)
            << " pid=" << services[i].ServiceStatusProcess.dwProcessId
            << "\n";
    }
    CloseServiceHandle(manager);
}

void AppendShares(std::ostringstream& out) {
    out << "[Shares]\n";
    SHARE_INFO_1* info = nullptr;
    DWORD entries = 0;
    DWORD total = 0;
    DWORD resume = 0;
    NET_API_STATUS status = NetShareEnum(
        nullptr, 1, reinterpret_cast<LPBYTE*>(&info), MAX_PREFERRED_LENGTH,
        &entries, &total, &resume);
    if (status != NERR_Success || info == nullptr) {
        out << "(unavailable)\n";
        return;
    }
    for (DWORD i = 0; i < entries; ++i) {
        out << WideToUtf8Local(info[i].shi1_netname) << " type="
            << info[i].shi1_type << " "
            << WideToUtf8Local(info[i].shi1_remark) << "\n";
    }
    NetApiBufferFree(info);
}

void AppendRunKeys(std::ostringstream& out) {
    out << "[RunKeys]\n";
    static const wchar_t* const kRoots[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    };
    HKEY hives[] = {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};
    for (HKEY hive : hives) {
        for (const wchar_t* subkey : kRoots) {
            HKEY key = nullptr;
            if (RegOpenKeyExW(hive, subkey, 0, KEY_READ, &key) !=
                ERROR_SUCCESS) {
                continue;
            }
            wchar_t name[256] = {};
            BYTE value[4096] = {};
            for (DWORD index = 0;; ++index) {
                DWORD nameLen = static_cast<DWORD>(std::size(name));
                DWORD valueLen = sizeof(value);
                LSTATUS status = RegEnumValueW(
                    key, index, name, &nameLen, nullptr, nullptr, value,
                    &valueLen);
                if (status == ERROR_NO_MORE_ITEMS) break;
                if (status != ERROR_SUCCESS) continue;
                std::string text(reinterpret_cast<const char*>(value),
                                 valueLen);
                while (!text.empty() && text.back() == '\0') text.pop_back();
                out << WideToUtf8Local(name) << " = " << text << "\n";
            }
            RegCloseKey(key);
        }
    }
}

} // namespace

std::string BuildSystemSnapshotText(const SnapshotOptions& options) {
    std::ostringstream out;
    out << "EDR system snapshot (UTC)\n";
    out << "generated_at: " << NowUtcString() << "\n";
    AppendProcesses(out, options.processTreeDepth);
    if (options.includeConnections) {
        AppendConnections(out);
        AppendListeners(out);
    }
    if (options.includeServices) AppendServices(out);
    if (options.includeShares) AppendShares(out);
    if (options.includeRunKeys) AppendRunKeys(out);
    return out.str();
}

std::string BuildSystemSnapshotManifest(const std::string& requestId,
                                        const std::string& ruleId,
                                        const std::string& severity,
                                        const std::string& action,
                                        const std::string& snapshotPath,
                                        const std::string& treePath,
                                        const std::string& alertPath,
                                        const std::string& evidencePath) {
    std::ostringstream out;
    out << "{\"schema\":\"edr.snapshot.manifest.v1\",";
    out << "\"requestId\":\"" << jsonlite::escape(requestId) << "\",";
    out << "\"ruleId\":\"" << jsonlite::escape(ruleId) << "\",";
    out << "\"severity\":\"" << jsonlite::escape(severity) << "\",";
    out << "\"action\":\"" << jsonlite::escape(action) << "\",";
    out << "\"generatedAt\":\"" << NowUtcString() << "\",";
    out << "\"snapshotPath\":\"" << jsonlite::escape(snapshotPath) << "\",";
    out << "\"treePath\":\"" << jsonlite::escape(treePath) << "\",";
    out << "\"alertPath\":\"" << jsonlite::escape(alertPath) << "\",";
    out << "\"evidencePath\":\"" << jsonlite::escape(evidencePath) << "\"}";
    return out.str();
}

bool WriteSystemSnapshotFile(const std::string& path, std::string& error,
                             const SnapshotOptions& options) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        error = "cannot open snapshot file: " + path;
        return false;
    }
    file << BuildSystemSnapshotText(options);
    file.flush();
    if (!file) {
        error = "failed writing snapshot file: " + path;
        return false;
    }
    return true;
}

int RunSystemSnapshot() {
    try {
        const std::string report = BuildSystemSnapshotText({});
        std::fwrite(report.data(), 1, report.size(), stdout);
        std::fflush(stdout);
        return 0;
    } catch (...) {
        return 1;
    }
}

} // namespace edr
