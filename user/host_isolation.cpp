#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "host_isolation.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

namespace edr {

HostIsolationController::HostIsolationController() = default;

bool HostIsolationController::ValidateIsolationParameters(
    const std::string& managementIp,
    const std::string& allowedPorts,
    std::string& error) {
    error.clear();
    if (managementIp.empty() || managementIp.size() > 45 ||
        std::any_of(managementIp.begin(), managementIp.end(),
            [](unsigned char c) { return std::isspace(c) != 0; })) {
        error = "management IP is invalid";
        return false;
    }
    IN_ADDR ipv4 = {};
    IN6_ADDR ipv6 = {};
    if (InetPtonA(AF_INET, managementIp.c_str(), &ipv4) != 1 &&
        InetPtonA(AF_INET6, managementIp.c_str(), &ipv6) != 1) {
        error = "management IP is invalid";
        return false;
    }
    if (allowedPorts.empty()) return true;
    size_t start = 0;
    while (start < allowedPorts.size()) {
        size_t comma = allowedPorts.find(',', start);
        size_t end = comma == std::string::npos ? allowedPorts.size() : comma;
        if (end == start) {
            error = "allowed ports contain an empty item";
            return false;
        }
        uint32_t port = 0;
        for (size_t i = start; i < end; ++i) {
            unsigned char c = static_cast<unsigned char>(allowedPorts[i]);
            if (!std::isdigit(c)) {
                error = "allowed ports must be comma-separated decimal ports";
                return false;
            }
            port = port * 10 + (c - '0');
            if (port > 65535) break;
        }
        if (port == 0 || port > 65535) {
            error = "allowed port is outside 1..65535";
            return false;
        }
        if (comma == std::string::npos) break;
        start = comma + 1;
        if (start == allowedPorts.size()) {
            error = "allowed ports contain an empty item";
            return false;
        }
    }
    return true;
}

HostIsolationController::~HostIsolationController() {
    /* Best-effort cleanup: remove any leftover isolation rules if the
     * destructor runs while still isolated.  We intentionally swallow the
     * error because there is no useful caller at this point. */
    if (m_isolated.load()) {
        std::string ignored;
        RemoveIsolationRules(ignored);
    }
}

/* ------------------------------------------------------------------ */
/*  EnableIsolation                                                    */
/* ------------------------------------------------------------------ */

bool HostIsolationController::EnableIsolation(
    const std::string& managementIp,
    const std::string& allowedPorts,
    std::string& error) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_isolated.load()) {
        error = "already in isolation mode";
        return false;
    }

    if (!ValidateIsolationParameters(managementIp, allowedPorts, error)) {
        return false;
    }

    /* First, remove any stale isolation rules left over from a previous
     * session (should not normally happen, but we are defensive). */
    RemoveIsolationRules(error);
    /* RemoveIsolationRules clears the error string on success; we overwrite
     * it here to make sure we don't leak a stale error message. */
    error.clear();

    if (!AddBlockAllRules(managementIp, allowedPorts, error)) {
        /* Roll back: remove whatever rules we managed to add. */
        std::string rollbackError;
        RemoveIsolationRules(rollbackError);
        return false;
    }

    m_managementIp = managementIp;
    m_allowedPorts = allowedPorts;

    /* Record the time (milliseconds since boot) so GetStatusJson can
     * report how long the host has been isolated. */
    m_isolatedSinceMs = GetTickCount64();
    m_isolated.store(true);

    return true;
}

/* ------------------------------------------------------------------ */
/*  DisableIsolation                                                   */
/* ------------------------------------------------------------------ */

bool HostIsolationController::DisableIsolation(std::string& error) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_isolated.load()) {
        error = "not currently isolated";
        return false;
    }

    if (!RemoveIsolationRules(error)) {
        return false;
    }

    m_isolated.store(false);
    m_managementIp.clear();
    m_allowedPorts.clear();
    m_isolatedSinceMs = 0;

    return true;
}

/* ------------------------------------------------------------------ */
/*  GetStatusJson                                                      */
/* ------------------------------------------------------------------ */

HostIsolationStatus HostIsolationController::GetStatus() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    HostIsolationStatus status;
    status.isolated = m_isolated.load();
    if (status.isolated) {
        status.managementIp = m_managementIp;
        status.allowedPorts = m_allowedPorts;
        status.isolatedSinceMs = m_isolatedSinceMs;
        status.elapsedMs = GetTickCount64() - m_isolatedSinceMs;
    }
    return status;
}

std::string HostIsolationController::GetStatusJson() const {
    HostIsolationStatus status = GetStatus();
    std::ostringstream json;
    json << "{";
    json << "\"isolated\":" << (status.isolated ? "true" : "false");

    if (status.isolated) {
        json << ",\"managementIp\":\"" << status.managementIp << "\"";
        json << ",\"allowedPorts\":\"" << status.allowedPorts << "\"";
        json << ",\"isolatedSinceMs\":" << status.isolatedSinceMs;
        json << ",\"elapsedMs\":" << status.elapsedMs;
    }

    json << "}";
    return json.str();
}

/* ------------------------------------------------------------------ */
/*  AddBlockAllRules                                                   */
/* ------------------------------------------------------------------ */

bool HostIsolationController::AddBlockAllRules(
    const std::string& managementIp,
    const std::string& allowedPorts,
    std::string& error) {

    /* -- 1. Allow inbound traffic from the management IP ------------- */
    {
        std::string cmd = "advfirewall firewall add rule "
            "name=\"EDR-Isolation-Allow-Management-In\" "
            "dir=in action=allow remoteip=" + managementIp;
        std::string output;
        DWORD errorCode = 0;
        if (!ExecuteNetsh(cmd, output, errorCode)) {
            error = "failed to create allow-management-in rule: " + output;
            return false;
        }
    }

    /* -- 2. Allow outbound traffic to the management IP -------------- */
    {
        std::string cmd = "advfirewall firewall add rule "
            "name=\"EDR-Isolation-Allow-Management-Out\" "
            "dir=out action=allow remoteip=" + managementIp;
        std::string output;
        DWORD errorCode = 0;
        if (!ExecuteNetsh(cmd, output, errorCode)) {
            error = "failed to create allow-management-out rule: " + output;
            return false;
        }
    }

    /* -- 3. Allow specified ports (inbound) -------------------------- */
    if (!allowedPorts.empty()) {
        std::string cmd = "advfirewall firewall add rule "
            "name=\"EDR-Isolation-Allow-Ports-In\" "
            "dir=in action=allow localport=" + allowedPorts + " protocol=tcp";
        std::string output;
        DWORD errorCode = 0;
        if (!ExecuteNetsh(cmd, output, errorCode)) {
            error = "failed to create allow-ports-in rule: " + output;
            return false;
        }

        /* Also allow outbound on the same ports so the host can
         * communicate on those ports. */
        cmd = "advfirewall firewall add rule "
            "name=\"EDR-Isolation-Allow-Ports-Out\" "
            "dir=out action=allow localport=" + allowedPorts + " protocol=tcp";
        if (!ExecuteNetsh(cmd, output, errorCode)) {
            error = "failed to create allow-ports-out rule: " + output;
            return false;
        }
    }

    /* -- 4. Block ALL inbound traffic (catch-all, lower priority) --- */
    {
        std::string cmd = "advfirewall firewall add rule "
            "name=\"EDR-Isolation-Block-All-In\" "
            "dir=in action=block";
        std::string output;
        DWORD errorCode = 0;
        if (!ExecuteNetsh(cmd, output, errorCode)) {
            error = "failed to create block-all-in rule: " + output;
            return false;
        }
    }

    /* -- 5. Block ALL outbound traffic (catch-all) ------------------ */
    {
        std::string cmd = "advfirewall firewall add rule "
            "name=\"EDR-Isolation-Block-All-Out\" "
            "dir=out action=block";
        std::string output;
        DWORD errorCode = 0;
        if (!ExecuteNetsh(cmd, output, errorCode)) {
            error = "failed to create block-all-out rule: " + output;
            return false;
        }
    }

    return true;
}

/* ------------------------------------------------------------------ */
/*  RemoveIsolationRules                                               */
/* ------------------------------------------------------------------ */

bool HostIsolationController::RemoveIsolationRules(std::string& error) {
    /* Delete every rule whose name starts with "EDR-Isolation-".
     * netsh supports wildcard '?' and '*' in rule names. */
    const char* kRulePatterns[] = {
        "EDR-Isolation-Allow-Management-In",
        "EDR-Isolation-Allow-Management-Out",
        "EDR-Isolation-Allow-Ports-In",
        "EDR-Isolation-Allow-Ports-Out",
        "EDR-Isolation-Block-All-In",
        "EDR-Isolation-Block-All-Out",
    };

    bool anyDeleted = false;
    for (const char* ruleName : kRulePatterns) {
        std::string cmd = "advfirewall firewall delete rule name=\"";
        cmd += ruleName;
        cmd += "\"";
        std::string output;
        DWORD errorCode = 0;
        if (ExecuteNetsh(cmd, output, errorCode)) {
            anyDeleted = true;
        }
        /* We intentionally ignore individual deletion failures: the rule
         * may never have been created (e.g. when no ports were specified). */
    }

    if (!anyDeleted) {
        /* Not an error – there were simply no rules to remove. */
        error.clear();
    }

    return true;
}

/* ------------------------------------------------------------------ */
/*  ExecuteNetsh                                                       */
/* ------------------------------------------------------------------ */

bool HostIsolationController::ExecuteNetsh(
    const std::string& arguments,
    std::string& output,
    DWORD& errorCode) {

    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = nullptr;

    /* Create a pipe for stdout. */
    HANDLE hStdoutRead = nullptr;
    HANDLE hStdoutWrite = nullptr;
    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &saAttr, 0)) {
        errorCode = GetLastError();
        output = "CreatePipe failed: " + std::to_string(errorCode);
        return false;
    }

    /* Ensure the read handle is not inherited. */
    if (!SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0)) {
        errorCode = GetLastError();
        CloseHandle(hStdoutRead);
        CloseHandle(hStdoutWrite);
        output = "SetHandleInformation failed: " + std::to_string(errorCode);
        return false;
    }

    wchar_t systemDirectory[MAX_PATH] = {};
    UINT systemLength = GetSystemDirectoryW(systemDirectory, MAX_PATH);
    if (systemLength == 0 || systemLength >= MAX_PATH) {
        errorCode = GetLastError();
        output = "GetSystemDirectory failed: " + std::to_string(errorCode);
        CloseHandle(hStdoutRead);
        CloseHandle(hStdoutWrite);
        return false;
    }
    std::wstring application = systemDirectory;
    application += L"\\netsh.exe";
    std::wstring wideArguments(arguments.begin(), arguments.end());
    std::wstring wideCommand = L"\"" + application + L"\" " + wideArguments;

    STARTUPINFOW siStartInfo;
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFOW));
    siStartInfo.cb = sizeof(STARTUPINFOW);
    siStartInfo.hStdError = hStdoutWrite;   /* redirect stderr to same pipe */
    siStartInfo.hStdOutput = hStdoutWrite;
    siStartInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    PROCESS_INFORMATION piProcInfo;
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

    BOOL bSuccess = CreateProcessW(
        application.c_str(),
        wideCommand.data(),
        nullptr,   /* process handle not inheritable */
        nullptr,   /* thread handle not inheritable */
        TRUE,      /* set handle inheritance to TRUE */
        CREATE_NO_WINDOW,  /* creation flags */
        nullptr,   /* use parent's environment block */
        nullptr,   /* use parent's starting directory */
        &siStartInfo,
        &piProcInfo);

    if (!bSuccess) {
        errorCode = GetLastError();
        output = "CreateProcess failed: " + std::to_string(errorCode);
        CloseHandle(hStdoutRead);
        CloseHandle(hStdoutWrite);
        return false;
    }

    /* Close the write end of the pipe so we can read all data. */
    CloseHandle(hStdoutWrite);

    /* Read the output from the pipe. */
    std::string result;
    char readBuffer[4096];
    DWORD bytesRead = 0;
    while (ReadFile(hStdoutRead, readBuffer, sizeof(readBuffer),
                    &bytesRead, nullptr) && bytesRead > 0) {
        result.append(readBuffer, bytesRead);
    }

    CloseHandle(hStdoutRead);

    /* Wait for the process to finish. */
    WaitForSingleObject(piProcInfo.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(piProcInfo.hProcess, &exitCode);
    errorCode = exitCode;

    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);

    output = result;

    /* netsh returns 0 on success. */
    return (exitCode == 0);
}

} // namespace edr
