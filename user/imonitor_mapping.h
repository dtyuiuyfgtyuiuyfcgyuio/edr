/*
 * imonitor_mapping.h - iMonitor message -> normalized Event mapping.
 *
 * Only compiled when EDR_IMONITOR is available (collector_imonitor.cpp).
 * Message semantics mirror the Sysmon mappings:
 *   - ProcessOpen  -> PROCESS_ACCESS (source = calling process)
 *   - ThreadCreate -> THREAD_CREATE (source = calling process)
 *   - HookReadProcessMemory -> PROCESS_READ (source = calling process)
 *   - FileRead (SAM/SECURITY/SYSTEM hive paths only) -> FILE_READ
 *   - HookQueueApcThread -> APC_INJECT (source = calling process)
 *   - HookSetContextThread -> CONTEXT_CHANGE (source = calling process)
 *   - HookWriteProcessMemory -> MEMORY_WRITE (source = calling process)
 *   - HookRpcCreateProcess -> RPC_CREATE_PROCESS (remote process creation)
 *   - HookSetWindowsHookEx -> WINDOWS_HOOK (window hook installation)
 *   - HookCreateService -> SERVICE_INSTALL_HOOK (service creation)
 *   - HookStartService -> SERVICE_START_HOOK (service start)
 *   - HookChangeServiceConfig -> SERVICE_CONFIG_CHANGE (service config)
 *   - HookCoCreateInstance -> CO_INSTANCE (COM object instantiation)
 *   - HookMapViewOfSection -> SECTION_MAP (DLL injection via section)
 *   - HookDuplicateHandle -> HANDLE_DUPLICATE (handle duplication)
 *   - HookSendInput -> INPUT_SIMULATION (keyboard/mouse simulation)
 *   - HookShutdownSystem -> SYSTEM_SHUTDOWN
 *   - HookSetSystemTime -> SYSTEM_TIME_CHANGE
 *   - HookGetClipboardData -> CLIPBOARD_ACCESS
 *   - HookSetDeskWallpaper -> WALLPAPER_CHANGE
 *   - HookUseCamera -> CAMERA_ACCESS
 *   - HookKeyLogger -> KEYLOGGER
 *   - HookPowerShell -> POWERSHELL_HOOK
 */
#ifndef EDR_IMONITOR_MAPPING_H
#define EDR_IMONITOR_MAPPING_H

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <cstdio>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "iMonitorProtocol.h"
#include "iMonitorSDK.h"
#include "process_access.h"

namespace edr {

inline std::string MonitorUtf8(LPCWSTR value) {
    return value != nullptr ? WideToUtf8(value) : std::string();
}

inline std::string MonitorIpString(const cxMSGDataIP& ip) {
    char buffer[INET6_ADDRSTRLEN] = {};
    if (ip.IsIPv4()) {
        IN_ADDR address = {};
        address.S_un.S_addr = ip.IPv4.IP;
        return InetNtopA(AF_INET, &address, buffer, sizeof(buffer)) ? buffer : "";
    }
    IN6_ADDR address = {};
    memcpy(&address, ip.IPv6, sizeof(address));
    return InetNtopA(AF_INET6, &address, buffer, sizeof(buffer)) ? buffer : "";
}

inline void SetMonitorProcessMetadata(Event& event, MonitorMessage* message) {
    event.pid = message->GetCurrentProcessId();
    event.processStartTime100ns = message->CurrentProcessCreateTime();
    if (event.pid != 0 && event.processStartTime100ns != 0)
        event.processIdentity = std::to_string(event.pid) + "@" +
                                std::to_string(event.processStartTime100ns);
    event.fields[field::kPid] = std::to_string(event.pid);
    std::string image = MonitorUtf8(message->CurrentProcessPath());
    if (!image.empty()) event.fields[field::kImage] = image;
}

inline bool MapIMonitorMessage(Event& event, IMonitorMessage* raw) {
    switch (raw->GetType()) {
    case emMSGProcessCreate: {
        auto* message = static_cast<cxMSGProcessCreate*>(raw);
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.pid = message->ProcessId();
        event.ppid = message->ParentProcessId();
        event.processStartTime100ns = message->CreateTime();
        if (event.pid != 0 && event.processStartTime100ns != 0)
            event.processIdentity = std::to_string(event.pid) + "@" +
                                    std::to_string(event.processStartTime100ns);
        if (event.ppid != 0 && message->ParentCreateTime() != 0)
            event.parentProcessIdentity = std::to_string(event.ppid) + "@" +
                std::to_string(message->ParentCreateTime());
        event.fields[field::kPid] = std::to_string(event.pid);
        event.fields[field::kPpid] = std::to_string(event.ppid);
        event.fields[field::kImage] = MonitorUtf8(message->Path());
        std::string commandLine = MonitorUtf8(message->Commandline());
        std::string parent = MonitorUtf8(message->ParentPath());
        if (!commandLine.empty()) event.fields[field::kCommandLine] = commandLine;
        if (!parent.empty()) event.fields[field::kParentImage] = parent;
        return true;
    }
    case emMSGProcessExit: {
        auto* message = static_cast<cxMSGProcessExit*>(raw);
        event.type = EDR_EVT_PROCESS_STOP;
        event.fields[field::kType] = "PROCESS_STOP";
        SetMonitorProcessMetadata(event, message);
        event.pid = message->ProcessId();
        event.fields[field::kPid] = std::to_string(event.pid);
        std::string image = MonitorUtf8(message->Path());
        if (!image.empty()) event.fields[field::kImage] = image;
        return true;
    }
    case emMSGFileCleanup: {
        auto* message = static_cast<cxMSGFileCleanup*>(raw);
        if (message->Information() != 2) return false; /* FILE_CREATED */
        event.type = EDR_EVT_FILE_CREATE;
        event.fields[field::kType] = "FILE_CREATE";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kFilePath] = MonitorUtf8(message->Path());
        return true;
    }
    case emMSGRegSetValue: {
        auto* message = static_cast<cxMSGRegSetValue*>(raw);
        event.type = EDR_EVT_REG_WRITE;
        event.fields[field::kType] = "REG_WRITE";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kRegKey] = MonitorUtf8(message->Path());
        event.fields[field::kRegValue] = MonitorUtf8(message->ValueName());
        return true;
    }
    case emMSGWFPTcpConnect: {
        auto* message = static_cast<cxMSGWFPTcpConnect*>(raw);
        event.type = EDR_EVT_NET_CONNECT;
        event.fields[field::kType] = "NET_CONNECT";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kDstIp] = MonitorIpString(message->IP());
        event.fields[field::kDstPort] = std::to_string(ntohs(message->Port()));
        event.fields[field::kProtocol] = "tcp";
        return true;
    }
    case emMSGWFPUdpConnect: {
        auto* message = static_cast<cxMSGWFPUdpConnect*>(raw);
        event.type = EDR_EVT_NET_CONNECT;
        event.fields[field::kType] = "NET_CONNECT";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kDstIp] = MonitorIpString(message->IP());
        event.fields[field::kDstPort] = std::to_string(ntohs(message->Port()));
        event.fields[field::kProtocol] = "udp";
        return true;
    }
    case emMSGProcessOpen: {
        auto* message = static_cast<cxMSGProcessOpen*>(raw);
        event.type = EDR_EVT_PROCESS_ACCESS;
        event.fields[field::kType] = "PROCESS_ACCESS";
        SetMonitorProcessMetadata(event, message);
        uint32_t targetPid = message->ProcessId();
        event.fields[field::kSourcePid] = event.fields[field::kPid];
        event.fields[field::kTargetPid] = std::to_string(targetPid);
        std::string source = MonitorUtf8(message->CurrentProcessPath());
        if (!source.empty()) event.fields[field::kActorImage] = source;
        std::string target = MonitorUtf8(message->Path());
        if (!target.empty()) event.fields[field::kTargetImage] = target;
        event.fields[field::kCrossProcess] =
            event.pid != targetPid ? "true" : "false";
        event.fields[field::kHandleDuplicated] =
            message->Duplicate() ? "true" : "false";
        ApplyProcessAccessFields(event, message->DesiredAccess());
        return true;
    }
    case emMSGThreadCreate: {
        auto* message = static_cast<cxMSGThreadCreate*>(raw);
        event.type = EDR_EVT_THREAD_CREATE;
        event.fields[field::kType] = "THREAD_CREATE";
        SetMonitorProcessMetadata(event, message);
        uint32_t targetPid = message->ProcessId();
        event.fields[field::kSourcePid] = event.fields[field::kPid];
        event.fields[field::kTargetPid] = std::to_string(targetPid);
        event.fields[field::kThreadId] = std::to_string(message->ThreadId());
        event.fields[field::kRemoteThread] =
            event.pid != targetPid ? "true" : "false";
        std::string source = MonitorUtf8(message->CurrentProcessPath());
        if (!source.empty()) event.fields[field::kActorImage] = source;
        std::string target = MonitorUtf8(message->Path());
        if (!target.empty()) event.fields[field::kTargetImage] = target;
        char address[24] = {};
        std::snprintf(address, sizeof(address), "0x%llx",
                      static_cast<unsigned long long>(message->StartAddress()));
        event.fields[field::kStartAddress] = address;
        return true;
    }
    case emMSGHookReadProcessMemory: {
        auto* message = static_cast<cxMSGHookReadProcessMemory*>(raw);
        event.type = EDR_EVT_PROCESS_READ;
        event.fields[field::kType] = "PROCESS_READ";
        SetMonitorProcessMetadata(event, message);
        uint32_t targetPid = message->ProcessId();
        event.fields[field::kSourcePid] = event.fields[field::kPid];
        event.fields[field::kTargetPid] = std::to_string(targetPid);
        std::string target = MonitorUtf8(message->Path());
        if (!target.empty()) event.fields[field::kTargetImage] = target;
        char address[24] = {};
        std::snprintf(address, sizeof(address), "0x%llx",
                      static_cast<unsigned long long>(message->BaseAddress()));
        event.fields[field::kBaseAddress] = address;
        ULONG size = message->Size();
        if (size > 0) event.fields[field::kMemorySize] = std::to_string(size);
        event.fields[field::kCrossProcess] =
            event.pid != targetPid ? "true" : "false";
        return true;
    }
    case emMSGFileRead: {
        auto* message = static_cast<cxMSGFileRead*>(raw);
        std::wstring path = message->Path() != nullptr ? message->Path() : L"";
        size_t slash = path.find_last_of(L"\\/");
        std::wstring name = slash == std::wstring::npos ? path : path.substr(slash + 1);
        if (_wcsicmp(name.c_str(), L"SAM") != 0 &&
            _wcsicmp(name.c_str(), L"SECURITY") != 0 &&
            _wcsicmp(name.c_str(), L"SYSTEM") != 0) {
            return false;
        }
        event.type = EDR_EVT_FILE_READ;
        event.fields[field::kType] = "FILE_READ";
        SetMonitorProcessMetadata(event, message);
        std::string filePath = MonitorUtf8(message->Path());
        event.fields[field::kFilePath] = filePath;
        event.fields[field::kTargetPath] = filePath;
        event.fields[field::kFileLength] = std::to_string(message->ReadLength());
        event.fields[field::kFileOffset] = std::to_string(message->Offset());
        return true;
    }
    case emMSGHookQueueApcThread: {
        auto* message = static_cast<cxMSGHookQueueApcThread*>(raw);
        event.type = EDR_EVT_APC_INJECT;
        event.fields[field::kType] = "APC_INJECT";
        SetMonitorProcessMetadata(event, message);
        uint32_t targetPid = message->ProcessId();
        event.fields[field::kSourcePid] = event.fields[field::kPid];
        event.fields[field::kTargetPid] = std::to_string(targetPid);
        std::string target = MonitorUtf8(message->Path());
        if (!target.empty()) event.fields[field::kTargetImage] = target;
        event.fields[field::kThreadId] = std::to_string(message->ThreadId());
        char address[24] = {};
        std::snprintf(address, sizeof(address), "0x%llx",
                      static_cast<unsigned long long>(message->ApcRoutine()));
        event.fields[field::kStartAddress] = address;
        event.fields[field::kCrossProcess] =
            event.pid != targetPid ? "true" : "false";
        return true;
    }
    case emMSGHookSetContextThread: {
        auto* message = static_cast<cxMSGHookSetContextThread*>(raw);
        event.type = EDR_EVT_CONTEXT_CHANGE;
        event.fields[field::kType] = "CONTEXT_CHANGE";
        SetMonitorProcessMetadata(event, message);
        uint32_t targetPid = message->ProcessId();
        event.fields[field::kSourcePid] = event.fields[field::kPid];
        event.fields[field::kTargetPid] = std::to_string(targetPid);
        std::string target = MonitorUtf8(message->Path());
        if (!target.empty()) event.fields[field::kTargetImage] = target;
        event.fields[field::kThreadId] = std::to_string(message->ThreadId());
        event.fields[field::kCrossProcess] =
            event.pid != targetPid ? "true" : "false";
        return true;
    }
    case emMSGHookWriteProcessMemory: {
        auto* message = static_cast<cxMSGHookWriteProcessMemory*>(raw);
        event.type = EDR_EVT_MEMORY_WRITE;
        event.fields[field::kType] = "MEMORY_WRITE";
        SetMonitorProcessMetadata(event, message);
        uint32_t targetPid = message->ProcessId();
        event.fields[field::kSourcePid] = event.fields[field::kPid];
        event.fields[field::kTargetPid] = std::to_string(targetPid);
        std::string target = MonitorUtf8(message->Path());
        if (!target.empty()) event.fields[field::kTargetImage] = target;
        char address[24] = {};
        std::snprintf(address, sizeof(address), "0x%llx",
                      static_cast<unsigned long long>(message->BaseAddress()));
        event.fields[field::kBaseAddress] = address;
        event.fields[field::kMemorySize] = std::to_string(message->Size());
        event.fields[field::kCrossProcess] =
            event.pid != targetPid ? "true" : "false";
        return true;
    }
    case emMSGHookRpcCreateProcess: {
        auto* message = static_cast<cxMSGHookRpcCreateProcess*>(raw);
        event.type = EDR_EVT_RPC_CREATE_PROCESS;
        event.fields[field::kType] = "RPC_CREATE_PROCESS";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kFilePath] = MonitorUtf8(message->Path());
        event.fields[field::kRpcCommandline] = MonitorUtf8(message->Commandline());
        uint32_t parentPid = message->ParentProcessId();
        if (parentPid != 0) {
            event.fields[field::kTargetPid] = std::to_string(parentPid);
            event.fields[field::kRpcParentPath] = MonitorUtf8(message->ParentPath());
            event.fields[field::kRpcParentCommandline] = MonitorUtf8(message->ParentCommandline());
        }
        return true;
    }
    case emMSGHookSetWindowsHookEx: {
        auto* message = static_cast<cxMSGHookSetWindowsHookEx*>(raw);
        event.type = EDR_EVT_WINDOWS_HOOK;
        event.fields[field::kType] = "WINDOWS_HOOK";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kHookType] = std::to_string(message->Type());
        event.fields[field::kHookThreadId] = std::to_string(message->ThreadId());
        char procAddr[24] = {};
        std::snprintf(procAddr, sizeof(procAddr), "0x%llx",
                      static_cast<unsigned long long>(message->HookProc()));
        event.fields[field::kHookProcAddress] = procAddr;
        char inst[24] = {};
        std::snprintf(inst, sizeof(inst), "0x%llx",
                      static_cast<unsigned long long>(message->Instance()));
        event.fields[field::kHookInstance] = inst;
        event.fields[field::kHookModulePath] = MonitorUtf8(message->InstancePath());
        return true;
    }
    case emMSGHookCreateService: {
        auto* message = static_cast<cxMSGHookCreateService*>(raw);
        event.type = EDR_EVT_SERVICE_INSTALL_HOOK;
        event.fields[field::kType] = "SERVICE_INSTALL_HOOK";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kServiceName] = MonitorUtf8(message->ServiceName());
        event.fields[field::kServiceDisplayName] = MonitorUtf8(message->DisplayName());
        event.fields[field::kServiceImagePath] = MonitorUtf8(message->BinPath());
        event.fields[field::kServiceCreateType] = std::to_string(message->ServiceType());
        event.fields[field::kServiceStartType] = std::to_string(message->StartType());
        return true;
    }
    case emMSGHookStartService: {
        auto* message = static_cast<cxMSGHookStartService*>(raw);
        event.type = EDR_EVT_SERVICE_START_HOOK;
        event.fields[field::kType] = "SERVICE_START_HOOK";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kServiceName] = MonitorUtf8(message->ServiceName());
        return true;
    }
    case emMSGHookChangeServiceConfig: {
        auto* message = static_cast<cxMSGHookChangeServiceConfig*>(raw);
        event.type = EDR_EVT_SERVICE_CONFIG_CHANGE;
        event.fields[field::kType] = "SERVICE_CONFIG_CHANGE";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kServiceName] = MonitorUtf8(message->ServiceName());
        event.fields[field::kServiceConfigType] = std::to_string(message->ServiceType());
        event.fields[field::kServiceStartType] = std::to_string(message->StartType());
        return true;
    }
    case emMSGHookCoCreateInstance: {
        auto* message = static_cast<cxMSGHookCoCreateInstance*>(raw);
        event.type = EDR_EVT_CO_INSTANCE;
        event.fields[field::kType] = "CO_INSTANCE";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kComContext] = std::to_string(message->Context());
        event.fields[field::kComClassId] = MonitorUtf8(message->ClassId());
        event.fields[field::kComInterfaceId] = MonitorUtf8(message->InterfaceId());
        return true;
    }
    case emMSGHookMapViewOfSection: {
        auto* message = static_cast<cxMSGHookMapViewOfSection*>(raw);
        event.type = EDR_EVT_SECTION_MAP;
        event.fields[field::kType] = "SECTION_MAP";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kSectionPath] = MonitorUtf8(message->Path());
        uint32_t targetPid = message->ProcessId();
        event.fields[field::kTargetPid] = std::to_string(targetPid);
        event.fields[field::kSectionPid] = std::to_string(targetPid);
        event.fields[field::kCrossProcess] =
            event.pid != targetPid ? "true" : "false";
        return true;
    }
    case emMSGHookDuplicateHandle: {
        auto* message = static_cast<cxMSGHookDuplicateHandle*>(raw);
        event.type = EDR_EVT_HANDLE_DUPLICATE;
        event.fields[field::kType] = "HANDLE_DUPLICATE";
        SetMonitorProcessMetadata(event, message);
        uint32_t targetPid = message->ProcessId();
        event.fields[field::kSourcePid] = event.fields[field::kPid];
        event.fields[field::kTargetPid] = std::to_string(targetPid);
        event.fields[field::kCrossProcess] =
            event.pid != targetPid ? "true" : "false";
        event.fields[field::kTargetImage] = MonitorUtf8(message->Path());
        event.fields[field::kDuplicateHandleValue] =
            std::to_string(message->Handle());
        return true;
    }
    case emMSGHookSendInput: {
        auto* message = static_cast<cxMSGHookSendInput*>(raw);
        event.type = EDR_EVT_INPUT_SIMULATION;
        event.fields[field::kType] = "INPUT_SIMULATION";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kInputType] = std::to_string(message->Type());
        return true;
    }
    case emMSGHookShutdownSystem: {
        auto* message = static_cast<cxMSGHookShutdownSystem*>(raw);
        event.type = EDR_EVT_SYSTEM_SHUTDOWN;
        event.fields[field::kType] = "SYSTEM_SHUTDOWN";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kShutdownRestart] =
            message->Restart() ? "true" : "false";
        return true;
    }
    case emMSGHookSetSystemTime: {
        auto* message = static_cast<cxMSGHookSetSystemTime*>(raw);
        event.type = EDR_EVT_SYSTEM_TIME_CHANGE;
        event.fields[field::kType] = "SYSTEM_TIME_CHANGE";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kSystemTimeValue] =
            std::to_string(message->Time());
        return true;
    }
    case emMSGHookGetClipboardData: {
        auto* message = static_cast<cxMSGHookGetClipboardData*>(raw);
        event.type = EDR_EVT_CLIPBOARD_ACCESS;
        event.fields[field::kType] = "CLIPBOARD_ACCESS";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kClipboardFormat] =
            std::to_string(message->Format());
        return true;
    }
    case emMSGHookSetDeskWallpaper: {
        auto* message = static_cast<cxMSGHookSetDeskWallpaper*>(raw);
        event.type = EDR_EVT_WALLPAPER_CHANGE;
        event.fields[field::kType] = "WALLPAPER_CHANGE";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kWallpaperPath] = MonitorUtf8(message->Path());
        return true;
    }
    case emMSGHookUseCamera: {
        auto* message = static_cast<cxMSGHookUseCamera*>(raw);
        event.type = EDR_EVT_CAMERA_ACCESS;
        event.fields[field::kType] = "CAMERA_ACCESS";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kCameraAction] =
            std::to_string(message->Action());
        return true;
    }
    case emMSGHookKeyLogger: {
        auto* message = static_cast<cxMSGHookKeyLogger*>(raw);
        event.type = EDR_EVT_KEYLOGGER;
        event.fields[field::kType] = "KEYLOGGER";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kKeyLoggerType] =
            std::to_string(message->Type());
        return true;
    }
    case emMSGHookPowerShell: {
        auto* message = static_cast<cxMSGHookPowerShell*>(raw);
        event.type = EDR_EVT_POWERSHELL_HOOK;
        event.fields[field::kType] = "POWERSHELL_HOOK";
        SetMonitorProcessMetadata(event, message);
        event.fields[field::kPowerShellScriptPath] =
            MonitorUtf8(message->ScriptPath());
        event.fields[field::kPowerShellCommand] =
            MonitorUtf8(message->Command());
        return true;
    }
    default:
        return false;
    }
}

} // namespace edr

#endif /* EDR_IMONITOR_MAPPING_H */
