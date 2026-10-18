/*
 * imonitor_mapping_tests.cpp - iMonitor message -> Event mapping tests.
 *
 * Compiled only when EDR_IMONITOR_AVAILABLE is defined (see CMakeLists.txt):
 * the iMonitor SDK headers require ATL and the mapping header is only
 * meaningful when the real collector is compiled. The fake message classes
 * below implement IMonitorMessage's pure virtuals and stand in for the
 * concrete SDK message objects; MapIMonitorMessage downcasts to
 * cxMSGProcessOpen/cxMSGThreadCreate, so the fakes derive from those.
 */
#include <winsock2.h>
#include <windows.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "iMonitorSDK.h"
#include "iMonitorProtocol.h"
#include "imonitor_mapping.h"
#include "process_access.h"

using namespace edr;

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "check failed at line " << __LINE__ << ": " #condition "\n"; \
        throw std::runtime_error("imonitor mapping test check failed"); \
    } \
} while (0)

namespace {

template <typename T>
class FakeMonitorMessage final : public T {
public:
    cxMSGHeader header = {};
    std::unordered_map<ULONG, ULONGLONG> numbers;
    std::unordered_map<ULONG, std::wstring> strings;
    cxMSGDataIP ip;
    IMonitorMessage::Binary binary = {};
    PVOID context = nullptr;

    void SetType(ULONG type) { header.Type = type; }
    void SetCurrentProcessId(ULONG pid) { header.CurrentProcessId = pid; }
    void SetNumber(ULONG index, ULONGLONG value) { numbers[index] = value; }
    void SetString(ULONG index, const wchar_t* value) {
        strings[index] = value != nullptr ? value : L"";
    }

    cxMSGHeader* GetHeader() override { return &header; }
    IMonitorMessageProcess* GetProcess() override { return nullptr; }
    IMonitorMessageProcess* GetRpcCallerProcess() override { return nullptr; }
    LPCWSTR GetTypeName() override { return L"fake"; }
    ULONG GetFieldCount() override { return 0; }
    emMSGDataType GetFieldType(ULONG) override { return emMSGDataUnknown; }
    LPCWSTR GetFieldName(ULONG) override { return L""; }
    ULONG GetFieldIndex(LPCWSTR) override { return 0; }
    ULONG GetULONG(ULONG index) override {
        auto it = numbers.find(index);
        return it == numbers.end() ? 0 : static_cast<ULONG>(it->second);
    }
    ULONGLONG GetULONGLONG(ULONG index) override {
        auto it = numbers.find(index);
        return it == numbers.end() ? 0 : it->second;
    }
    cxMSGDataIPRef GetIP(ULONG) override { return ip; }
    IMonitorMessage::Binary GetBinary(ULONG) override { return binary; }
    LPCWSTR GetString(ULONG index) override {
        static const wchar_t kEmpty[] = L"";
        auto it = strings.find(index);
        return it == strings.end() ? kEmpty : it->second.c_str();
    }
    LPCWSTR GetFormatedString(ULONG index) override { return GetString(index); }
    bool IsMatch(ULONG, LPCWSTR, bool) override { return false; }
    ULONGLONG GetNumber(LPCWSTR, bool* hasValue) override {
        if (hasValue != nullptr) *hasValue = false;
        return 0;
    }
    LPCWSTR GetString(LPCWSTR, bool* hasValue) override {
        if (hasValue != nullptr) *hasValue = false;
        return L"";
    }
    bool IsWaiting() override { return false; }
    bool SetAction(const cxMSGAction&) override { return false; }
    bool SetBlock() override { return false; }
    bool SetGrantedAccess(ULONG) override { return false; }
    bool SetIPRedirect(ULONG, USHORT, ULONG) override { return false; }
    bool SetTerminateProcess() override { return false; }
    bool SetTerminateThread() override { return false; }
    bool SetInjectDll(LPCWSTR, bool, bool) override { return false; }
    bool SetFileRedirect(LPCWSTR) override { return false; }
    bool InjectPacket(PCHAR, ULONG, bool) override { return false; }
    bool Pending() override { return false; }
    void CompletePending() override {}
    void SetCustomContext(PVOID value) override { context = value; }
    PVOID GetCustomContext() override { return context; }
    bool IsUserMonitor() override { return false; }
};

using FakeProcessOpenMessage = FakeMonitorMessage<cxMSGProcessOpen>;
using FakeThreadCreateMessage = FakeMonitorMessage<cxMSGThreadCreate>;
using FakeReadProcessMemoryMessage =
    FakeMonitorMessage<cxMSGHookReadProcessMemory>;
using FakeFileReadMessage = FakeMonitorMessage<cxMSGFileRead>;
using FakeQueueApcMessage = FakeMonitorMessage<cxMSGHookQueueApcThread>;
using FakeSetContextMessage = FakeMonitorMessage<cxMSGHookSetContextThread>;
using FakeWriteProcessMemoryMessage =
    FakeMonitorMessage<cxMSGHookWriteProcessMemory>;

} // namespace

void RunIMonitorMappingTests() {
    /* emMSGThreadCreate, remote thread: current pid differs from target. */
    {
        FakeThreadCreateMessage message;
        message.SetType(emMSGThreadCreate);
        message.SetCurrentProcessId(1000);
        message.SetNumber(cxMSGThreadCreate::emMSGFieldCurrentProcessCreateTime,
                          123456);
        message.SetString(cxMSGThreadCreate::emMSGFieldCurrentProcessPath,
                          L"C:\\tool.exe");
        message.SetNumber(cxMSGThreadCreate::emMSGFieldProcessId, 2000);
        message.SetNumber(cxMSGThreadCreate::emMSGFieldThreadId, 777);
        message.SetNumber(cxMSGThreadCreate::emMSGFieldStartAddress,
                          0x7ff612345678ull);
        message.SetNumber(cxMSGThreadCreate::emMSGFieldRemoteThread, 1);
        message.SetString(cxMSGThreadCreate::emMSGFieldPath,
                          L"C:\\target.exe");

        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source; /* collector_imonitor.cpp */
        CHECK(MapIMonitorMessage(event, &message));
        CHECK(event.type == EDR_EVT_THREAD_CREATE);
        CHECK(event.fields[field::kType] == "THREAD_CREATE");
        CHECK(event.pid == 1000);
        CHECK(event.processIdentity == "1000@123456");
        CHECK(event.fields[field::kSourcePid] == "1000");
        CHECK(event.fields[field::kTargetPid] == "2000");
        CHECK(event.fields[field::kThreadId] == "777");
        CHECK(event.fields[field::kRemoteThread] == "true");
        CHECK(event.fields[field::kStartAddress] == "0x7ff612345678");
        CHECK(event.fields[field::kSource] == "imonitor");
        CHECK(event.source == "imonitor");
        CHECK(event.fields[field::kActorImage] == "C:\\tool.exe");
        CHECK(event.fields[field::kTargetImage] == "C:\\target.exe");
    }

    /* emMSGThreadCreate, local thread: current pid equals the target. */
    {
        FakeThreadCreateMessage message;
        message.SetType(emMSGThreadCreate);
        message.SetCurrentProcessId(1000);
        message.SetNumber(cxMSGThreadCreate::emMSGFieldCurrentProcessCreateTime,
                          123456);
        message.SetNumber(cxMSGThreadCreate::emMSGFieldProcessId, 1000);
        message.SetNumber(cxMSGThreadCreate::emMSGFieldThreadId, 1);
        message.SetNumber(cxMSGThreadCreate::emMSGFieldStartAddress, 0x1000);

        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        CHECK(MapIMonitorMessage(event, &message));
        CHECK(event.type == EDR_EVT_THREAD_CREATE);
        CHECK(event.fields[field::kRemoteThread] == "false");
        CHECK(event.fields[field::kStartAddress] == "0x1000");
    }

    /* emMSGProcessOpen, cross-process full access with duplicated handle. */
    {
        FakeProcessOpenMessage message;
        message.SetType(emMSGProcessOpen);
        message.SetCurrentProcessId(1000);
        message.SetNumber(cxMSGProcessOpen::emMSGFieldCurrentProcessCreateTime,
                          123456);
        message.SetString(cxMSGProcessOpen::emMSGFieldCurrentProcessPath,
                          L"C:\\tool.exe");
        message.SetNumber(cxMSGProcessOpen::emMSGFieldProcessId, 2000);
        message.SetNumber(cxMSGProcessOpen::emMSGFieldDesiredAccess,
                          0x001fffff);
        message.SetNumber(cxMSGProcessOpen::emMSGFieldDuplicate, 1);
        message.SetString(cxMSGProcessOpen::emMSGFieldPath,
                          L"C:\\target.exe");

        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        CHECK(MapIMonitorMessage(event, &message));
        CHECK(event.type == EDR_EVT_PROCESS_ACCESS);
        CHECK(event.fields[field::kType] == "PROCESS_ACCESS");
        CHECK(event.fields[field::kGrantedAccess] == "0x001fffff");
        CHECK(event.fields[field::kAccessVmWrite] == "true");
        CHECK(event.fields[field::kAccessVmOperation] == "true");
        CHECK(event.fields[field::kAccessDuplicateHandle] == "true");
        CHECK(event.fields[field::kHandleDuplicated] == "true");
        CHECK(event.fields[field::kCrossProcess] == "true");
        CHECK(event.fields[field::kTargetPid] == "2000");
        CHECK(event.fields[field::kSourcePid] == "1000");
        CHECK(event.processIdentity == "1000@123456");
    }

    /* emMSGProcessOpen, same-process open without a duplicated handle. */
    {
        FakeProcessOpenMessage message;
        message.SetType(emMSGProcessOpen);
        message.SetCurrentProcessId(2000);
        message.SetNumber(cxMSGProcessOpen::emMSGFieldCurrentProcessCreateTime,
                          99);
        message.SetNumber(cxMSGProcessOpen::emMSGFieldProcessId, 2000);
        message.SetNumber(cxMSGProcessOpen::emMSGFieldDesiredAccess,
                          PROCESS_VM_OPERATION);
        message.SetNumber(cxMSGProcessOpen::emMSGFieldDuplicate, 0);

        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        CHECK(MapIMonitorMessage(event, &message));
        CHECK(event.type == EDR_EVT_PROCESS_ACCESS);
        CHECK(event.fields[field::kHandleDuplicated] == "false");
        CHECK(event.fields[field::kCrossProcess] == "false");
        CHECK(event.fields[field::kAccessVmWrite] == "false");
        CHECK(event.fields[field::kAccessVmOperation] == "true");
        CHECK(event.processIdentity == "2000@99");
    }

    /* emMSGHookReadProcessMemory, cross-process read into lsass. */
    {
        FakeReadProcessMemoryMessage message;
        message.SetType(emMSGHookReadProcessMemory);
        message.SetCurrentProcessId(1000);
        message.SetNumber(cxMSGHookReadProcessMemory::
            emMSGFieldCurrentProcessCreateTime, 123456);
        message.SetString(cxMSGHookReadProcessMemory::
            emMSGFieldCurrentProcessPath, L"C:\\tool.exe");
        message.SetNumber(cxMSGHookReadProcessMemory::emMSGFieldProcessId,
                          2000);
        message.SetNumber(cxMSGHookReadProcessMemory::emMSGFieldBaseAddress,
                          0x7ff600004000ull);
        message.SetNumber(cxMSGHookReadProcessMemory::emMSGFieldSize, 4096);
        message.SetString(cxMSGHookReadProcessMemory::emMSGFieldPath,
                          L"C:\\Windows\\System32\\lsass.exe");

        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        CHECK(MapIMonitorMessage(event, &message));
        CHECK(event.type == EDR_EVT_PROCESS_READ);
        CHECK(event.fields[field::kType] == "PROCESS_READ");
        CHECK(event.processIdentity == "1000@123456");
        CHECK(event.fields[field::kSourcePid] == "1000");
        CHECK(event.fields[field::kTargetPid] == "2000");
        CHECK(event.fields[field::kTargetImage] ==
              "C:\\Windows\\System32\\lsass.exe");
        CHECK(event.fields[field::kBaseAddress] == "0x7ff600004000");
        CHECK(event.fields[field::kMemorySize] == "4096");
        CHECK(event.fields[field::kCrossProcess] == "true");
    }

    /* emMSGFileRead, SAM hive path (mixed case): mapped. */
    {
        FakeFileReadMessage message;
        message.SetType(emMSGFileRead);
        message.SetCurrentProcessId(1000);
        message.SetNumber(cxMSGFileRead::emMSGFieldCurrentProcessCreateTime,
                          123456);
        message.SetString(cxMSGFileRead::emMSGFieldCurrentProcessPath,
                          L"C:\\Windows\\System32\\smss.exe");
        message.SetString(cxMSGFileRead::emMSGFieldPath,
                          L"\\Device\\HarddiskVolume2\\Windows\\System32\\config\\SaM");
        message.SetNumber(cxMSGFileRead::emMSGFieldReadLength, 512);
        message.SetNumber(cxMSGFileRead::emMSGFieldOffset, 0x1000);

        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        CHECK(MapIMonitorMessage(event, &message));
        CHECK(event.type == EDR_EVT_FILE_READ);
        CHECK(event.fields[field::kType] == "FILE_READ");
        CHECK(event.fields[field::kFilePath] ==
              "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\SaM");
        CHECK(event.fields[field::kTargetPath] ==
              "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\SaM");
        CHECK(event.fields[field::kFileLength] == "512");
        CHECK(event.fields[field::kFileOffset] == "4096");
    }

    /* emMSGFileRead, SECURITY hive (lowercase): mapped. */
    {
        FakeFileReadMessage message;
        message.SetType(emMSGFileRead);
        message.SetCurrentProcessId(1000);
        message.SetString(cxMSGFileRead::emMSGFieldPath,
                          L"C:\\Windows\\System32\\config\\security");
        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        CHECK(MapIMonitorMessage(event, &message));
        CHECK(event.type == EDR_EVT_FILE_READ);
        CHECK(event.fields[field::kFilePath] ==
              "C:\\Windows\\System32\\config\\security");
    }

    /* emMSGFileRead, SYSTEM hive: mapped. */
    {
        FakeFileReadMessage message;
        message.SetType(emMSGFileRead);
        message.SetCurrentProcessId(1000);
        message.SetString(cxMSGFileRead::emMSGFieldPath,
                          L"C:\\Windows\\System32\\config\\System");
        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        CHECK(MapIMonitorMessage(event, &message));
        CHECK(event.type == EDR_EVT_FILE_READ);
    }

    /* emMSGFileRead, non-sensitive path: rejected before any fields. */
    {
        FakeFileReadMessage message;
        message.SetType(emMSGFileRead);
        message.SetString(cxMSGFileRead::emMSGFieldPath,
                          L"C:\\Windows\\System32\\config\\software");
        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        CHECK(!MapIMonitorMessage(event, &message));
        CHECK(event.type == 0);
    }

    /* emMSGHookQueueApcThread, cross-process APC injection. */
    {
        FakeQueueApcMessage message;
        message.SetType(emMSGHookQueueApcThread);
        message.SetCurrentProcessId(1000);
        message.SetNumber(cxMSGHookQueueApcThread::
            emMSGFieldCurrentProcessCreateTime, 123456);
        message.SetString(cxMSGHookQueueApcThread::
            emMSGFieldCurrentProcessPath, L"C:\\tool.exe");
        message.SetNumber(cxMSGHookQueueApcThread::emMSGFieldProcessId, 2000);
        message.SetNumber(cxMSGHookQueueApcThread::emMSGFieldThreadId, 777);
        message.SetNumber(cxMSGHookQueueApcThread::emMSGFieldApcRoutine,
                          0x7ff612345678ull);
        message.SetString(cxMSGHookQueueApcThread::emMSGFieldPath,
                          L"C:\\Windows\\explorer.exe");

        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        CHECK(MapIMonitorMessage(event, &message));
        CHECK(event.type == EDR_EVT_APC_INJECT);
        CHECK(event.fields[field::kType] == "APC_INJECT");
        CHECK(event.processIdentity == "1000@123456");
        CHECK(event.fields[field::kSourcePid] == "1000");
        CHECK(event.fields[field::kTargetPid] == "2000");
        CHECK(event.fields[field::kThreadId] == "777");
        CHECK(event.fields[field::kStartAddress] == "0x7ff612345678");
        CHECK(event.fields[field::kTargetImage] ==
              "C:\\Windows\\explorer.exe");
        CHECK(event.fields[field::kCrossProcess] == "true");
    }

    /* emMSGHookSetContextThread, cross-process context hijack. */
    {
        FakeSetContextMessage message;
        message.SetType(emMSGHookSetContextThread);
        message.SetCurrentProcessId(1000);
        message.SetNumber(cxMSGHookSetContextThread::
            emMSGFieldCurrentProcessCreateTime, 123456);
        message.SetNumber(cxMSGHookSetContextThread::emMSGFieldProcessId,
                          2000);
        message.SetNumber(cxMSGHookSetContextThread::emMSGFieldThreadId, 42);
        message.SetString(cxMSGHookSetContextThread::emMSGFieldPath,
                          L"C:\\Windows\\System32\\svchost.exe");

        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        CHECK(MapIMonitorMessage(event, &message));
        CHECK(event.type == EDR_EVT_CONTEXT_CHANGE);
        CHECK(event.fields[field::kType] == "CONTEXT_CHANGE");
        CHECK(event.fields[field::kSourcePid] == "1000");
        CHECK(event.fields[field::kTargetPid] == "2000");
        CHECK(event.fields[field::kThreadId] == "42");
        CHECK(event.fields[field::kTargetImage] ==
              "C:\\Windows\\System32\\svchost.exe");
        CHECK(event.fields[field::kCrossProcess] == "true");
    }

    /* emMSGHookWriteProcessMemory, cross-process memory write. */
    {
        FakeWriteProcessMemoryMessage message;
        message.SetType(emMSGHookWriteProcessMemory);
        message.SetCurrentProcessId(1000);
        message.SetNumber(cxMSGHookWriteProcessMemory::
            emMSGFieldCurrentProcessCreateTime, 123456);
        message.SetString(cxMSGHookWriteProcessMemory::
            emMSGFieldCurrentProcessPath, L"C:\\tool.exe");
        message.SetNumber(cxMSGHookWriteProcessMemory::emMSGFieldProcessId,
                          2000);
        message.SetNumber(cxMSGHookWriteProcessMemory::emMSGFieldBaseAddress,
                          0x7ff612340000ull);
        message.SetNumber(cxMSGHookWriteProcessMemory::emMSGFieldSize, 8192);
        message.SetString(cxMSGHookWriteProcessMemory::emMSGFieldPath,
                          L"C:\\Windows\\System32\\lsass.exe");

        Event event;
        event.source = "imonitor";
        event.fields[field::kSource] = event.source;
        CHECK(MapIMonitorMessage(event, &message));
        CHECK(event.type == EDR_EVT_MEMORY_WRITE);
        CHECK(event.fields[field::kType] == "MEMORY_WRITE");
        CHECK(event.fields[field::kSourcePid] == "1000");
        CHECK(event.fields[field::kTargetPid] == "2000");
        CHECK(event.fields[field::kTargetImage] ==
              "C:\\Windows\\System32\\lsass.exe");
        CHECK(event.fields[field::kBaseAddress] == "0x7ff612340000");
        CHECK(event.fields[field::kMemorySize] == "8192");
        CHECK(event.fields[field::kCrossProcess] == "true");
    }

    /* Unmapped message type: mapping rejects it without touching the event. */
    {
        FakeThreadCreateMessage message;
        message.SetType(emMSGFileWrite);
        Event event;
        CHECK(!MapIMonitorMessage(event, &message));
        CHECK(event.type == 0);
    }
}
