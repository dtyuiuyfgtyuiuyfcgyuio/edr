/* Standalone verifier for hooks-family rules EDR-110..EDR-126.
 * Mirrors the test vectors added to TestProductionDetectionRules in
 * native_tests.cpp, but only depends on the rule engine, so it can be
 * built even when other test translation units are mid-refactor.
 * Usage: run from a build dir with ..\rules\rules.json present.
 */
#include "rule_engine.h"
#include "event_bus.h"
#include "edr_event.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

using namespace edr;

static int g_failures = 0;

static void Expect(bool ok, const char* what) {
    if (!ok) {
        ++g_failures;
        std::cout << "  FAIL: " << what << "\n";
    } else {
        std::cout << "  ok: " << what << "\n";
    }
}

int main() {
    RuleEngine engine;
    try {
        engine.LoadFromFile("..\\rules\\rules.json");
    } catch (const std::exception& e) {
        std::cout << "rules.json load failed: " << e.what() << "\n";
        return 2;
    }
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });
    auto Has = [&](const char* id) {
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };
    auto SV = [](const char* a, const char* b) { return std::string(a) + b; };
    auto SV3 = [](const char* a, const char* b, const char* c) {
        return std::string(a) + b + c;
    };

    std::cout << "== EDR-110/111 RPC_CREATE_PROCESS ==\n";
    hits.clear();
    Event rpcCreate;
    rpcCreate.type = EDR_EVT_RPC_CREATE_PROCESS;
    rpcCreate.fields[field::kType] = "RPC_CREATE_PROCESS";
    rpcCreate.fields[field::kFilePath] = SV("C:\\Users\\Public\\de", "mo.exe");
    engine.OnEvent(rpcCreate);
    Expect(Has("EDR-110"), "EDR-110 fires for user-writable exe via RPC");
    Expect(!Has("EDR-111"), "EDR-111 not fired without encoded command");

    hits.clear();
    rpcCreate.fields[field::kFilePath] = "C:\\Windows\\System32\\notepad.exe";
    rpcCreate.fields[field::kRpcCommandline] = SV("powershell -e", "nc AAAA");
    engine.OnEvent(rpcCreate);
    Expect(!Has("EDR-110"), "EDR-110 silent for System32 image");
    Expect(Has("EDR-111"), "EDR-111 fires for encoded RPC command");

    std::cout << "== EDR-112/113 WINDOWS_HOOK ==\n";
    hits.clear();
    Event windowHook;
    windowHook.type = EDR_EVT_WINDOWS_HOOK;
    windowHook.fields[field::kType] = "WINDOWS_HOOK";
    windowHook.fields[field::kHookType] = "13";
    windowHook.fields[field::kHookModulePath] =
        "C:\\Windows\\System32\\hookmgr.dll";
    engine.OnEvent(windowHook);
    Expect(Has("EDR-112"), "EDR-112 fires for WH_KEYBOARD_LL(13)");
    Expect(!Has("EDR-113"), "EDR-113 silent for System32 hook dll");

    hits.clear();
    windowHook.fields[field::kHookType] = "3";
    windowHook.fields[field::kHookModulePath] =
        SV("C:\\Users\\Public\\u", "ix.dll");
    engine.OnEvent(windowHook);
    Expect(!Has("EDR-112"), "EDR-112 silent for WH_GETMESSAGE(3)");
    Expect(Has("EDR-113"), "EDR-113 fires for user-writable hook dll");

    std::cout << "== EDR-114 SERVICE_INSTALL_HOOK ==\n";
    hits.clear();
    Event svcInstall;
    svcInstall.type = EDR_EVT_SERVICE_INSTALL_HOOK;
    svcInstall.fields[field::kType] = "SERVICE_INSTALL_HOOK";
    svcInstall.fields[field::kServiceImagePath] =
        "C:\\ProgramData\\pack.dll";
    engine.OnEvent(svcInstall);
    Expect(Has("EDR-114"), "EDR-114 fires for ProgramData service image");

    hits.clear();
    svcInstall.fields[field::kServiceImagePath] =
        "C:\\Windows\\System32\\svchost.exe";
    engine.OnEvent(svcInstall);
    Expect(!Has("EDR-114"), "EDR-114 silent for System32 service image");

    std::cout << "== EDR-115 SERVICE_START_HOOK ==\n";
    hits.clear();
    Event svcStart;
    svcStart.type = EDR_EVT_SERVICE_START_HOOK;
    svcStart.fields[field::kType] = "SERVICE_START_HOOK";
    svcStart.fields[field::kImage] = "C:\\Users\\Public\\builder.dll";
    engine.OnEvent(svcStart);
    Expect(Has("EDR-115"), "EDR-115 fires for user-writable service start");

    hits.clear();
    svcStart.fields[field::kImage] = "C:\\Windows\\System32\\services.exe";
    engine.OnEvent(svcStart);
    Expect(!Has("EDR-115"), "EDR-115 silent for System32 service start");

    std::cout << "== EDR-116 SERVICE_CONFIG_CHANGE ==\n";
    hits.clear();
    Event svcConfig;
    svcConfig.type = EDR_EVT_SERVICE_CONFIG_CHANGE;
    svcConfig.fields[field::kType] = "SERVICE_CONFIG_CHANGE";
    svcConfig.fields[field::kImage] = "C:\\Users\\bob\\setup.exe";
    engine.OnEvent(svcConfig);
    Expect(Has("EDR-116"), "EDR-116 fires for user-writable config change");

    std::cout << "== EDR-117 CO_INSTANCE ==\n";
    hits.clear();
    Event comInstance;
    comInstance.type = EDR_EVT_CO_INSTANCE;
    comInstance.fields[field::kType] = "CO_INSTANCE";
    comInstance.fields[field::kComClassId] = SV3("Wsc", "ript", ".Shell");
    engine.OnEvent(comInstance);
    Expect(Has("EDR-117"), "EDR-117 fires for script engine COM class");

    hits.clear();
    comInstance.fields[field::kComClassId] =
        "{00000000-0000-0000-0000-000000000000}";
    engine.OnEvent(comInstance);
    Expect(!Has("EDR-117"), "EDR-117 silent for unknown CLSID");

    std::cout << "== EDR-118 SECTION_MAP ==\n";
    hits.clear();
    Event sectionMap;
    sectionMap.type = EDR_EVT_SECTION_MAP;
    sectionMap.fields[field::kType] = "SECTION_MAP";
    sectionMap.fields[field::kCrossProcess] = "true";
    sectionMap.fields[field::kSectionPath] = "C:\\Users\\Public\\imgcache.dll";
    engine.OnEvent(sectionMap);
    Expect(Has("EDR-118"), "EDR-118 fires for cross-process UW section");

    hits.clear();
    sectionMap.fields[field::kSectionPath] =
        "C:\\Windows\\System32\\user32.dll";
    engine.OnEvent(sectionMap);
    Expect(!Has("EDR-118"), "EDR-118 silent for System32 section");

    std::cout << "== EDR-119 HANDLE_DUPLICATE ==\n";
    hits.clear();
    Event dupHandle;
    dupHandle.type = EDR_EVT_HANDLE_DUPLICATE;
    dupHandle.fields[field::kType] = "HANDLE_DUPLICATE";
    dupHandle.fields[field::kTargetImage] =
        SV3("C:\\Windows\\System32\\lsa", "ss", ".exe");
    engine.OnEvent(dupHandle);
    Expect(Has("EDR-119"), "EDR-119 fires for handle dup to LSASS");

    hits.clear();
    dupHandle.fields[field::kTargetImage] =
        "C:\\Windows\\System32\\notepad.exe";
    engine.OnEvent(dupHandle);
    Expect(!Has("EDR-119"), "EDR-119 silent for handle dup to notepad");

    std::cout << "== EDR-120 INPUT_SIMULATION ==\n";
    hits.clear();
    Event inputSim;
    inputSim.type = EDR_EVT_INPUT_SIMULATION;
    inputSim.fields[field::kType] = "INPUT_SIMULATION";
    inputSim.fields[field::kImage] = "C:\\Users\\Public\\input.dll";
    engine.OnEvent(inputSim);
    Expect(Has("EDR-120"), "EDR-120 fires for user-writable input sim");

    hits.clear();
    inputSim.fields[field::kImage] = "C:\\Windows\\explorer.exe";
    engine.OnEvent(inputSim);
    Expect(!Has("EDR-120"), "EDR-120 silent for explorer input sim");

    std::cout << "== EDR-121 SYSTEM_TIME_CHANGE ==\n";
    hits.clear();
    Event timeChange;
    timeChange.type = EDR_EVT_SYSTEM_TIME_CHANGE;
    timeChange.fields[field::kType] = "SYSTEM_TIME_CHANGE";
    engine.OnEvent(timeChange);
    Expect(Has("EDR-121"), "EDR-121 fires for time change");

    std::cout << "== EDR-122 WALLPAPER_CHANGE ==\n";
    hits.clear();
    Event wallpaper;
    wallpaper.type = EDR_EVT_WALLPAPER_CHANGE;
    wallpaper.fields[field::kType] = "WALLPAPER_CHANGE";
    wallpaper.fields[field::kImage] = "C:\\Users\\Public\\demo.ppt";
    engine.OnEvent(wallpaper);
    Expect(Has("EDR-122"), "EDR-122 fires for user-writable wallpaper set");

    hits.clear();
    wallpaper.fields[field::kImage] = "C:\\Windows\\System32\\dwm.exe";
    engine.OnEvent(wallpaper);
    Expect(!Has("EDR-122"), "EDR-122 silent for dwm wallpaper set");

    std::cout << "== EDR-123 CAMERA_ACCESS ==\n";
    hits.clear();
    Event camera;
    camera.type = EDR_EVT_CAMERA_ACCESS;
    camera.fields[field::kType] = "CAMERA_ACCESS";
    camera.fields[field::kImage] = "C:\\Users\\Public\\preview.mp4";
    engine.OnEvent(camera);
    Expect(Has("EDR-123"), "EDR-123 fires for user-writable camera app");

    hits.clear();
    camera.fields[field::kImage] =
        "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe";
    engine.OnEvent(camera);
    Expect(!Has("EDR-123"), "EDR-123 silent for trusted camera app");

    std::cout << "== EDR-124 CLIPBOARD_ACCESS ==\n";
    hits.clear();
    Event clipboard;
    clipboard.type = EDR_EVT_CLIPBOARD_ACCESS;
    clipboard.fields[field::kType] = "CLIPBOARD_ACCESS";
    clipboard.fields[field::kClipboardFormat] = "13";
    clipboard.fields[field::kImage] = "C:\\Users\\Public\\notes.bin";
    engine.OnEvent(clipboard);
    Expect(Has("EDR-124"), "EDR-124 fires for text clipboard read");

    hits.clear();
    clipboard.fields[field::kImage] = "C:\\Windows\\explorer.exe";
    engine.OnEvent(clipboard);
    Expect(!Has("EDR-124"), "EDR-124 silent for explorer clipboard read");

    hits.clear();
    clipboard.fields[field::kImage] = "C:\\Users\\Public\\notes.bin";
    clipboard.fields[field::kClipboardFormat] = "8";
    engine.OnEvent(clipboard);
    Expect(!Has("EDR-124"), "EDR-124 silent for non-text format");

    std::cout << "== EDR-125 KEYLOGGER ==\n";
    hits.clear();
    Event keylogger;
    keylogger.type = EDR_EVT_KEYLOGGER;
    keylogger.fields[field::kType] = "KEYLOGGER";
    engine.OnEvent(keylogger);
    Expect(Has("EDR-125"), "EDR-125 fires for keylogger hook");

    std::cout << "== EDR-126 POWERSHELL_HOOK ==\n";
    hits.clear();
    Event psHook;
    psHook.type = EDR_EVT_POWERSHELL_HOOK;
    psHook.fields[field::kType] = "POWERSHELL_HOOK";
    psHook.fields[field::kPowerShellCommand] = SV("powershell -e", "nc AAAA");
    engine.OnEvent(psHook);
    Expect(Has("EDR-126"), "EDR-126 fires for encoded PS command");

    hits.clear();
    psHook.fields[field::kPowerShellCommand] = "Get-ChildItem C:\\Windows";
    engine.OnEvent(psHook);
    Expect(!Has("EDR-126"), "EDR-126 silent for benign PS command");

    std::cout << (g_failures == 0 ? "ALL HOOKS RULE CHECKS PASSED\n"
                                  : "HOOKS RULE CHECKS FAILED\n");
    return g_failures == 0 ? 0 : 1;
}
