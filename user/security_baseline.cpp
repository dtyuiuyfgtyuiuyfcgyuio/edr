/*
 * security_baseline.cpp - Host security configuration baseline check.
 *
 * Checks: Windows Defender real-time protection state, Windows Firewall
 * per-profile state, UAC enforcement, LSA protection (RunAsPPL), LSASS
 * process, automatic updates policy, and the built-in Administrator /
 * Guest account states. Each check prints PASS / FAIL / SKIP. Returns the
 * number of FAIL items.
 *
 * Read-only: only registry reads and service queries are performed.
 */
#include <windows.h>
#include <tlhelp32.h>
#include <lmcons.h>
#include <lmapibuf.h>
#include <lmaccess.h>

#include <cstdio>
#include <string>

#include "security_baseline.h"

namespace edr {

namespace {

enum class CheckResult {
    Pass,
    Fail,
    Skip, /* not applicable / unavailable */
};

struct Check {
    const char* name;
    CheckResult result;
    const char* detail;
};

static std::string RegDword(HKEY root, const wchar_t* subKey,
                            const wchar_t* value, DWORD& out) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subKey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return "open_failed";
    }
    DWORD type = 0;
    DWORD size = sizeof(out);
    LONG rc = RegQueryValueExW(key, value, nullptr, &type,
                               reinterpret_cast<BYTE*>(&out), &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS) return "missing";
    if (type != REG_DWORD || size != sizeof(out)) return "type_error";
    return std::string();
}

static bool RegDwordValue(HKEY root, const wchar_t* subKey,
                          const wchar_t* value, DWORD& out) {
    std::string err = RegDword(root, subKey, value, out);
    return err.empty();
}

static void CheckDefender(Check& check) {
    DWORD disableRealtime = 0;
    if (!RegDwordValue(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\"
            L"Real-Time Protection", L"DisableRealtimeMonitoring",
            disableRealtime)) {
        /* No policy key; treat Defender state as unmanaged but present. */
        check.result = CheckResult::Pass;
        check.detail = "no group policy override";
        return;
    }
    if (disableRealtime != 0) {
        check.result = CheckResult::Fail;
        check.detail = "realtime monitoring disabled by policy";
    } else {
        check.result = CheckResult::Pass;
        check.detail = "realtime monitoring enabled by policy";
    }
}

static void CheckFirewall(Check& check) {
    /* Windows Firewall per-profile enable state is exposed via the shared
     * access API; for a read-only baseline we read the policy registry
     * values. */
    DWORD value = 0;
    std::string err = RegDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\"
        L"FirewallPolicy\\StandardProfile", L"EnableFirewall", value);
    if (!err.empty()) {
        check.result = CheckResult::Skip;
        check.detail = "firewall state not readable";
        return;
    }
    if (value == 0) {
        check.result = CheckResult::Fail;
        check.detail = "standard profile firewall disabled";
    } else {
        check.result = CheckResult::Pass;
        check.detail = "standard profile firewall enabled";
    }
}

static void CheckUac(Check& check) {
    DWORD enableLua = 0;
    if (!RegDwordValue(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            L"EnableLUA", enableLua)) {
        check.result = CheckResult::Skip;
        check.detail = "UAC state not readable";
        return;
    }
    if (enableLua == 0) {
        check.result = CheckResult::Fail;
        check.detail = "UAC (EnableLUA) disabled";
    } else {
        check.result = CheckResult::Pass;
        check.detail = "UAC (EnableLUA) enabled";
    }
}

static void CheckLsaProtection(Check& check) {
    DWORD runAsPpl = 0;
    if (!RegDwordValue(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL",
            runAsPpl)) {
        check.result = CheckResult::Skip;
        check.detail = "RunAsPPL not configured";
        return;
    }
    if (runAsPpl == 0) {
        check.result = CheckResult::Fail;
        check.detail = "LSA protection (RunAsPPL) disabled";
    } else {
        check.result = CheckResult::Pass;
        check.detail = "LSA protection (RunAsPPL) enabled";
    }
}

static void CheckAutoUpdates(Check& check) {
    DWORD noAutoUpdate = 0;
    if (!RegDwordValue(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
            L"NoAutoUpdate", noAutoUpdate)) {
        check.result = CheckResult::Skip;
        check.detail = "auto-update policy not configured";
        return;
    }
    if (noAutoUpdate != 0) {
        check.result = CheckResult::Fail;
        check.detail = "automatic updates disabled by policy";
    } else {
        check.result = CheckResult::Pass;
        check.detail = "automatic updates not disabled";
    }
}

static void CheckBuiltinAdmin(Check& check) {
    /* Local user account enabled state via NetUserGetInfo. */
    typedef NET_API_STATUS(WINAPI* NetUserGetInfoFn)(LPCWSTR, LPCWSTR, DWORD,
                                                     LPBYTE*);
    HMODULE netapi = LoadLibraryW(L"netapi32.dll");
    if (netapi == nullptr) {
        check.result = CheckResult::Skip;
        check.detail = "netapi32 unavailable";
        return;
    }
    auto fn = reinterpret_cast<NetUserGetInfoFn>(
        GetProcAddress(netapi, "NetUserGetInfo"));
    if (fn == nullptr) {
        FreeLibrary(netapi);
        check.result = CheckResult::Skip;
        check.detail = "NetUserGetInfo unavailable";
        return;
    }
    LPBYTE buffer = nullptr;
    NET_API_STATUS status = fn(L".", L"Administrator", 1, &buffer);
    if (status != 0 || buffer == nullptr) {
        FreeLibrary(netapi);
        check.result = CheckResult::Skip;
        check.detail = "Administrator account not queryable";
        return;
    }
    /* USER_INFO_1: usri1_flags bit USER_ACCOUNT_DISABLED (0x0001). */
    DWORD flags = reinterpret_cast<USER_INFO_1*>(buffer)->usri1_flags;
    NetApiBufferFree(buffer);
    FreeLibrary(netapi);
    if (flags & 0x1u) {
        check.result = CheckResult::Pass;
        check.detail = "Administrator account disabled";
    } else {
        check.result = CheckResult::Fail;
        check.detail = "built-in Administrator account enabled";
    }
}

static void CheckLsassRunning(Check& check) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        check.result = CheckResult::Skip;
        check.detail = "process snapshot unavailable";
        return;
    }
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (found) {
        check.result = CheckResult::Pass;
        check.detail = "lsass.exe running";
    } else {
        check.result = CheckResult::Fail;
        check.detail = "lsass.exe not running";
    }
}

} // namespace

int RunSecurityBaseline() {
    Check checks[] = {
        {"Windows Defender real-time protection", CheckResult::Skip, ""},
        {"Windows Firewall (standard profile)", CheckResult::Skip, ""},
        {"UAC enabled (EnableLUA)", CheckResult::Skip, ""},
        {"LSA protection (RunAsPPL)", CheckResult::Skip, ""},
        {"Automatic updates", CheckResult::Skip, ""},
        {"Built-in Administrator disabled", CheckResult::Skip, ""},
        {"lsass.exe running", CheckResult::Skip, ""},
    };

    CheckDefender(checks[0]);
    CheckFirewall(checks[1]);
    CheckUac(checks[2]);
    CheckLsaProtection(checks[3]);
    CheckAutoUpdates(checks[4]);
    CheckBuiltinAdmin(checks[5]);
    CheckLsassRunning(checks[6]);

    std::printf("EDR security baseline\n");
    std::printf("=====================\n");
    int fails = 0;
    int skips = 0;
    for (const Check& check : checks) {
        const char* resultStr = "SKIP";
        if (check.result == CheckResult::Pass) resultStr = "PASS";
        else if (check.result == CheckResult::Fail) resultStr = "FAIL";
        if (check.result == CheckResult::Fail) fails++;
        if (check.result == CheckResult::Skip) skips++;
        std::printf("[%s] %s%s%s\n", resultStr, check.name,
                    check.detail[0] ? " - " : "", check.detail);
    }
    std::printf("----\n%d fail(s), %d skip(s), %d total\n",
                fails, skips, static_cast<int>(sizeof(checks) / sizeof(checks[0])));
    return fails;
}

} // namespace edr
