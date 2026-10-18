/*
 * driver_policy_publisher.cpp - Build and push EDR_POLICY_V1 to the driver.
 *
 * Serialization rules (must mirror driver/policy_validate.h):
 *   - File rules: UTF-8 path -> UTF-16LE, must start with L'\\', byte length
 *     2..512 even, no NUL, no unpaired surrogates. Stored as an NT prefix
 *     (the driver matches on path-component boundary).
 *   - Net rules: strict dotted-quad parse (inet_pton semantics), octets in
 *     display order, never a special address, port 0..65535 (0 = any).
 *   - The whole table is validated with EdrPolicyEngineValidate before any
 *     DeviceIoControl; a rejected build never touches the driver.
 *   - Generation is supplied by the caller (agent-owned monotonic counter).
 */
#include "driver_policy_publisher.h"

#include <cstring>
#include <sstream>
#include <stdexcept>

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include "edr_ioctl.h"
#include "edr_policy_engine.h"

namespace edr {

namespace {

bool IsSpecialIpv4(const unsigned char ip[4]) {
    return EdrPolicyEngineIpv4IsSpecial(ip);
}

} // namespace

DriverPolicyBuildResult BuildDriverPolicy(const Config& cfg,
                                          uint32_t generation) {
    DriverPolicyBuildResult result;
    EDR_POLICY_V1* policy = nullptr;

    if (generation == 0) {
        result.error = "generation must be nonzero";
        return result;
    }
    if (cfg.driverBlockFilePaths.size() > EDR_MAX_FILE_RULES) {
        std::ostringstream os;
        os << "too many file rules: " << cfg.driverBlockFilePaths.size()
           << " (max " << EDR_MAX_FILE_RULES << ")";
        result.error = os.str();
        return result;
    }
    if (cfg.driverNetRules.size() > EDR_MAX_NET_RULES) {
        std::ostringstream os;
        os << "too many net rules: " << cfg.driverNetRules.size()
           << " (max " << EDR_MAX_NET_RULES << ")";
        result.error = os.str();
        return result;
    }

    result.bytes.resize(EDR_POLICY_SIZE, 0);
    policy = reinterpret_cast<EDR_POLICY_V1*>(result.bytes.data());

    policy->version = EDR_POLICY_VERSION;
    policy->struct_size = EDR_POLICY_SIZE;
    policy->generation = generation;
    policy->enable_mask = 0;
    if (cfg.driverEnableFile) {
        policy->enable_mask |= EDR_ENABLE_FILE;
    }
    if (cfg.driverEnableNet) {
        policy->enable_mask |= EDR_ENABLE_NET;
    }
    if (cfg.driverEnableBlock) {
        policy->enable_mask |= EDR_ENABLE_BLOCK;
    }
    if (cfg.driverEnableObjectHandle) {
        policy->enable_mask |= EDR_ENABLE_OBJECT_HANDLE;
    }
    /* Process/registry telemetry bits stay as the driver boot default
     * (PROCESS|REGISTRY); the publisher never toggles them. */
    policy->enable_mask |= EDR_ENABLE_PROCESS | EDR_ENABLE_REGISTRY;
    policy->file_rule_count = (unsigned int)cfg.driverBlockFilePaths.size();
    policy->net_rule_count = (unsigned int)cfg.driverNetRules.size();

    for (size_t i = 0; i < cfg.driverBlockFilePaths.size(); ++i) {
        const std::string& utf8 = cfg.driverBlockFilePaths[i];
        std::wstring wide;
        try {
            wide = Utf8ToWide(utf8);
        } catch (...) {
            result.error = "file rule is not valid UTF-8: " + utf8;
            return result;
        }
        if (wide.empty() || wide[0] != L'\\') {
            result.error = "file rule must be a normalized NT prefix: " + utf8;
            return result;
        }
        size_t bytes = wide.size() * sizeof(wchar_t);
        if (bytes < 2 || bytes > EDR_PATH_MAX_BYTES || (bytes & 1) != 0) {
            result.error = "file rule length out of range: " + utf8;
            return result;
        }
        if (wide.find(L'\0') != std::wstring::npos) {
            result.error = "file rule contains NUL: " + utf8;
            return result;
        }
        EDR_POLICY_FILE_RULE& fr = policy->file_rules[i];
        fr.length = (unsigned short)bytes;
        fr.reserved = 0;
        std::memcpy(fr.path, wide.data(), bytes);
    }

    for (size_t i = 0; i < cfg.driverNetRules.size(); ++i) {
        const Config::DriverNetRule& rule = cfg.driverNetRules[i];
        EDR_POLICY_NET_RULE& nr = policy->net_rules[i];
        std::string ip4 = rule.ip;
        /* Strict parse: inet_pton returns 1 for a valid dotted quad. */
        if (ip4.find(':') != std::string::npos) {
            result.error = "IPv6 is not supported by driver net rules: " + ip4;
            return result;
        }
        unsigned char octets[4] = {0, 0, 0, 0};
        if (inet_pton(AF_INET, ip4.c_str(), octets) != 1) {
            result.error = "malformed IPv4 address: " + ip4;
            return result;
        }
        if (IsSpecialIpv4(octets)) {
            result.error = "special IPv4 address is excluded: " + ip4;
            return result;
        }
        std::memcpy(nr.ip, octets, 4);
        nr.port = rule.port;
        nr.reserved = 0;
    }

    if (!EdrPolicyEngineValidate(policy)) {
        result.error = "internal policy validation failed";
        return result;
    }
    return result;
}

bool PushDriverPolicy(const std::vector<uint8_t>& policy, std::string& error) {
    HANDLE handle = CreateFileA(EDR_USERMODE_PATH,
                                GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        error = "cannot open \\\\.\\edrdrv: error " +
                std::to_string(GetLastError());
        return false;
    }
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(handle, IOCTL_EDR_SET_POLICY,
                              (LPVOID)policy.data(), (DWORD)policy.size(),
                              nullptr, 0, &bytes, nullptr);
    DWORD err = GetLastError();
    CloseHandle(handle);
    if (!ok) {
        error = "IOCTL_EDR_SET_POLICY failed: error " + std::to_string(err);
        return false;
    }
    return true;
}

bool PublishDriverPolicy(const Config& cfg, std::string& error) {
    static uint32_t s_generation = 1;
    DriverPolicyBuildResult built = BuildDriverPolicy(cfg, s_generation);
    if (!built.error.empty()) {
        error = "policy build rejected: " + built.error;
        return false;
    }
    if (!PushDriverPolicy(built.bytes, error)) {
        return false;
    }
    ++s_generation;
    return true;
}

} // namespace edr
