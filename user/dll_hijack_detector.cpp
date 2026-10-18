/*
 * dll_hijack_detector.cpp - See dll_hijack_detector.h.
 */
#include "dll_hijack_detector.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_set>

namespace edr {
namespace {

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return slash == std::string::npos ? value : value.substr(slash + 1);
}

bool IsKnownHijackTarget(const std::string& lowerName) {
    static const std::unordered_set<std::string> kTargets = {
        "amsi.dll",
        "apphelp.dll",
        "bcrypt.dll",
        "comctl32.dll",
        "crypt32.dll",
        "cryptbase.dll",
        "cscapi.dll",
        "dbghelp.dll",
        "dwmapi.dll",
        "d3d9.dll",
        "dxgi.dll",
        "linkinfo.dll",
        "mpr.dll",
        "mswsock.dll",
        "ncrypt.dll",
        "netapi32.dll",
        "ntmarta.dll",
        "ntshrui.dll",
        "ole32.dll",
        "propsys.dll",
        "secur32.dll",
        "shell32.dll",
        "srvcli.dll",
        "sspicli.dll",
        "urlmon.dll",
        "userenv.dll",
        "usp10.dll",
        "vaultcli.dll",
        "version.dll",
        "wevtapi.dll",
        "winhttp.dll",
        "wininet.dll",
        "winmm.dll",
        "wkscli.dll",
        "wlanapi.dll",
        "wldap32.dll",
        "wtsapi32.dll",
    };
    return kTargets.find(lowerName) != kTargets.end();
}

} // namespace

DllHijackSignal ClassifyDllHijackPath(const std::string& imagePath) {
    DllHijackSignal signal;
    const std::string lowerPath = LowerAscii(imagePath);
    const std::string lowerName = BaseName(lowerPath);
    if (lowerName.size() < 5 ||
        lowerName.compare(lowerName.size() - 4, 4, ".dll") != 0 ||
        !IsKnownHijackTarget(lowerName)) {
        return signal;
    }

    std::string location;
    uint32_t score = 0;
    if (lowerPath.find("\\temp\\") != std::string::npos ||
        lowerPath.find("\\windows\\temp\\") != std::string::npos ||
        lowerPath.find("\\appdata\\local\\temp\\") != std::string::npos) {
        location = "temp";
        score = 82;
    } else if (lowerPath.find("\\downloads\\") != std::string::npos) {
        location = "download";
        score = 76;
    } else if (lowerPath.find("\\programdata\\") != std::string::npos) {
        location = "programdata";
        score = 72;
    } else if (lowerPath.find("\\users\\public\\") != std::string::npos) {
        location = "public";
        score = 70;
    } else if (lowerPath.find("\\appdata\\roaming\\") != std::string::npos ||
               lowerPath.find("\\appdata\\local\\") != std::string::npos ||
               lowerPath.find("\\desktop\\") != std::string::npos ||
               lowerPath.find("\\documents\\") != std::string::npos) {
        location = "profile";
        score = 68;
    }

    if (location.empty()) {
        return signal;
    }

    signal.suspicious = true;
    signal.name = lowerName;
    signal.location = location;
    signal.score = score;
    signal.verdict = "dll_search_order_hijack";
    return signal;
}

DllHijackDetector::DllHijackDetector(bool enabled) : m_enabled(enabled) {}

bool DllHijackDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_IMAGE_LOAD;
}

void DllHijackDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_IMAGE_LOAD) {
        return;
    }

    auto loadType = event.fields.find(field::kImageLoadType);
    if (loadType != event.fields.end() && loadType->second == "unload") {
        return;
    }

    const auto image = event.fields.find(field::kImageLoaded);
    if (image == event.fields.end() || image->second.empty()) {
        return;
    }

    const DllHijackSignal signal = ClassifyDllHijackPath(image->second);
    if (!signal.suspicious) {
        return;
    }

    event.fields[field::kDllHijackScore] = std::to_string(signal.score);
    event.fields[field::kDllHijackPath] = image->second;
    event.fields[field::kDllHijackName] = signal.name;
    event.fields[field::kDllHijackLocation] = signal.location;
    event.fields[field::kDllHijackVerdict] = signal.verdict;
}

} // namespace edr
