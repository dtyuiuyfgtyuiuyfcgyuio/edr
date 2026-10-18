/*
 * service_install_detector.cpp - See service_install_detector.h.
 */
#include "service_install_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace edr {
namespace {

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string ExtractImagePath(const std::string& lowerFullPath) {
    const size_t quoteStart = lowerFullPath.find('"');
    if (quoteStart != std::string::npos) {
        const size_t quoteEnd = lowerFullPath.find('"', quoteStart + 1);
        if (quoteEnd != std::string::npos) {
            return lowerFullPath.substr(quoteStart + 1,
                                        quoteEnd - quoteStart - 1);
        }
    }
    const size_t space = lowerFullPath.find_first_of(" \t");
    if (space != std::string::npos) return lowerFullPath.substr(0, space);
    return lowerFullPath;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

bool IsTransientDir(const std::string& lowerPath) {
    const char* kPaths[] = {
        "\\temp\\", "\\appdata\\", "\\downloads\\", "\\programdata\\",
        "\\public\\", "\\desktop\\", "$recycle.bin", "\\perflogs\\",
        "\\users\\", "\\windows\\tasks\\", "\\windows\\tracing\\"
    };
    for (const char* p : kPaths) {
        if (lowerPath.find(p) != std::string::npos) return true;
    }
    return false;
}

bool IsLolbinImage(const std::string& lowerPath) {
    const std::string& image = lowerPath;

    static const char* kLolbins[] = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "wscript.exe", "cscript.exe", "msbuild.exe",
        "installutil.exe", "schtasks.exe", "certutil.exe", "bitsadmin.exe",
        "curl.exe", "ftp.exe", "javaw.exe"
    };
    for (const char* lol : kLolbins) {
        /* Match either a bare executable name or a quoted/arg-suffixed image. */
        const size_t n = std::strlen(lol);
        if (image.size() < n) continue;
        const size_t pos = image.rfind(lol);
        if (pos == std::string::npos) continue;
        const size_t end = pos + n;
        if (end != image.size()) continue;
        if (pos > 0) {
            const char prev = image[pos - 1];
            if (prev != '\\' && prev != '/' && prev != '"' &&
                prev != ' ') continue;
        }
        return true;
    }
    return false;
}

} // namespace

ServiceInstallDetector::ServiceInstallDetector(bool enabled)
    : m_enabled(enabled) {}

void ServiceInstallDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    const std::string imagePath =
        FieldValue(event, field::kServiceImagePath);
    if (imagePath.empty()) return;
    const std::string lower = LowerAscii(imagePath);

    uint32_t score = 0;
    std::string signals;

    const auto AddSignal = [&signals](const bool cond, const char* name,
                                      uint32_t& acc, const uint32_t weight) {
        if (!cond) return;
        if (!signals.empty()) signals += ",";
        signals += name;
        acc += weight;
    };

    const std::string image = ExtractImagePath(lower);
    const bool transientDir = IsTransientDir(image);
    AddSignal(transientDir, "transient_dir", score, 30);

    /* Additive scoring contract (see the test suite): a LOLBin image
     * inside a transient dir scores both signals. */
    const bool lolbin = IsLolbinImage(image);
    AddSignal(lolbin, "lolbin_image", score, 25);

    const bool encoded =
        lower.find("-enc ") != std::string::npos ||
        lower.find("-encod") != std::string::npos ||
        lower.find("frombase64string") != std::string::npos ||
        lower.find("downloadstring") != std::string::npos ||
        lower.find("invoke-expression") != std::string::npos ||
        lower.find("iex ") != std::string::npos;
    AddSignal(encoded, "encoded_or_cradle", score, 25);

    const bool webPayload =
        lower.find("http://") != std::string::npos ||
        lower.find("https://") != std::string::npos ||
        lower.find("ftp://") != std::string::npos;
    AddSignal(webPayload, "web_payload", score, 15);

    const bool uncPath = lower.rfind("\\\\", 0) == 0;
    AddSignal(uncPath, "unc_path", score, 15);

    if (score == 0) return;

    const std::string startType =
        FieldValue(event, field::kServiceStartType);
    if (startType == "2" || startType == "auto") {
        if (!signals.empty()) signals += ",";
        signals += "auto_start";
        score += 5;
    }

    score = std::min(100u, score);
    event.fields[field::kSvcInstallScore] = std::to_string(score);
    event.fields[field::kSvcInstallSignals] = signals;
    event.fields[field::kSvcInstallService] =
        FieldValue(event, field::kServiceName);
    event.fields[field::kSvcInstallImagePath] = imagePath;
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kSvcInstallVerdict] = verdict;
    }
}

} // namespace edr
