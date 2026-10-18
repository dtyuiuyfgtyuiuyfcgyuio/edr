#include "amsi_enricher.h"

#include <cstdio>
#include <limits>
#include <vector>

#include "edr_event.h"

namespace edr {

namespace {

constexpr uint32_t kAmsiResultClean = 0;
constexpr uint32_t kAmsiResultBlockedByAdminStart = 0x4000;
constexpr uint32_t kAmsiResultBlockedByAdminEnd = 0x4fff;
constexpr uint32_t kAmsiResultDetected = 0x8000;

std::string HresultString(HRESULT result) {
    char value[11] = {};
    std::snprintf(value, sizeof(value), "0x%08lx",
                  static_cast<unsigned long>(result));
    return value;
}

bool IsContinuation(unsigned char value) {
    return (value & 0xc0) == 0x80;
}

bool StrictBoundedUtf8ToUtf16(const std::string& input, size_t maxChars,
                              std::wstring& output, bool& truncated) {
    output.clear();
    truncated = false;
    bool accepting = true;
    for (size_t i = 0; i < input.size();) {
        const unsigned char first = static_cast<unsigned char>(input[i]);
        uint32_t scalar = 0;
        size_t width = 0;
        if (first <= 0x7f) {
            scalar = first;
            width = 1;
        } else if (first >= 0xc2 && first <= 0xdf) {
            scalar = first & 0x1f;
            width = 2;
        } else if (first >= 0xe0 && first <= 0xef) {
            scalar = first & 0x0f;
            width = 3;
        } else if (first >= 0xf0 && first <= 0xf4) {
            scalar = first & 0x07;
            width = 4;
        } else {
            return false;
        }
        if (i + width > input.size()) return false;
        for (size_t offset = 1; offset < width; ++offset) {
            const unsigned char next = static_cast<unsigned char>(input[i + offset]);
            if (!IsContinuation(next)) return false;
            scalar = (scalar << 6) | (next & 0x3f);
        }
        if ((width == 3 && scalar < 0x800) ||
            (width == 4 && scalar < 0x10000) ||
            (scalar >= 0xd800 && scalar <= 0xdfff) || scalar > 0x10ffff) {
            return false;
        }
        size_t requiredUnits = scalar <= 0xffff ? 1 : 2;
        if (accepting && output.size() + requiredUnits <= maxChars) {
            if (requiredUnits == 1) {
                output.push_back(static_cast<wchar_t>(scalar));
            } else {
                scalar -= 0x10000;
                output.push_back(static_cast<wchar_t>(0xd800 + (scalar >> 10)));
                output.push_back(static_cast<wchar_t>(0xdc00 + (scalar & 0x3ff)));
            }
        } else {
            truncated = true;
            accepting = false;
        }
        i += width;
    }
    return true;
}

std::string LowerAscii(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + ('a' - 'A'));
    }
    return value;
}

} // namespace

AmsiEnricher::AmsiEnricher(bool enabled, uint32_t maxContentChars,
                           IAmsiPlatform& platform)
    : m_enabled(enabled), m_maxContentChars(maxContentChars),
      m_platform(platform) {
    if (m_enabled) {
        m_initResult = m_platform.Initialize(L"EDR Agent", &m_context);
        if (SUCCEEDED(m_initResult) && m_context == nullptr) m_initResult = E_FAIL;
        if (FAILED(m_initResult)) m_context = nullptr;
    }
}

AmsiEnricher::~AmsiEnricher() {
    Shutdown();
}

bool AmsiEnricher::SelectSource(const Event& event, const std::string*& content,
                                const char*& source) const {
    if (!m_enabled) return false;
    if (event.type == EDR_EVT_PROCESS_START) {
        const auto image = event.fields.find(field::kImage);
        const auto commandLine = event.fields.find(field::kCommandLine);
        if (image == event.fields.end() || commandLine == event.fields.end()) return false;
        const size_t slash = image->second.find_last_of("\\/");
        const std::string basename = LowerAscii(image->second.substr(
            slash == std::string::npos ? 0 : slash + 1));
        if (basename != "powershell.exe" && basename != "pwsh.exe" &&
            basename != "wscript.exe" && basename != "cscript.exe" &&
            basename != "mshta.exe") {
            return false;
        }
        content = &commandLine->second;
        source = "command_line";
        return true;
    }
    if (event.type == EDR_EVT_WMI_EVENT) {
        const auto id = event.fields.find(field::kWmiEventId);
        const auto query = event.fields.find(field::kWmiQuery);
        if (id == event.fields.end() || id->second != "5860" ||
            query == event.fields.end()) {
            return false;
        }
        content = &query->second;
        source = "wmi_query";
        return true;
    }
    return false;
}

bool AmsiEnricher::IsEligible(const Event& event) const {
    const std::string* content = nullptr;
    const char* source = nullptr;
    return SelectSource(event, content, source);
}

void AmsiEnricher::EnrichEligible(Event& event) {
    const std::string* content = nullptr;
    const char* source = nullptr;
    if (!SelectSource(event, content, source)) return;

    event.fields[field::kAmsiSource] = source;
    event.fields[field::kAmsiTruncated] = "false";
    event.fields.erase(field::kAmsiResult);
    event.fields.erase(field::kAmsiErrorHresult);

    if (FAILED(m_initResult)) {
        event.fields[field::kAmsiVerdict] = "error";
        event.fields[field::kAmsiErrorHresult] = HresultString(m_initResult);
        return;
    }

    std::wstring wide;
    bool truncated = false;
    if (!StrictBoundedUtf8ToUtf16(*content, m_maxContentChars, wide, truncated)) {
        event.fields[field::kAmsiVerdict] = "error";
        event.fields[field::kAmsiErrorHresult] = HresultString(E_INVALIDARG);
        return;
    }
    event.fields[field::kAmsiTruncated] = truncated ? "true" : "false";
    if (wide.size() > std::numeric_limits<uint32_t>::max() / sizeof(wchar_t)) {
        event.fields[field::kAmsiVerdict] = "error";
        event.fields[field::kAmsiErrorHresult] = HresultString(E_INVALIDARG);
        return;
    }

    uint32_t result = 0;
    const HRESULT scanResult = m_platform.ScanBuffer(
        m_context, wide.data(), static_cast<uint32_t>(wide.size() * sizeof(wchar_t)),
        L"EDR telemetry", &result);
    if (FAILED(scanResult)) {
        event.fields[field::kAmsiVerdict] = "error";
        event.fields[field::kAmsiErrorHresult] = HresultString(scanResult);
        return;
    }
    event.fields[field::kAmsiResult] = std::to_string(result);
    if (result == kAmsiResultClean) {
        event.fields[field::kAmsiVerdict] = "clean";
    } else if (result >= kAmsiResultBlockedByAdminStart &&
               result <= kAmsiResultBlockedByAdminEnd) {
        event.fields[field::kAmsiVerdict] = "blocked_by_admin";
    } else if (result >= kAmsiResultDetected) {
        event.fields[field::kAmsiVerdict] = "detected";
    } else {
        event.fields[field::kAmsiVerdict] = "not_detected";
    }
}

void AmsiEnricher::Shutdown() {
    if (m_context != nullptr) {
        m_platform.Uninitialize(m_context);
        m_context = nullptr;
    }
}

bool AmsiEnricher::InitializationFailed() const {
    return m_enabled && FAILED(m_initResult);
}

} // namespace edr
