/*
 * script_host_abuse_detector.cpp - See script_host_abuse_detector.h.
 */
#include "script_host_abuse_detector.h"

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

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

bool ContainsI(const std::string& haystack, const std::string& needle) {
    return LowerAscii(haystack).find(LowerAscii(needle)) != std::string::npos;
}

bool EndsWithI(const std::string& value, const char* suffix) {
    const std::string lower = LowerAscii(value);
    const size_t len = std::char_traits<char>::length(suffix);
    return lower.size() >= len &&
           lower.compare(lower.size() - len, len, suffix) == 0;
}

bool IsScriptExtension(const std::string& path) {
    return EndsWithI(path, ".js") || EndsWithI(path, ".jse") ||
           EndsWithI(path, ".vbs") || EndsWithI(path, ".vbe") ||
           EndsWithI(path, ".wsf") || EndsWithI(path, ".wsh") ||
           EndsWithI(path, ".hta") || EndsWithI(path, ".ps1") ||
           EndsWithI(path, ".sct") || EndsWithI(path, ".chm");
}

/* Transient, user-writable staging locations where a legitimately
 * installed script almost never lives. */
bool IsTransientLocation(const std::string& arg) {
    const std::string lower = LowerAscii(arg);
    static const char* kMarkers[] = {
        "\\temp\\", "\\tmp\\", "\\downloads\\", "\\public\\",
        "\\appdata\\local\\temp", "\\programdata\\temp", "\\recycle",
        "\\cache\\", "\\inbox\\", "\\desktop\\tmp"
    };
    for (const char* marker : kMarkers) {
        if (lower.find(marker) != std::string::npos) return true;
    }
    return false;
}

/* A single argument that looks like a long base64/hex blob is the usual
 * shape of encoded inline payloads (shortcut chaining, downloaders). */
bool LooksEncodedBlob(const std::string& arg) {
    if (arg.size() < 200) return false;
    size_t alphaNumeric = 0;
    for (char c : arg) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '+' ||
            c == '/' || c == '=' || c == '-') {
            ++alphaNumeric;
        }
    }
    return alphaNumeric * 100 >= arg.size() * 95;
}

/* True when the command line contains a script filename under a transient
 * user-writable staging directory. */
bool HasTransientScript(const std::string& line) {
    static const char* kExtensions[] = {".js", ".vbs", ".jse", ".vbe",
                                        ".wsf", ".hta"};
    for (const char* ext : kExtensions) {
        size_t pos = 0;
        while ((pos = line.find(ext, pos)) != std::string::npos) {
            size_t start = pos;
            while (start > 0 && line[start - 1] != ' ' &&
                   line[start - 1] != '"' && line[start - 1] != '\'')
                --start;
            if (IsTransientLocation(
                    line.substr(start, pos - start + strlen(ext)))) {
                return true;
            }
            pos += strlen(ext);
        }
    }
    return false;
}

/* True when the command line contains a very long base64-looking token. */
bool HasEncodedBlobArgument(const std::string& line) {
    size_t start = 0;
    while (start < line.size()) {
        while (start < line.size() &&
               (line[start] == ' ' || line[start] == '"' ||
                line[start] == '\''))
            ++start;
        size_t end = start;
        while (end < line.size() && line[end] != ' ' &&
               line[end] != '"' && line[end] != '\'')
            ++end;
        if (end - start >= 200 &&
            LooksEncodedBlob(line.substr(start, end - start)))
            return true;
        start = end + 1;
    }
    return false;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 50) return "SUSPICIOUS";
    return "";
}

} // namespace

ScriptHostAbuseSignal ClassifyScriptHostCommand(const std::string& image,
                                                const std::string& commandLine) {
    ScriptHostAbuseSignal result;
    const std::string base = BaseName(image);
    if (base != "wscript.exe" && base != "cscript.exe" &&
        base != "mshta.exe")
        return result;

    result.engine = base.substr(0, base.size() - 4); /* strip ".exe" */
    const std::string line = LowerAscii(commandLine);
    std::string signals;
    uint32_t score = 0;

    auto AddSignal = [&](const char* name, uint32_t weight) {
        if (!signals.empty()) signals += ",";
        signals += name;
        score = std::min(100u, score + weight);
    };

    /* Remote script payload: WSH / mshta fetching the script itself. */
    if (line.find("http://") != std::string::npos ||
        line.find("https://") != std::string::npos)
        AddSignal("remote_payload", 55);

    /* mshta inline scripting protocol (javascript: / vbscript:). */
    if (result.engine == "mshta" &&
        (line.find("javascript:") != std::string::npos ||
         line.find("vbscript:") != std::string::npos))
        AddSignal("inline_script", 40);

    /* UNC-hosted script payloads. */
    if (line.find("\\\\") != std::string::npos) {
        size_t unc = line.find("\\\\");
        const std::string rest = line.substr(unc);
        if (IsScriptExtension(rest.substr(0, rest.find_first_of(" \t\""))))
            AddSignal("remote_payload", 55);
    }

    /* Script staged in a transient, user-writable directory. */
    if (HasTransientScript(line)) AddSignal("transient_location", 25);

    /* WSH pointed at an executable payload (script-host smuggling). */
    {
        std::string trimmed = line;
        while (!trimmed.empty() &&
               (trimmed.back() == '"' || trimmed.back() == '\'' ||
                trimmed.back() == ' '))
            trimmed.pop_back();
        if (result.engine != "mshta" &&
            (EndsWithI(trimmed, ".exe") || EndsWithI(trimmed, ".dll") ||
             EndsWithI(trimmed, ".bin") || EndsWithI(trimmed, ".com")))
            AddSignal("proxy_payload", 20);
    }

    /* Long encoded blob argument (common for obfuscated launchers). */
    if (HasEncodedBlobArgument(line)) AddSignal("encoded_payload", 30);

    if (score == 0) return result;
    result.suspicious = true;
    result.score = score;
    result.signals = signals;
    result.verdict = Verdict(score);
    return result;
}

bool ScriptHostAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

ScriptHostAbuseDetector::ScriptHostAbuseDetector(bool enabled)
    : m_enabled(enabled) {}

void ScriptHostAbuseDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (event.type != EDR_EVT_PROCESS_START) return;

    const std::string image = FieldValue(event, field::kImage);
    const std::string commandLine = FieldValue(event, field::kCommandLine);
    ScriptHostAbuseSignal signal =
        ClassifyScriptHostCommand(image, commandLine);
    if (!signal.suspicious) return;

    event.fields[field::kScriptHostScore] = std::to_string(signal.score);
    event.fields[field::kScriptHostSignals] = signal.signals;
    event.fields[field::kScriptHostEngine] = signal.engine;
    if (!signal.verdict.empty())
        event.fields[field::kScriptHostVerdict] = signal.verdict;
}

} // namespace edr
