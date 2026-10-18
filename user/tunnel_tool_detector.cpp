/*
 * tunnel_tool_detector.cpp - See tunnel_tool_detector.h.
 */
#include "tunnel_tool_detector.h"

#include <algorithm>
#include <cctype>

namespace edr {
namespace {

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

bool HasFlag(const std::string& line, const char* flag) {
    /* Match "-R", "-L", "-D" as standalone flags: preceded by start or
     * whitespace, not part of a longer word. */
    size_t pos = 0;
    const size_t len = std::char_traits<char>::length(flag);
    while ((pos = line.find(flag, pos)) != std::string::npos) {
        const bool startOk = pos == 0 || line[pos - 1] == ' ' ||
                             line[pos - 1] == '"' || line[pos - 1] == '\'';
        const bool endOk = pos + len >= line.size() ||
                           line[pos + len] == ' ' ||
                           line[pos + len] == ':' ||
                           line[pos + len] == '=' ||
                           isdigit(static_cast<unsigned char>(
                               line[pos + len]));
        if (startOk && endOk) return true;
        pos += len;
    }
    return false;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 50) return "SUSPICIOUS";
    return "";
}

} // namespace

TunnelToolSignal ClassifyTunnelCommand(const std::string& image,
                                       const std::string& commandLine) {
    TunnelToolSignal result;
    const std::string base = BaseName(image);
    const std::string line = LowerAscii(commandLine);
    std::string signals;
    std::string tools;
    uint32_t score = 0;

    auto AddTool = [&](const std::string& name) {
        if (tools.find(name) == std::string::npos) {
            if (!tools.empty()) tools += ",";
            tools += name;
        }
    };
    auto AddSignal = [&](const char* name, uint32_t weight) {
        if (!signals.empty()) signals += ",";
        signals += name;
        score = std::min(100u, score + weight);
    };

    /* Built-in port proxy: netsh interface portproxy add ... (T1090.001) */
    if (base == "netsh.exe" &&
        line.find("portproxy") != std::string::npos &&
        line.find("add") != std::string::npos) {
        AddTool("netsh_portproxy");
        AddSignal("portproxy_rule", 80);
        result.suspicious = true;
        result.score = score;
        result.signals = signals;
        result.tools = tools;
        result.verdict = Verdict(score);
        return result;
    }

    /* ssh / plink with reverse (-R), local (-L) or dynamic (-D) forwards.
     * The command line is lowercased above, so the flags are matched in
     * lowercase too (uppercase literals here made the branch dead code). */
    if (base == "ssh.exe" || base == "plink.exe") {
        if (HasFlag(line, "-r") || HasFlag(line, "-l") ||
            HasFlag(line, "-d")) {
            AddTool(base.substr(0, base.size() - 4));
            AddSignal("port_forward", 70);
            /* Tunnelling to a jump host with agent forwarding strengthens
             * the signal slightly. */
            if (HasFlag(line, "-n") || HasFlag(line, "-f"))
                AddSignal("background_forward", 10);
        }
    }

    /* Netcat-family listeners with relay/exec chaining */
    if (base == "ncat.exe" || base == "nc.exe" || base == "nc64.exe" ||
        base == "netcat.exe") {
        const bool listener = line.find("-l") != std::string::npos ||
                              line.find("--listen") != std::string::npos;
        const bool relay = line.find("--sh-exec") != std::string::npos ||
                           line.find("-e ") != std::string::npos ||
                           line.find("-c ") != std::string::npos ||
                           line.find("cmd.exe") != std::string::npos ||
                           line.find("powershell") != std::string::npos;
        if (listener && relay) {
            AddTool("netcat");
            AddSignal("listener_relay", 65);
        } else if (listener) {
            AddTool("netcat");
            AddSignal("raw_listener", 30);
        }
    }

    /* socat listeners */
    if (base == "socat.exe") {
        if (line.find("tcp-listen") != std::string::npos ||
            line.find("tcp4-listen") != std::string::npos) {
            AddTool("socat");
            AddSignal("socat_listener", 40);
            if (line.find("exec") != std::string::npos ||
                line.find("system") != std::string::npos)
                AddSignal("listener_relay", 25);
        }
    }

    /* Packaged tunnel clients */
    static const char* kTunnelClients[] = {
        "ngrok.exe", "chisel.exe", "frpc.exe", "frps.exe",
        "stowaway.exe", "ligolo.exe", "rinetd.exe", "iodine.exe",
        "dnscat2.exe", "ptunnel.exe"
    };
    for (const char* client : kTunnelClients) {
        if (base == client) {
            AddTool(base.substr(0, base.size() - 4));
            /* Named tunnel clients are almost never legitimate on a
             * corporate endpoint. */
            AddSignal("tunnel_client", 60);
            break;
        }
    }

    if (score == 0) return result;
    result.suspicious = true;
    result.score = score;
    result.signals = signals;
    result.tools = tools;
    result.verdict = Verdict(score);
    return result;
}

bool TunnelToolDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

TunnelToolDetector::TunnelToolDetector(bool enabled) : m_enabled(enabled) {}

void TunnelToolDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (event.type != EDR_EVT_PROCESS_START) return;

    const std::string image = event.fields.count(field::kImage)
                                  ? event.fields.at(field::kImage)
                                  : std::string();
    const std::string commandLine =
        event.fields.count(field::kCommandLine)
            ? event.fields.at(field::kCommandLine)
            : std::string();
    TunnelToolSignal signal = ClassifyTunnelCommand(image, commandLine);
    if (!signal.suspicious) return;

    event.fields[field::kTunnelScore] = std::to_string(signal.score);
    event.fields[field::kTunnelSignals] = signal.signals;
    event.fields[field::kTunnelTools] = signal.tools;
    if (!signal.verdict.empty())
        event.fields[field::kTunnelVerdict] = signal.verdict;
}

} // namespace edr
