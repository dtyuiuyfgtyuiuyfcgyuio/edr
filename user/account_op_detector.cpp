/*
 * account_op_detector.cpp - See account_op_detector.h.
 */
#include "account_op_detector.h"

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

bool ContainsI(const std::string& haystack, const char* needle) {
    return LowerAscii(haystack).find(LowerAscii(needle)) != std::string::npos;
}

/* House verdict band (CLAUDE.md, "security log detector family"
 * convention): >= 75 MALICIOUS, >= 55 SUSPICIOUS, below 55 empty. The
 * 50-54 band is a dead band - the house score regex is
 * ^(?:5[5-9]|[6-9][0-9]|100)$ and no rule consumes 50-54 - so sub-55
 * findings must not be stamped onto events at all. */
std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

} // namespace

AccountOpSignal ClassifyAccountOperation(const std::string& image,
                                         const std::string& commandLine) {
    AccountOpSignal result;
    const std::string base = BaseName(image);
    if (base != "net.exe" && base != "net1.exe" && base != "dsadd.exe")
        return result;

    const std::string line = LowerAscii(commandLine);
    std::string signals;
    uint32_t score = 0;

    auto AddSignal = [&](const char* name, const char* command,
                         uint32_t weight) {
        if (!signals.empty()) signals += ",";
        signals += name;
        score = std::min(100u, score + weight);
        result.command = command;
    };

    if (base == "dsadd.exe") {
        /* dsadd user "CN=backdoor,CN=Users,DC=corp,DC=local" ... */
        if (line.find(" user ") != std::string::npos ||
            line.find("\"user") != std::string::npos)
            AddSignal("account_create", "dsadd_user", 55);
        else if (line.find(" group ") != std::string::npos)
            AddSignal("group_add", "dsadd_group", 55);
    } else {
        if (line.find("accounts ") != std::string::npos) {
            /* net accounts /lockoutthreshold:never /minpwlen:0 ... */
            AddSignal("account_policy_change", "net_accounts", 35);
        } else if (line.find("localgroup ") != std::string::npos &&
                   line.find("/add") != std::string::npos) {
            if (ContainsI(line, "administrators"))
                AddSignal("admin_group_add", "net_localgroup_add", 80);
            else
                AddSignal("local_group_add", "net_localgroup_add", 60);
        } else if (line.find(" group ") != std::string::npos &&
                   line.find("/add") != std::string::npos) {
            /* net group "Domain Admins" backdoor /add */
            AddSignal("domain_group_add", "net_group_add", 75);
        } else if (line.find(" user ") != std::string::npos &&
                   line.find("/delete") != std::string::npos) {
            /* net user <name> /delete - account removal (T1531).
             * The space-delimited " user " needle keeps connection
             * teardown (net use \\srv\ipc$ /delete) and group deletion
             * (net localgroup <group> <member> /delete) out. */
            AddSignal("account_delete", "net_user_delete", 70);
        } else if (line.find("user ") != std::string::npos) {
            if (line.find("/add") != std::string::npos) {
                if (line.find("/domain") != std::string::npos)
                    AddSignal("domain_account_create", "net_user_add_domain",
                              70);
                else
                    AddSignal("account_create", "net_user_add", 55);
            } else if (line.find("/active:y") != std::string::npos ||
                       line.find("/active: yes") != std::string::npos) {
                AddSignal("account_enable", "net_user_active", 50);
            } else if (line.find("/active:no") != std::string::npos ||
                       line.find("/active: no") != std::string::npos) {
                /* net user <name> /active:no - disable account (T1531) */
                AddSignal("account_disable", "net_user_active", 60);
            } else {
                /* net user <name> <new-password> - password reset */
                AddSignal("password_change", "net_user_password", 40);
            }
        }
    }

    if (score == 0) return result;
    result.suspicious = true;
    result.score = score;
    result.signals = signals;
    result.verdict = Verdict(score);
    return result;
}

bool AccountOpDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

AccountOpDetector::AccountOpDetector(bool enabled) : m_enabled(enabled) {}

void AccountOpDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (event.type != EDR_EVT_PROCESS_START) return;

    const std::string image = event.fields.count(field::kImage)
                                  ? event.fields.at(field::kImage)
                                  : std::string();
    const std::string commandLine =
        event.fields.count(field::kCommandLine)
            ? event.fields.at(field::kCommandLine)
            : std::string();
    AccountOpSignal signal = ClassifyAccountOperation(image, commandLine);
    if (!signal.suspicious) return;
    /* Band gate on the FINAL aggregated score (equivalent early exit of
     * `if (Verdict(final).empty()) return;` - signal.verdict was computed
     * from the fully accumulated score inside ClassifyAccountOperation):
     * sub-55 signals (account_policy_change 35, password_change 40,
     * account_enable 50) stamp NOTHING - no score/signals/commands/
     * verdict - because no rule consumes the 50-54 dead band, so a
     * stamped sub-55 score would be a dead letter. This is not a
     * per-signal gate: any accumulated combination reaching 55+ stamps
     * and scores as usual. */
    if (signal.verdict.empty()) return;

    event.fields[field::kAccountOpScore] = std::to_string(signal.score);
    event.fields[field::kAccountOpSignals] = signal.signals;
    event.fields[field::kAccountOpCommands] = signal.command;
    if (!signal.verdict.empty())
        event.fields[field::kAccountOpVerdict] = signal.verdict;
}

} // namespace edr
