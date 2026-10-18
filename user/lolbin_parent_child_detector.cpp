/*
 * lolbin_parent_child_detector.cpp - See lolbin_parent_child_detector.h.
 *
 * Parent classes (office/adobe/browser/mail/chat/script_host) plus child
 * classes (powershell/cmd/script/lolbin/download) produce a base score.
 * Command-line boosters (encoded payload, hidden window, IEX/download
 * cradle, remote URL/UNC, user-writable child path) add to the score and
 * are recorded as flags. The event is stamped only when the score reaches
 * minScore.
 */
#include "lolbin_parent_child_detector.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

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

bool NameIs(const std::string& basename, const char* expected) {
    return basename == expected;
}

bool NameIn(const std::string& basename, std::initializer_list<const char*> names) {
    for (const char* name : names) {
        if (basename == name) return true;
    }
    return false;
}

const char* ClassifyParent(const std::string& basename) {
    if (NameIn(basename, {"winword.exe", "excel.exe", "powerpnt.exe",
                          "outlook.exe", "msaccess.exe", "visio.exe",
                          "onenote.exe", "onenotem.exe", "winproj.exe",
                          "mspub.exe", "eqnedt32.exe"}))
        return "office";
    if (NameIn(basename, {"acrord32.exe", "acrobat.exe", "rdrcef.exe",
                          "acrocefc.exe"}))
        return "adobe";
    if (NameIn(basename, {"chrome.exe", "msedge.exe", "msedgewebview2.exe",
                          "firefox.exe", "iexplore.exe", "brave.exe",
                          "opera.exe"}))
        return "browser";
    if (NameIn(basename, {"thunderbird.exe", "hxoutlook.exe"}))
        return "mail";
    if (NameIn(basename, {"teams.exe", "msteams.exe", "slack.exe",
                          "discord.exe", "skype.exe", "zoom.exe"}))
        return "chat";
    if (NameIn(basename, {"wscript.exe", "cscript.exe", "mshta.exe",
                          "wmic.exe"}))
        return "script_host";
    return "";
}

const char* ClassifyChild(const std::string& basename) {
    if (NameIn(basename, {"powershell.exe", "pwsh.exe"}))
        return "powershell";
    if (NameIs(basename, "cmd.exe"))
        return "cmd";
    if (NameIn(basename, {"wscript.exe", "cscript.exe", "mshta.exe",
                          "hh.exe"}))
        return "script";
    if (NameIn(basename, {"curl.exe", "wget.exe"}))
        return "download";
    if (NameIn(basename, {"rundll32.exe", "regsvr32.exe", "certutil.exe",
                          "bitsadmin.exe", "msbuild.exe", "installutil.exe",
                          "regasm.exe", "regsvcs.exe", "cmstp.exe",
                          "msiexec.exe", "ieexec.exe", "forfiles.exe",
                          "pcalua.exe", "presentationhost.exe", "jsc.exe",
                          "csc.exe", "ilasm.exe",
                          "syncappvpublishingserver.exe"}))
        return "lolbin";
    return "";
}

uint32_t BaseScore(const char* parentClass, const char* childClass) {
    const bool office = std::strcmp(parentClass, "office") == 0;
    const bool adobe = std::strcmp(parentClass, "adobe") == 0;
    const bool browser = std::strcmp(parentClass, "browser") == 0;
    const bool mail = std::strcmp(parentClass, "mail") == 0;
    const bool chat = std::strcmp(parentClass, "chat") == 0;
    const bool scriptHost = std::strcmp(parentClass, "script_host") == 0;

    if (std::strcmp(childClass, "powershell") == 0) {
        if (office) return 80;
        if (adobe) return 75;
        if (mail) return 70;
        if (browser) return 65;
        if (chat) return 60;
        if (scriptHost) return 55;
    }
    if (std::strcmp(childClass, "script") == 0) {
        if (office) return 75;
        if (adobe) return 75;
        if (mail) return 70;
        if (browser) return 60;
        if (chat) return 60;
        if (scriptHost) return 40;
    }
    if (std::strcmp(childClass, "lolbin") == 0) {
        if (office) return 70;
        if (adobe) return 65;
        if (mail) return 60;
        if (browser) return 55;
        if (chat) return 50;
        if (scriptHost) return 50;
    }
    if (std::strcmp(childClass, "cmd") == 0) {
        if (office) return 55;
        if (adobe) return 50;
        if (mail) return 50;
        if (browser) return 0; /* too noisy without boosters */
        if (chat) return 40;
        if (scriptHost) return 35;
    }
    if (std::strcmp(childClass, "download") == 0) {
        if (office || adobe) return 65;
        if (mail || browser) return 55;
        if (chat || scriptHost) return 45;
    }
    return 0;
}

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool IsUserWritablePath(const std::string& path) {
    return Contains(path, "\\temp\\") || Contains(path, "\\tmp\\") ||
           Contains(path, "\\appdata\\") || Contains(path, "\\programdata\\") ||
           Contains(path, "\\users\\public\\") ||
           Contains(path, "\\downloads\\") || Contains(path, "\\desktop\\");
}

} // namespace

LolbinScoreResult ScoreLolbinParentChild(const std::string& parentImage,
                                         const std::string& childImage,
                                         const std::string& commandLine) {
    LolbinScoreResult result;
    const std::string parent = BaseName(parentImage);
    const std::string child = BaseName(childImage);
    if (parent.empty() || child.empty()) return result;

    const char* parentClass = ClassifyParent(parent);
    const char* childClass = ClassifyChild(child);
    if (parentClass[0] == '\0' || childClass[0] == '\0') return result;

    result.parentClass = parentClass;
    result.childClass = childClass;
    result.score = BaseScore(parentClass, childClass);
    if (result.score == 0) return result;

    result.flags.push_back(std::string("LOLBIN_PARENT_") + parentClass);
    result.flags.push_back(std::string("LOLBIN_CHILD_") + childClass);

    const std::string cmd = LowerAscii(commandLine);
    if (Contains(cmd, "-enc") || Contains(cmd, "-encodedcommand") ||
        Contains(cmd, " -e ") || Contains(cmd, " -e\t")) {
        result.score += 15;
        result.flags.push_back("LOLBIN_ENCODED");
    }
    if (Contains(cmd, "-nop") || Contains(cmd, "-noprofile") ||
        Contains(cmd, "-w hidden") || Contains(cmd, "-windowstyle hidden") ||
        Contains(cmd, "-window hidden")) {
        result.score += 10;
        result.flags.push_back("LOLBIN_HIDDEN");
    }
    if (Contains(cmd, "iex") || Contains(cmd, "invoke-expression") ||
        Contains(cmd, "downloadstring") || Contains(cmd, "downloadfile") ||
        Contains(cmd, "frombase64string")) {
        result.score += 15;
        result.flags.push_back("LOLBIN_CRADLE");
    }
    if (Contains(cmd, "http://") || Contains(cmd, "https://") ||
        Contains(cmd, "\\\\")) {
        result.score += 10;
        result.flags.push_back("LOLBIN_REMOTE");
    }
    if (IsUserWritablePath(LowerAscii(childImage))) {
        result.score += 10;
        result.flags.push_back("LOLBIN_USER_WRITABLE");
    }

    if (result.score > 100) result.score = 100;
    return result;
}

const char* LolbinVerdict(uint32_t score) {
    if (score >= 70) return "MALICIOUS";
    if (score >= 50) return "SUSPICIOUS";
    return "";
}

LolbinParentChildDetector::LolbinParentChildDetector(bool enabled,
                                                     uint32_t minScore)
    : m_enabled(enabled),
      m_minScore(std::min(100u, std::max(1u, minScore))) {}

bool LolbinParentChildDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

void LolbinParentChildDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_PROCESS_START) return;

    const std::string parent = FieldValue(event, field::kParentImage);
    const std::string image = FieldValue(event, field::kImage);
    if (parent.empty() || image.empty()) return;

    const LolbinScoreResult scored = ScoreLolbinParentChild(
        parent, image, FieldValue(event, field::kCommandLine));
    if (scored.score < m_minScore || scored.parentClass.empty()) return;

    event.fields[field::kLolbinScore] = std::to_string(scored.score);
    event.fields[field::kLolbinParentClass] = scored.parentClass;
    event.fields[field::kLolbinChildClass] = scored.childClass;
    std::string flags;
    for (const std::string& flag : scored.flags) {
        if (!flags.empty()) flags += ",";
        flags += flag;
    }
    event.fields[field::kLolbinFlags] = flags;
    const char* verdict = LolbinVerdict(scored.score);
    if (verdict[0] != '\0')
        event.fields[field::kLolbinVerdict] = verdict;
}

} // namespace edr
