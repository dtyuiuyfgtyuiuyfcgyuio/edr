/*
 * wsl_abuse_detector.cpp - Windows Subsystem for Linux abuse detector (T1202).
 *
 * House contract: PROCESS_START takes kCommandLine; POWERSHELL_SCRIPT takes
 * kScriptBlockText (never kCommandLine). Scores >= 55 suspicious,
 * >= 75 malicious; below min_score stays silent.
 */
#include "wsl_abuse_detector.h"
#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {
namespace {
bool Contains(const std::string& v,const char* n){return v.find(n)!=std::string::npos;}
std::string ToLowerAscii(const std::string& t){
    std::string o=t; std::transform(o.begin(),o.end(),o.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));}); return o;
}
std::string BaseName(const std::string& v){
    size_t p=v.find_last_of("\\/");
    return p==std::string::npos?v:v.substr(p+1);
}
bool IsWslImage(const std::string& imageLower){
    const std::string b=BaseName(imageLower);
    return b=="wsl.exe"||b=="bash.exe";
}
bool MentionsWindowsInterpreter(const std::string& l){
    return Contains(l,"cmd.exe")||Contains(l,"cmd /")||Contains(l,"powershell")||Contains(l,"pwsh")||
           Contains(l,"wscript")||Contains(l,"cscript")||Contains(l,"mshta")||Contains(l,"rundll32")||
           Contains(l,"regsvr32")||Contains(l,"msiexec");
}
} // namespace

WslAbuseDetector::WslAbuseDetector(bool e,uint32_t ms,uint32_t dw,size_t cap)
    :m_enabled(e),m_minScore(ms),m_dedupWindow100ns(static_cast<uint64_t>(dw)*kFiletimeTicksPerSecond),m_capacity(cap){}

bool WslAbuseDetector::Inspects(uint16_t t){
    return t==EDR_EVT_PROCESS_START||t==EDR_EVT_POWERSHELL_SCRIPT;
}

bool WslAbuseDetector::ClassifyPayload(const std::string& lower, const std::string& imageLower, Finding* out){
    const bool wslImage = IsWslImage(imageLower);
    const bool wslToken = Contains(lower,"wsl.exe")||Contains(lower,"wsl ")||Contains(lower,"\\wsl$\\")||wslImage||
                          Contains(lower,"bash.exe -c")||Contains(lower,"bash -c");
    if(!wslToken) return false;

    // Windows-side staging into the WSL filesystem (any image).
    if(Contains(lower,"\\\\wsl$\\")){
        *out=Finding{75,"windows-side wsl filesystem staging"};
        return true;
    }
    // Distribution image staging / disk attach.
    if(Contains(lower,"--import")||Contains(lower,"--export")||Contains(lower,"--mount")){
        *out=Finding{85,"wsl distribution image staging/mount"};
        return true;
    }
    // Cross-boundary Windows execution from inside WSL.
    if(Contains(lower,"--exec")||Contains(lower," -e ")){
        if(MentionsWindowsInterpreter(lower)){
            *out=Finding{90,"wsl cross-boundary windows exec"};
        } else {
            *out=Finding{80,"wsl --exec payload"};
        }
        return true;
    }
    // Non-interactive shells.
    if(Contains(lower,"bash -c")||Contains(lower,"bash.exe -c")){
        *out=Finding{85,"bash non-interactive command"};
        return true;
    }
    // Windows filesystem touched from inside WSL.
    if(Contains(lower,"/mnt/c")||Contains(lower,"/mnt/d")||Contains(lower,"/mnt/e")){
        *out=Finding{80,"wsl windows filesystem access"};
        return true;
    }
    // Implicit exec: wsl [-d distro] [-u user] <command>.
    if(wslImage||Contains(lower,"wsl ")){
        if(Contains(lower," -d ")||Contains(lower,"--distribution")||
           Contains(lower," -u ")||Contains(lower,"--user")){
            *out=Finding{75,"wsl implicit distro exec"};
            return true;
        }
    }
    // Administrative / interactive surface stays silent: bare wsl, --list,
    // --status, --help, --version, --shutdown, --terminate, --update.
    return false;
}

void WslAbuseDetector::Stamp(Event& e,const Finding& f,const std::string& k){
    e.fields[field::kWslAbuseScore]=std::to_string(f.score);
    e.fields[field::kWslAbuseVerdict]= f.score>=75?"malicious":"suspicious";
    e.fields[field::kWslAbuseSignals]=f.signal;
    e.fields[field::kWslAbuseText]=k;
}

void WslAbuseDetector::Enrich(Event& event){
    if(!m_enabled) return;
    if(!Inspects(event.type)) return;
    std::string image;
    auto imgIt=event.fields.find(field::kImage);
    if(imgIt!=event.fields.end()) image=imgIt->second;
    std::string text;
    auto cmdIt=event.fields.find(field::kCommandLine);
    if(cmdIt!=event.fields.end()) text=cmdIt->second;
    if(text.empty()&&event.type==EDR_EVT_POWERSHELL_SCRIPT){
        auto scIt=event.fields.find(field::kScriptBlockText);
        if(scIt!=event.fields.end()) text=scIt->second;
    }
    if(text.empty()&&!IsWslImage(ToLowerAscii(image))) return;
    std::string combined=image+" "+text;
    std::string lower=ToLowerAscii(combined);
    Finding f;
    if(!ClassifyPayload(lower,ToLowerAscii(image),&f)) return;
    if(f.score<m_minScore) return;
    std::string key=lower.substr(0,160);
    uint64_t now=event.ts100ns;
    auto it=m_state.find(key);
    if(it!=m_state.end()){
        if(m_dedupWindow100ns!=0 && now>=it->second && now-it->second<m_dedupWindow100ns) return;
        it->second=now;
    } else {
        if(m_capacity>0 && m_state.size()>=m_capacity){ m_state.clear(); std::fprintf(stderr,"[edr-wsl] state capacity %zu reached; dedup reset\n",m_capacity); }
        m_state.emplace(key,now);
    }
    Stamp(event,f,key);
}
} // namespace edr
