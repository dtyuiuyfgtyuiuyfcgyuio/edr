/*
 * winlogon_hijack_detector.cpp - Winlogon persistence detector (T1547.004).
 */
#include "winlogon_hijack_detector.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace edr {
namespace {
bool Contains(const std::string& v, const char* n){ return v.find(n)!=std::string::npos; }
std::string ToLowerAscii(const std::string& t){
    std::string o=t; std::transform(o.begin(),o.end(),o.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));}); return o;
}
bool MentionsWritableDir(const std::string& l){
    return Contains(l,"\\temp\\")||Contains(l,"\\tmp\\")||Contains(l,"appdata")||Contains(l,"programdata")||Contains(l,"\\users\\public")||Contains(l,"\\public\\")||Contains(l,"\\downloads\\")||Contains(l,"%temp%")||Contains(l,"%appdata%")||Contains(l,"c:\\temp")||Contains(l,"c:\\users");
}
bool MentionsInterpreter(const std::string& l){
    return Contains(l,"cmd.exe")||Contains(l,"powershell")||Contains(l,"pwsh")||Contains(l,"wscript")||Contains(l,"cscript")||Contains(l,"rundll32")||Contains(l,"mshta")||Contains(l,"regsvr32");
}
bool IsSystem32Path(const std::string& l){
    return Contains(l,"\\windows\\system32\\")||Contains(l,"\\windows\\syswow64\\")||Contains(l,"system32\\");
}
bool IsReadOnlyQuery(const std::string& l){
    return Contains(l,"reg query")||Contains(l,"get-itemproperty");
}
bool IsTrustedWriter(const std::string& l){
    return Contains(l,"msiexec")||Contains(l,"trustedinstaller");
}
bool IsWinlogonKey(const std::string& l){
    if (l.find("winlogon")==std::string::npos) return false;
    if (l.find("software\\microsoft\\windows nt\\currentversion\\winlogon")==std::string::npos &&
        l.find("software/microsoft/windows nt/currentversion/winlogon")==std::string::npos) return false;
    return true;
}
bool IsWinlogonValue(const std::string& l){
    return Contains(l,"userinit")||Contains(l,"shell")||Contains(l,"notify")||Contains(l,"gina")||Contains(l,"system")||Contains(l,"taskman")||Contains(l,"vmApplet");
}
} // namespace

WinlogonHijackDetector::WinlogonHijackDetector(bool e,uint32_t ms,uint32_t dw,size_t cap)
    :m_enabled(e),m_minScore(ms),m_dedupWindow100ns(static_cast<uint64_t>(dw)*kFiletimeTicksPerSecond),m_capacity(cap){}

bool WinlogonHijackDetector::Inspects(uint16_t t){
    return t==EDR_EVT_REG_WRITE||t==EDR_EVT_PROCESS_START||t==EDR_EVT_POWERSHELL_SCRIPT;
}
bool WinlogonHijackDetector::ClassifyPayload(const std::string& data, Finding* out){
    if(data.empty()) return false;
    std::string l=ToLowerAscii(data);
    // defaults: userinit.exe, explorer.exe in system32 are benign
    if ((Contains(l,"userinit.exe")||Contains(l,"explorer.exe")) && IsSystem32Path(l) && !MentionsWritableDir(l)) return false;
    if (MentionsInterpreter(l)||MentionsWritableDir(l)){
        *out=Finding{90,"Winlogon hijack to writable/interpreter"};
        return true;
    }
    if (!IsSystem32Path(l)){
        *out=Finding{85,"Winlogon hijack outside system32"};
        return true;
    }
    return false;
}
void WinlogonHijackDetector::Stamp(Event& e,const Finding& f,const std::string& k){
    e.fields[field::kWinlogonHijackScore]=std::to_string(f.score);
    e.fields[field::kWinlogonHijackVerdict]= f.score>=75?"malicious":"suspicious";
    e.fields[field::kWinlogonHijackSignals]=f.signal;
    e.fields[field::kWinlogonHijackText]=k;
}
void WinlogonHijackDetector::Enrich(Event& event){
    if(!m_enabled) return;
    if(!Inspects(event.type)) return;
    if(event.type==EDR_EVT_REG_WRITE){
        auto kit=event.fields.find(field::kRegKey);
        auto vit=event.fields.find(field::kRegValue);
        std::string keyText= kit!=event.fields.end()?kit->second:"";
        std::string valText= vit!=event.fields.end()?vit->second:"";
        std::string lowerJoined=ToLowerAscii(keyText+" "+valText);
        if(!IsWinlogonKey(lowerJoined)) return;
        std::string lowerKey=ToLowerAscii(keyText);
        std::string lowerVal=ToLowerAscii(valText);
        // if value name indicates winlogon value
        bool isValSlot = IsWinlogonValue(lowerJoined);
        if(!isValSlot) return;
        Finding f;
        // Distinguish payload vs name-only (driver shape: value name without path)
        std::string lowerValTrim = lowerVal;
        bool isPayload = false;
        if (!valText.empty()) {
            bool hasPath = lowerVal.find("\\") != std::string::npos || lowerVal.find(":") != std::string::npos;
            bool hasExeDll = Contains(lowerVal, ".exe") || Contains(lowerVal, ".dll");
            bool isValueNameOnly = IsWinlogonValue(lowerVal) && !hasPath && !hasExeDll;
            if (isValueNameOnly) {
                f = Finding{75, "Winlogon value written with no payload token"};
            } else {
                isPayload = true;
                if (!ClassifyPayload(valText, &f)) return;
            }
        } else {
            f = Finding{75, "Winlogon value written with no payload token"};
        }
        if(f.score<m_minScore) return;
        std::string dedup=lowerJoined.substr(0,160);
        uint64_t now=event.ts100ns;
        auto it=m_state.find(dedup);
        if(it!=m_state.end()){
            if(m_dedupWindow100ns!=0 && now>=it->second && now-it->second<m_dedupWindow100ns) return;
            it->second=now;
        } else {
            if(m_capacity>0 && m_state.size()>=m_capacity){ m_state.clear(); std::fprintf(stderr,"[edr-winlogon] state capacity %zu reached; dedup reset\n",m_capacity); }
            m_state.emplace(dedup,now);
        }
        Stamp(event,f,lowerJoined.substr(0,160));
        return;
    }
    std::string text;
    auto cit=event.fields.find(field::kCommandLine);
    if(cit!=event.fields.end()) text=cit->second;
    if(text.empty() && event.type==EDR_EVT_POWERSHELL_SCRIPT){
        auto sit=event.fields.find(field::kScriptBlockText);
        if(sit!=event.fields.end()) text=sit->second;
    }
    if(text.empty()) return;
    std::string lower=ToLowerAscii(text);
    if(!IsWinlogonKey(lower)) return;
    if(!IsWinlogonValue(lower)) return;
    if(IsReadOnlyQuery(lower)) return;
    if(IsTrustedWriter(lower)) return;
    std::string data;
    size_t dpos=lower.find("/d");
    if(dpos!=std::string::npos){
        size_t s=dpos+2;
        while(s<text.size() && (text[s]==' '||text[s]=='\"'||text[s]==':')) ++s;
        size_t e=text.find(" /",s);
        if(e==std::string::npos) e=text.size();
        data=text.substr(s,e-s);
    } else data=text;
    Finding f;
    if(data.find(".exe")==std::string::npos && data.find(".dll")==std::string::npos && !MentionsInterpreter(ToLowerAscii(data))){
        f=Finding{75,"Winlogon value written with no payload token"};
    } else {
        if(!ClassifyPayload(data,&f)) return;
    }
    if(f.score<m_minScore) return;
    std::string key=lower.substr(0,160);
    uint64_t now=event.ts100ns;
    auto it=m_state.find(key);
    if(it!=m_state.end()){
        if(m_dedupWindow100ns!=0 && now>=it->second && now-it->second<m_dedupWindow100ns) return;
        it->second=now;
    } else {
        if(m_capacity>0 && m_state.size()>=m_capacity){ m_state.clear(); std::fprintf(stderr,"[edr-winlogon] state capacity %zu reached; dedup reset\n",m_capacity); }
        m_state.emplace(key,now);
    }
    Stamp(event,f,key);
}
} // namespace edr
