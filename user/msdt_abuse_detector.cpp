/*
 * msdt_abuse_detector.cpp - MSDT / ms-msdt URI abuse detector (T1203).
 *
 * House contract: PROCESS_START takes kCommandLine; POWERSHELL_SCRIPT takes
 * kScriptBlockText (never kCommandLine). Scores >= 55 suspicious,
 * >= 75 malicious; below min_score stays silent.
 *
 * False-positive note: legitimate troubleshooting runs msdt.exe with a
 * plain /id pack. Bare msdt.exe and plain /id invocations still score 75
 * (suspicious); operators that only want weaponized shapes should raise
 * msdt_abuse.min_score to 85.
 */
#include "msdt_abuse_detector.h"
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
bool IsMsdtImage(const std::string& imageLower){
    const std::string b=BaseName(imageLower);
    return b=="msdt.exe"||b=="sdiagnhost.exe";
}
bool MentionsRemote(const std::string& l){
    return Contains(l,"http://")||Contains(l,"https://")||Contains(l,"\\\\")||Contains(l,".hta")||
           Contains(l,".diagcab")||Contains(l,".ps1");
}
bool MentionsScriptInterpreter(const std::string& l){
    return Contains(l,"powershell")||Contains(l,"pwsh")||Contains(l,"cmd /")||Contains(l,"cmd.exe")||
           Contains(l,"wscript")||Contains(l,"cscript")||Contains(l,"-enc")||Contains(l,"encodedcommand")||
           Contains(l,"invoke-expression")||Contains(l,"vbscript:")||Contains(l,"javascript:");
}
bool MentionsWritableDir(const std::string& l){
    return Contains(l,"\\temp\\")||Contains(l,"\\tmp\\")||Contains(l,"appdata")||Contains(l,"\\downloads\\")||
           Contains(l,"\\users\\public")||Contains(l,"programdata")||Contains(l,"%temp%");
}
bool HasOfficeParent(const std::string& parentLower){
    const std::string b=BaseName(parentLower);
    return b=="winword.exe"||b=="excel.exe"||b=="powerpnt.exe"||b=="outlook.exe"||b=="msaccess.exe"||
           b=="mspub.exe"||b=="visio.exe";
}
} // namespace

MsdtAbuseDetector::MsdtAbuseDetector(bool e,uint32_t ms,uint32_t dw,size_t cap)
    :m_enabled(e),m_minScore(ms),m_dedupWindow100ns(static_cast<uint64_t>(dw)*kFiletimeTicksPerSecond),m_capacity(cap){}

bool MsdtAbuseDetector::Inspects(uint16_t t){
    return t==EDR_EVT_PROCESS_START||t==EDR_EVT_POWERSHELL_SCRIPT;
}

bool MsdtAbuseDetector::ClassifyPayload(const std::string& lower, const std::string& imageLower, const std::string& parentLower, Finding* out){
    // Follina vector: ms-msdt: URI from any image (usually an Office doc).
    if(Contains(lower,"ms-msdt:")){
        *out=Finding{90,"ms-msdt uri handler invocation"};
        return true;
    }
    if(!IsMsdtImage(imageLower)) return false;
    // Diagnostic invocation backed by a writable path (staged .diagcab etc.)
    // is distinct from a remote payload even when the extension is .diagcab.
    if((Contains(lower,"/id")||Contains(lower,"pcwdiagnostic")||Contains(lower,"/af")||Contains(lower,"/moreoptions"))&&MentionsWritableDir(lower)){
        *out=Finding{85,"msdt diagnostic with writable path"};
        return true;
    }
    if(MentionsRemote(lower)){
        *out=Finding{90,"msdt remote payload reference"};
        return true;
    }
    if(MentionsScriptInterpreter(lower)){
        *out=Finding{85,"msdt script interpreter reference"};
        return true;
    }
    // Any other msdt invocation with arguments (plain /id troubleshooting
    // packs land here; see the FP note above).
    if(Contains(lower,"msdt")&&lower!=BaseName(imageLower)){
        Finding f{75,"msdt diagnostic invocation with arguments"};
        if(HasOfficeParent(parentLower)){
            f.score=85;
            f.signal="msdt spawned by office application";
        }
        *out=f;
        return true;
    }
    return false;
}

void MsdtAbuseDetector::Stamp(Event& e,const Finding& f,const std::string& k){
    e.fields[field::kMsdtAbuseScore]=std::to_string(f.score);
    e.fields[field::kMsdtAbuseVerdict]= f.score>=75?"malicious":"suspicious";
    e.fields[field::kMsdtAbuseSignals]=f.signal;
    e.fields[field::kMsdtAbuseText]=k;
}

void MsdtAbuseDetector::Enrich(Event& event){
    if(!m_enabled) return;
    if(!Inspects(event.type)) return;
    std::string image;
    auto imgIt=event.fields.find(field::kImage);
    if(imgIt!=event.fields.end()) image=imgIt->second;
    std::string parent;
    auto parIt=event.fields.find(field::kParentImage);
    if(parIt!=event.fields.end()) parent=parIt->second;
    std::string text;
    auto cmdIt=event.fields.find(field::kCommandLine);
    if(cmdIt!=event.fields.end()) text=cmdIt->second;
    if(text.empty()&&event.type==EDR_EVT_POWERSHELL_SCRIPT){
        auto scIt=event.fields.find(field::kScriptBlockText);
        if(scIt!=event.fields.end()) text=scIt->second;
    }
    if(text.empty()) return;
    std::string textLower=ToLowerAscii(text);
    const std::string imgLower=ToLowerAscii(image);
    // Bare msdt.exe (no arguments) is the interactive troubleshooter
    // entry point and stays silent.
    if(textLower.empty()||textLower==BaseName(imgLower)||textLower==imgLower) return;
    std::string combined=image+" "+text;
    std::string lower=ToLowerAscii(combined);
    Finding f;
    if(!ClassifyPayload(lower,imgLower,ToLowerAscii(parent),&f)) return;
    if(f.score<m_minScore) return;
    std::string key=lower.substr(0,160);
    uint64_t now=event.ts100ns;
    auto it=m_state.find(key);
    if(it!=m_state.end()){
        if(m_dedupWindow100ns!=0 && now>=it->second && now-it->second<m_dedupWindow100ns) return;
        it->second=now;
    } else {
        if(m_capacity>0 && m_state.size()>=m_capacity){ m_state.clear(); std::fprintf(stderr,"[edr-msdt] state capacity %zu reached; dedup reset\n",m_capacity); }
        m_state.emplace(key,now);
    }
    Stamp(event,f,key);
}
} // namespace edr
