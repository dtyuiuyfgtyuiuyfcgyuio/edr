/*
 * dotnet_proxy_exec_detector.cpp - .NET assembly-registration tool proxy
 * execution detector (T1218.009).
 *
 * House contract: PROCESS_START takes kCommandLine; POWERSHELL_SCRIPT takes
 * kScriptBlockText (never kCommandLine). Scores >= 55 suspicious,
 * >= 75 malicious; below min_score stays silent (not even a verdict).
 *
 * False-positive note: legitimate deployment scripts register signed
 * in-house assemblies with regasm.exe/regsvcs.exe. Those normally sit in
 * Program Files with a distributor-signed assembly and land at the 75
 * "suspicious" floor; operators that only want the weaponized shapes should
 * raise dotnet_proxy_exec.min_score to 85.
 */
#include "dotnet_proxy_exec_detector.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace edr {
namespace {

bool Contains(const std::string& v,const char* n){return v.find(n)!=std::string::npos;}

std::string ToLowerAscii(const std::string& t){
    std::string o=t;
    std::transform(o.begin(),o.end(),o.begin(),
        [](unsigned char c){return static_cast<char>(std::tolower(c));});
    return o;
}

std::string BaseName(const std::string& v){
    size_t p=v.find_last_of("\\/");
    return p==std::string::npos?v:v.substr(p+1);
}

/* The invoked image basename is one of the two registration tools. */
bool IsProxyImage(const std::string& imageLower){
    const std::string b=BaseName(imageLower);
    return b=="regsvcs.exe"||b=="regasm.exe";
}

/* Remove the tool tokens so the tool's own ".exe" suffix is never mistaken
 * for an assembly-file argument on the script plane. */
std::string StripToolTokens(const std::string& s){
    std::string out=s;
    const char* tokens[]={"regsvcs.exe","regasm.exe","regsvcs","regasm"};
    for(const char* tok:tokens){
        const size_t n=std::strlen(tok);
        size_t p;
        while((p=out.find(tok))!=std::string::npos) out.erase(p,n);
    }
    return out;
}

bool MentionsRemote(const std::string& l){
    return Contains(l,"http://")||Contains(l,"https://")||Contains(l,"\\\\");
}

bool MentionsWritableDir(const std::string& l){
    return Contains(l,"\\temp\\")||Contains(l,"\\tmp\\")||Contains(l,"appdata")||
           Contains(l,"\\users\\public")||Contains(l,"\\downloads\\")||
           Contains(l,"programdata")||Contains(l,"%temp%");
}

bool MentionsInterpreter(const std::string& l){
    return Contains(l,"powershell")||Contains(l,"pwsh")||Contains(l,"cmd")||
           Contains(l,"wscript")||Contains(l,"cscript")||Contains(l,"mshta")||
           Contains(l,"-enc")||Contains(l,"javascript:")||Contains(l,"vbscript:")||
           Contains(l,"rundll32");
}

/* "/U" (unregister) switch. Multi-marker lookup uses the house
 * `(a != npos) ? a : b` idiom; std::max(rfind(A),rfind(B)) is banned
 * because a missing marker poisons the result with npos. */
bool MentionsUnregister(const std::string& l){
    return Contains(l,"/u ")||Contains(l,"/u\t")||Contains(l,"/u:")||Contains(l,"/unregister");
}

/* Parent is an Office application or a script host. */
bool HasOfficeOrScriptHostParent(const std::string& parentLower){
    const std::string b=BaseName(parentLower);
    return b=="winword.exe"||b=="excel.exe"||b=="powerpnt.exe"||b=="outlook.exe"||
           b=="wscript.exe"||b=="cscript.exe"||b=="mshta.exe";
}

/* An assembly-file argument is present (its own ".exe" already stripped). */
bool HasAssemblyArg(const std::string& l){
    return Contains(l,".dll")||Contains(l,".exe");
}

} // namespace

DotnetProxyExecDetector::DotnetProxyExecDetector(
    bool e,uint32_t ms,uint32_t dw,size_t cap)
    :m_enabled(e),m_minScore(ms),
     m_dedupWindow100ns(static_cast<uint64_t>(dw)*kFiletimeTicksPerSecond),
     m_capacity(cap){}

bool DotnetProxyExecDetector::Inspects(uint16_t t){
    return t==EDR_EVT_PROCESS_START||t==EDR_EVT_POWERSHELL_SCRIPT;
}

bool DotnetProxyExecDetector::ClassifyPayload(
    const std::string& lower, const std::string& imageLower,
    const std::string& parentLower, Finding* out){
    const bool proxyImage=IsProxyImage(imageLower);
    // On the script plane there is no image; the tool is named in the text.
    const bool mentionsTool=Contains(lower,"regsvcs")||Contains(lower,"regasm");
    if(!proxyImage&&!mentionsTool) return false;

    const std::string args=StripToolTokens(lower);
    const bool remote=MentionsRemote(args);
    const bool writable=MentionsWritableDir(args);
    const bool unregister=MentionsUnregister(args);
    const bool interpreter=MentionsInterpreter(args);
    const bool assemblyArg=HasAssemblyArg(args);

    Finding f;
    if(unregister&&(remote||writable)){
        f=Finding{85,"regsvcs/regasm unregister of writable or remote assembly"};
    } else if(remote){
        f=Finding{90,"regsvcs/regasm remote or UNC assembly"};
    } else if(writable){
        f=Finding{90,"regsvcs/regasm assembly from user-writable path"};
    } else if(interpreter){
        f=Finding{85,"regsvcs/regasm assembly argument references script interpreter"};
    } else if(assemblyArg){
        f=Finding{75,"regsvcs/regasm assembly invocation"};
    } else {
        // Bare `regsvcs` / `regasm` (or a help switch only) stays silent.
        return false;
    }

    // An Office or script-host parent lifts a sub-85 base to 85.
    if(f.score<85&&HasOfficeOrScriptHostParent(parentLower)){
        f.score=85;
        f.signal="regsvcs/regasm spawned by office or script host";
    }
    *out=f;
    return true;
}

void DotnetProxyExecDetector::Stamp(Event& e,const Finding& f,const std::string& k){
    e.fields[field::kDotnetProxyExecScore]=std::to_string(f.score);
    e.fields[field::kDotnetProxyExecVerdict]= f.score>=75?"malicious":"suspicious";
    e.fields[field::kDotnetProxyExecSignals]=f.signal;
    e.fields[field::kDotnetProxyExecText]=k;
}

void DotnetProxyExecDetector::Enrich(Event& event){
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

    const std::string imageLower=ToLowerAscii(image);
    const std::string lower=ToLowerAscii(image+" "+text);

    Finding f;
    if(!ClassifyPayload(lower,imageLower,ToLowerAscii(parent),&f)) return;
    if(f.score<m_minScore) return;

    const std::string key=lower.substr(0,160);
    const uint64_t now=event.ts100ns;
    auto it=m_state.find(key);
    if(it!=m_state.end()){
        if(m_dedupWindow100ns!=0 && now>=it->second && now-it->second<m_dedupWindow100ns) return;
        it->second=now;
    } else {
        if(m_capacity>0 && m_state.size()>=m_capacity){
            m_state.clear();
            std::fprintf(stderr,"[edr-dotnet-proxy] state capacity %zu reached; dedup reset\n",m_capacity);
        }
        m_state.emplace(key,now);
    }
    Stamp(event,f,key);
}

} // namespace edr
