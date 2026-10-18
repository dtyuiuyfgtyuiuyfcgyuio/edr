/*
 * cmstp_bypass_detector.cpp - See cmstp_bypass_detector.h
 */
#include "cmstp_bypass_detector.h"
#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {
namespace {
bool Contains(const std::string& v, const char* n){ return v.find(n)!=std::string::npos; }
std::string ToLower(const std::string& t){ std::string o=t; std::transform(o.begin(),o.end(),o.begin(),[](unsigned char c){return (char)std::tolower(c);}); return o; }
bool MentionsWritable(const std::string& l){ return Contains(l,"\\temp\\")||Contains(l,"%temp%")||Contains(l,"\\appdata\\")||Contains(l,"%appdata%")||Contains(l,"\\users\\public")||Contains(l,"\\programdata\\")||Contains(l,"\\downloads\\")||Contains(l,"\\desktop\\"); }
bool IsRemoteInf(const std::string& l){ return Contains(l,"http://")||Contains(l,"https://")||Contains(l,"\\\\"); }
}
CmstpBypassDetector::CmstpBypassDetector(bool e,uint32_t min,uint32_t dedup,size_t cap):m_enabled(e),m_minScore(min),m_dedupWindow100ns((uint64_t)dedup*kFiletimeTicksPerSecond),m_stateCapacity(cap){}
bool CmstpBypassDetector::Inspects(uint16_t t){ return t==EDR_EVT_PROCESS_START||t==EDR_EVT_POWERSHELL_SCRIPT; }
bool CmstpBypassDetector::Analyze(const std::string& lower,const std::string& /*raw*/, Finding* out) const{
    bool hasCmstp=Contains(lower,"cmstp");
    bool hasInf=Contains(lower,".inf");
    bool hasControlCpl=Contains(lower,"control")&&Contains(lower,".cpl");
    if(hasCmstp){
        if(hasInf){
            if(IsRemoteInf(lower)){ *out={90,"cmstp with remote INF"}; return true; }
            if(MentionsWritable(lower)){ *out={90,"cmstp with INF in writable path"}; return true; }
            *out={85,"cmstp with local INF"}; return true;
        }
        if(Contains(lower,"/ni")||Contains(lower,"/s ")||Contains(lower," /ni")||Contains(lower,"-ni")){ *out={75,"cmstp with non-interactive switch"}; return true; }
        // bare cmstp invocation without inf is suspicious but low
        *out={60,"cmstp invocation without INF"}; return true;
    }
    if(hasControlCpl && MentionsWritable(lower)){ *out={75,"control with CPL in writable path"}; return true; }
    return false;
}
void CmstpBypassDetector::Stamp(Event& ev,const Finding& f,const std::string& k){
    ev.fields[field::kCmstpBypassScore]=std::to_string(f.score);
    ev.fields[field::kCmstpBypassVerdict]=f.score>=75?"malicious":"suspicious";
    ev.fields[field::kCmstpBypassSignals]=f.signal;
    ev.fields[field::kCmstpBypassText]=k;
}
void CmstpBypassDetector::Enrich(Event& ev){
    if(!m_enabled) return;
    std::string text;
    auto it=ev.fields.find(field::kCommandLine);
    if(it!=ev.fields.end()) text=it->second;
    if(text.empty()&&ev.type==EDR_EVT_POWERSHELL_SCRIPT){
        auto s=ev.fields.find(field::kScriptBlockText);
        if(s!=ev.fields.end()) text=s->second;
    }
    if(text.empty()){
        auto img=ev.fields.find(field::kImage);
        if(img!=ev.fields.end()) text=img->second;
    }
    if(text.empty()) return;
    std::string lower=ToLower(text);
    // ignore read-only queries that mention cmstp as a string
    if(Contains(lower,"reg query")||Contains(lower,"findstr")||Contains(lower,"select-string")) return;
    Finding f;
    if(!Analyze(lower,text,&f)) return;
    if(f.score < m_minScore) return;
    std::string key=lower.substr(0,160);
    uint64_t now=ev.ts100ns;
    auto dit=m_lastAlert.find(key);
    if(dit!=m_lastAlert.end()){
        if(m_dedupWindow100ns!=0 && now>=dit->second && now-dit->second < m_dedupWindow100ns) return;
        dit->second=now;
    } else {
        if(m_stateCapacity>0 && m_lastAlert.size()>=m_stateCapacity){ m_lastAlert.clear(); std::fprintf(stderr,"[edr-cmstp] state capacity %zu reached; dedup reset\n",m_stateCapacity); }
        m_lastAlert.emplace(key,now);
    }
    Stamp(ev,f,key);
}
} // namespace edr
