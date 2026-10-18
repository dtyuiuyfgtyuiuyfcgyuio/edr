/*
 * mshta_abuse_detector.cpp - Mshta proxy execution detector (T1218.005).
 */
#include "mshta_abuse_detector.h"
#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {
namespace {
bool Contains(const std::string& v,const char* n){return v.find(n)!=std::string::npos;}
std::string ToLowerAscii(const std::string& t){
    std::string o=t; std::transform(o.begin(),o.end(),o.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));}); return o;
}
bool MentionsWritableDir(const std::string& l){
    return Contains(l,"\\temp\\")||Contains(l,"\\tmp\\")||Contains(l,"appdata")||Contains(l,"\\downloads\\")||Contains(l,"\\users\\public")||Contains(l,"programdata")||Contains(l,"%temp%");
}
} // namespace

MshtaAbuseDetector::MshtaAbuseDetector(bool e,uint32_t ms,uint32_t dw,size_t cap)
    :m_enabled(e),m_minScore(ms),m_dedupWindow100ns(static_cast<uint64_t>(dw)*kFiletimeTicksPerSecond),m_capacity(cap){}

bool MshtaAbuseDetector::Inspects(uint16_t t){
    return t==EDR_EVT_PROCESS_START;
}
bool MshtaAbuseDetector::ClassifyPayload(const std::string& lower, Finding* out){
    bool isMshta = Contains(lower,"mshta");
    if(!isMshta) return false;
    bool hasHttp = Contains(lower,"http://")||Contains(lower,"https://");
    bool hasJs = Contains(lower,"javascript:")||Contains(lower,"vbscript:");
    bool hasHta = Contains(lower,".hta");
    if(hasHttp){
        *out=Finding{90,"mshta remote http payload"};
        return true;
    }
    if(hasJs){
        *out=Finding{85,"mshta javascript/vbscript payload"};
        return true;
    }
    if(hasHta){
        if(MentionsWritableDir(lower)){
            *out=Finding{80,"mshta hta in writable dir"};
        } else {
            *out=Finding{75,"mshta hta execution"};
        }
        return true;
    }
    return false;
}
void MshtaAbuseDetector::Stamp(Event& e,const Finding& f,const std::string& k){
    e.fields[field::kMshtaAbuseScore]=std::to_string(f.score);
    e.fields[field::kMshtaAbuseVerdict]= f.score>=75?"malicious":"suspicious";
    e.fields[field::kMshtaAbuseSignals]=f.signal;
    e.fields[field::kMshtaAbuseText]=k;
}
void MshtaAbuseDetector::Enrich(Event& event){
    if(!m_enabled) return;
    if(!Inspects(event.type)) return;
    std::string image;
    auto imgIt=event.fields.find(field::kImage);
    if(imgIt!=event.fields.end()) image=imgIt->second;
    std::string cmd;
    auto cmdIt=event.fields.find(field::kCommandLine);
    if(cmdIt!=event.fields.end()) cmd=cmdIt->second;
    std::string combined = image + " " + cmd;
    std::string lower = ToLowerAscii(combined);
    if(!Contains(lower,"mshta")) return;
    // allowlist: mshta without args is silent? But mshta alone is rare; treat as silent if no payload
    Finding f;
    if(!ClassifyPayload(lower,&f)) return;
    if(f.score<m_minScore) return;
    std::string key=lower.substr(0,160);
    uint64_t now=event.ts100ns;
    auto it=m_state.find(key);
    if(it!=m_state.end()){
        if(m_dedupWindow100ns!=0 && now>=it->second && now-it->second<m_dedupWindow100ns) return;
        it->second=now;
    } else {
        if(m_capacity>0 && m_state.size()>=m_capacity){ m_state.clear(); std::fprintf(stderr,"[edr-mshta] state capacity %zu reached; dedup reset\n",m_capacity); }
        m_state.emplace(key,now);
    }
    Stamp(event,f,key);
}
} // namespace edr
