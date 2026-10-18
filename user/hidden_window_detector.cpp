/*
 * hidden_window_detector.cpp - See hidden_window_detector.h (T1564.003)
 */
#include "hidden_window_detector.h"
#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {
namespace {
bool Contains(const std::string& v,const char* n){return v.find(n)!=std::string::npos;}
std::string ToLower(const std::string& t){std::string o=t; std::transform(o.begin(),o.end(),o.begin(),[](unsigned char c){return (char)std::tolower(c);}); return o;}
bool MentionsPayload(const std::string& l){return Contains(l,"-enc")||Contains(l,"-encodedcommand")||Contains(l,"invoke-expression")||Contains(l,"iex")||Contains(l,"downloadstring")||Contains(l,"webclient")||Contains(l,"http");}
}
HiddenWindowDetector::HiddenWindowDetector(bool e,uint32_t min,uint32_t dedup,size_t cap):m_enabled(e),m_minScore(min),m_dedupWindow100ns((uint64_t)dedup*kFiletimeTicksPerSecond),m_stateCapacity(cap){}
bool HiddenWindowDetector::Inspects(uint16_t t){return t==EDR_EVT_PROCESS_START||t==EDR_EVT_POWERSHELL_SCRIPT;}
bool HiddenWindowDetector::Analyze(const std::string& lower,const std::string&,Finding* out) const{
    bool hiddenStyle=Contains(lower,"windowstyle")&&Contains(lower,"hidden");
    bool wHidden=Contains(lower," -w hidden")||Contains(lower," -windowstyle hidden");
    bool createNoWindow=Contains(lower,"create_no_window")||Contains(lower,"createnowindow");
    bool useShowHidden=Contains(lower,"useshowwindow")||Contains(lower,"startupinfo")&&Contains(lower,"hidden");
    bool startMin=Contains(lower,"start ")&& (Contains(lower," /min")||Contains(lower," /b"));
    // score tiers
    if((hiddenStyle||wHidden||createNoWindow||useShowHidden) && MentionsPayload(lower)){ *out={90,"hidden window with encoded/download payload"}; return true; }
    if(hiddenStyle||wHidden||createNoWindow||useShowHidden){ *out={85,"hidden window style execution"}; return true; }
    if(startMin && MentionsPayload(lower)){ *out={80,"start /min with payload"}; return true; }
    if(startMin){ *out={75,"concealed window via start /min"}; return true; }
    /* Bare -WindowStyle with a VISIBLE style (Minimized/Normal/Maximized)
     * is legitimate UI usage and stays silent; concealed variants are
     * already covered by hiddenStyle/wHidden above. */
    return false;
}
void HiddenWindowDetector::Stamp(Event& ev,const Finding& f,const std::string& k){
    ev.fields[field::kHiddenWindowScore]=std::to_string(f.score);
    ev.fields[field::kHiddenWindowVerdict]=f.score>=75?"malicious":"suspicious";
    ev.fields[field::kHiddenWindowSignals]=f.signal;
    ev.fields[field::kHiddenWindowText]=k;
}
void HiddenWindowDetector::Enrich(Event& ev){
    if(!m_enabled) return;
    std::string text; auto it=ev.fields.find(field::kCommandLine);
    if(it!=ev.fields.end()) text=it->second;
    if(text.empty()&&ev.type==EDR_EVT_POWERSHELL_SCRIPT){auto s=ev.fields.find(field::kScriptBlockText); if(s!=ev.fields.end()) text=s->second;}
    if(text.empty()){auto img=ev.fields.find(field::kImage); if(img!=ev.fields.end()) text=img->second;}
    if(text.empty()) return;
    std::string lower=ToLower(text);
    // ignore help queries listing flags
    if(Contains(lower,"get-help")||(Contains(lower,"/?")&&Contains(lower,"windowstyle"))) return;
    Finding f; if(!Analyze(lower,text,&f)) return;
    if(f.score < m_minScore) return;
    std::string key=lower.substr(0,160);
    uint64_t now=ev.ts100ns; auto dit=m_lastAlert.find(key);
    if(dit!=m_lastAlert.end()){ if(m_dedupWindow100ns!=0 && now>=dit->second && now-dit->second<m_dedupWindow100ns) return; dit->second=now; }
    else { if(m_stateCapacity>0 && m_lastAlert.size()>=m_stateCapacity){m_lastAlert.clear(); std::fprintf(stderr,"[edr-hidden-window] state capacity %zu reached; dedup reset\n",m_stateCapacity);} m_lastAlert.emplace(key,now); }
    Stamp(ev,f,key);
}
} // namespace edr
