/*
 * file_assoc_detector.cpp - See file_assoc_detector.h (T1546.001)
 */
#include "file_assoc_detector.h"
#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {
namespace {
bool Contains(const std::string& v,const char* n){return v.find(n)!=std::string::npos;}
std::string ToLower(const std::string& t){std::string o=t; std::transform(o.begin(),o.end(),o.begin(),[](unsigned char c){return (char)std::tolower(c);}); return o;}
bool EndsWith(const std::string& v,const char* s){size_t n=std::char_traits<char>::length(s); return v.size()>=n && v.compare(v.size()-n,n,s)==0;}
bool MentionsInterpreter(const std::string& l){ return Contains(l,"powershell")||Contains(l,"pwsh")||Contains(l,"cmd.exe")||Contains(l,"wscript")||Contains(l,"cscript")||Contains(l,"rundll32")||Contains(l,"mshta")||Contains(l,"regsvr32"); }
bool MentionsWritable(const std::string& l){ return Contains(l,"\\temp\\")||Contains(l,"%temp%")||Contains(l,"\\appdata\\")||Contains(l,"%appdata%")||Contains(l,"\\users\\public")||Contains(l,"\\programdata\\")||Contains(l,"\\downloads\\")||Contains(l,"\\desktop\\"); }
bool MentionsPayloadExt(const std::string& l){ return Contains(l,".exe")||Contains(l,".bat")||Contains(l,".cmd")||Contains(l,".vbs")||Contains(l,".js")||Contains(l,".ps1")||Contains(l,".hta"); }
bool IsStockOpen(const std::string& l){ return (Contains(l,"\\windows\\system32\\")||Contains(l,"%systemroot%")||Contains(l,"%windir%")) && Contains(l,"notepad")&&!MentionsWritable(l); }
bool IsAssocSlot(const std::string& l){ 
    /* Both the HKCU/HKLM Software\Classes subtree and the HKCR merged
     * view (reg add HKCR\txtfile\shell\open\command) name a slot. */
    const bool classesTree = Contains(l,"software\\classes") || Contains(l,"hkcr\\");
    if(!classesTree) return false;
    return Contains(l,"shell\\open\\command")||Contains(l,"openwithprogids")||
           Contains(l,"\\exefile")||Contains(l,"\\scrfile")||
           EndsWith(l,".exe")||Contains(l,"\\command");
}
/* ftype/assoc WRITE always carries '='; a query never does. */
bool IsReadOnlyQuery(const std::string& l){ 
    bool q=Contains(l,"assoc")||Contains(l,"ftype")||Contains(l,"reg query")||Contains(l,"get-itemproperty"); 
    if(!q) return false; 
    return !Contains(l,"reg add")&&!Contains(l,"set-itemproperty")&&!Contains(l,"new-item")&&!Contains(l,"="); 
}
}
FileAssocDetector::FileAssocDetector(bool e,uint32_t min,uint32_t dedup,size_t cap):m_enabled(e),m_minScore(min),m_dedupWindow100ns((uint64_t)dedup*kFiletimeTicksPerSecond),m_stateCapacity(cap){}
bool FileAssocDetector::Inspects(uint16_t t){ return t==EDR_EVT_PROCESS_START||t==EDR_EVT_POWERSHELL_SCRIPT||t==EDR_EVT_REG_WRITE; }
bool FileAssocDetector::ClassifyPayload(const std::string& data, Finding* out){
    std::string l=ToLower(data); if(l.empty()) return false;
    if(MentionsInterpreter(l)){ *out={90,"file association points at interpreter"}; return true; }
    if(MentionsWritable(l)){ *out={90,"file association in writable path"}; return true; }
    if(IsStockOpen(l)) return false;
    if(MentionsPayloadExt(l)){ *out={85,"file association with payload extension"}; return true; }
    return false;
}
void FileAssocDetector::Stamp(Event& ev,const Finding& f,const std::string& k){
    ev.fields[field::kFileAssocScore]=std::to_string(f.score);
    ev.fields[field::kFileAssocVerdict]=f.score>=75?"malicious":"suspicious";
    ev.fields[field::kFileAssocSignals]=f.signal;
    ev.fields[field::kFileAssocText]=k;
}
void FileAssocDetector::Enrich(Event& ev){
    if(!m_enabled) return;
    if(ev.type==EDR_EVT_REG_WRITE){
        auto k=ev.fields.find(field::kRegKey);
        auto v=ev.fields.find(field::kRegValue);
        std::string key=k!=ev.fields.end()?k->second:"";
        std::string val=v!=ev.fields.end()?v->second:"";
        std::string lowerKey=ToLower(key), lowerVal=ToLower(val), joined=ToLower(key+" "+val);
        if(!IsAssocSlot(lowerKey) && !IsAssocSlot(lowerVal) && !IsAssocSlot(joined)) return;
        /* sysmon/reg_watch shape: key names the slot, val carries the
         * DATA. driver shape: kRegValue carries only the value NAME
         * ("(default)") or is empty -- slot touched, no data seen. */
        bool keyIsSlot=IsAssocSlot(lowerKey);
        Finding f;
        if(keyIsSlot && (val.empty() || lowerVal=="(default)")){
            f={75,"file association slot registered without payload"};
        } else if(keyIsSlot){
            if(!ClassifyPayload(val,&f)) return;
        } else {
            if(val.empty()||!ClassifyPayload(val,&f)) return;
        }
        if(f.score < m_minScore) return;
        Stamp(ev,f, joined.substr(0,160));
        return;
    }
    std::string text;
    auto it=ev.fields.find(field::kCommandLine);
    if(it!=ev.fields.end()) text=it->second;
    if(text.empty()&&ev.type==EDR_EVT_POWERSHELL_SCRIPT){ auto s=ev.fields.find(field::kScriptBlockText); if(s!=ev.fields.end()) text=s->second; }
    if(text.empty()) return;
    std::string lower=ToLower(text);
    if(IsReadOnlyQuery(lower)) return;
    /* Command plane: a ftype/assoc WRITE always carries '='; without
     * one this is a read-only query (already handled above as belt) or
     * chatter. */
    bool mentionsFtype=Contains(lower,"ftype")&&Contains(lower,"=");
    bool mentionsAssocEq=Contains(lower,"assoc ")&&Contains(lower,"=");
    bool mentionsAssocSlot=(Contains(lower,"software\\classes")||Contains(lower,"hkcr\\"))&&Contains(lower,"shell\\open\\command");
    if(!mentionsFtype && !mentionsAssocEq && !mentionsAssocSlot) return;
    Finding f; std::string payload=text;
    // try to extract payload after = or /d
    size_t eq=text.rfind('='); size_t dpos=lower.rfind("/d ");
    size_t start=std::string::npos;
    if(eq!=std::string::npos) start=eq+1; else if(dpos!=std::string::npos) start=dpos+3;
    if(start!=std::string::npos && start<text.size()) payload=text.substr(start);
    // strip quotes
    if(!payload.empty() && (payload.front()=='\"'||payload.front()=='\'')){ char q=payload.front(); size_t e=payload.find(q,1); if(e!=std::string::npos) payload=payload.substr(1,e-1); }
    if(!ClassifyPayload(payload,&f)){
        // ftype slot write without extractable payload still counts
        if(mentionsFtype||mentionsAssocEq) f={75,"file association slot written without payload token"};
        else return;
    }
    if(f.score < m_minScore) return;
    std::string key=lower.substr(0,160);
    uint64_t now=ev.ts100ns; auto dit=m_lastAlert.find(key);
    if(dit!=m_lastAlert.end()){ if(m_dedupWindow100ns!=0 && now>=dit->second && now-dit->second<m_dedupWindow100ns) return; dit->second=now; }
    else { if(m_stateCapacity>0 && m_lastAlert.size()>=m_stateCapacity){m_lastAlert.clear(); std::fprintf(stderr,"[edr-file-assoc] state capacity %zu reached; dedup reset\n",m_stateCapacity);} m_lastAlert.emplace(key,now); }
    Stamp(ev,f,key);
}
} // namespace edr
