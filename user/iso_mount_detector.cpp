/*
 * iso_mount_detector.cpp - Disk-image mount abuse detector (T1553.005).
 *
 * House contract: PROCESS_START takes kCommandLine; POWERSHELL_SCRIPT takes
 * kScriptBlockText (never kCommandLine). Scores >= 55 suspicious,
 * >= 75 malicious; below min_score stays silent.
 */
#include "iso_mount_detector.h"
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
bool MentionsDiskImage(const std::string& l){
    return Contains(l,".iso")||Contains(l,".img")||Contains(l,".vhd");
}
bool MentionsWritableDir(const std::string& l){
    return Contains(l,"\\temp\\")||Contains(l,"\\tmp\\")||Contains(l,"appdata")||Contains(l,"\\downloads\\")||
           Contains(l,"\\users\\public")||Contains(l,"programdata")||Contains(l,"%temp%")||
           Contains(l,"$env:temp")||Contains(l,"\\desktop\\");
}
} // namespace

IsoMountDetector::IsoMountDetector(bool e,uint32_t ms,uint32_t dw,size_t cap)
    :m_enabled(e),m_minScore(ms),m_dedupWindow100ns(static_cast<uint64_t>(dw)*kFiletimeTicksPerSecond),m_capacity(cap){}

bool IsoMountDetector::Inspects(uint16_t t){
    return t==EDR_EVT_PROCESS_START||t==EDR_EVT_POWERSHELL_SCRIPT;
}

bool IsoMountDetector::ClassifyPayload(const std::string& lower, const std::string& imageLower, Finding* out){
    if(!MentionsDiskImage(lower)) return false;

    // Dismount/cleanup is explicitly non-creating and remains silent even
    // when the image path is user-writable.
    if(Contains(lower,"dismount-diskimage")) return false;

    // PowerShell-native mount verb (also the script-body shape).
    if(Contains(lower,"mount-diskimage")){
        if(MentionsWritableDir(lower)){
            *out=Finding{90,"disk image mounted from writable path"};
        } else {
            *out=Finding{85,"mount-diskimage execution"};
        }
        return true;
    }
    // Explorer double-click mount of a staged image.
    if(BaseName(imageLower)=="explorer.exe"){
        *out=Finding{75,"explorer mounted disk image"};
        return true;
    }
    // Read-only inspection stays silent: dism /get-imageinfo, Get-DiskImage
    // queries, dismount cleanup, archive listing of an .iso.
    if(Contains(lower,"get-imageinfo")||Contains(lower,"get-diskimage")||
       Contains(lower,"dismount-diskimage")||Contains(lower,"/get-wiminfo")){
        return false;
    }
    return false;
}

void IsoMountDetector::Stamp(Event& e,const Finding& f,const std::string& k){
    e.fields[field::kIsoMountScore]=std::to_string(f.score);
    e.fields[field::kIsoMountVerdict]= f.score>=75?"malicious":"suspicious";
    e.fields[field::kIsoMountSignals]=f.signal;
    e.fields[field::kIsoMountText]=k;
}

void IsoMountDetector::Enrich(Event& event){
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
    if(text.empty()) return;
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
        if(m_capacity>0 && m_state.size()>=m_capacity){ m_state.clear(); std::fprintf(stderr,"[edr-isomount] state capacity %zu reached; dedup reset\n",m_capacity); }
        m_state.emplace(key,now);
    }
    Stamp(event,f,key);
}
} // namespace edr
