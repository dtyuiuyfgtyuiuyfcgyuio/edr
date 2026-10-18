/*
 * net_share_discovery_detector_tests.cpp - Unit tests for
 * NetShareDiscoveryDetector (T1135).
 *
 * The detector's contract is *burst-shaped*: a single share probe is routine
 * administration and stays silent, and it stamps only once an actor has
 * issued at least minCommands DISTINCT share-discovery commands inside the
 * rolling window. Expected scores mirror the ladder in
 * user/net_share_discovery_detector.cpp: 3 -> 60, 4 -> 70, 5 -> 75, 6+ -> 85,
 * plus 10 for the enumeration-then-pivot shape (localEnum && remoteUnc) and
 * plus 10 when the burst is privileged, capped at 100. >= 75 is "malicious".
 */
#include "net_share_discovery_detector_tests.h"
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include "edr_event.h"
#include "event_bus.h"
#include "net_share_discovery_detector.h"

namespace {
#define NS_CHECK(c) Check((c), #c, __LINE__)
void Check(bool c,const char* e,int l){ if(!c) throw std::runtime_error(std::string("CHECK failed at ")+std::to_string(l)+": "+e); }
constexpr uint64_t kSecond = 10000000ULL;
edr::Event ProcEvent(uint64_t ts, const char* cmd, const char* img="C:\\Windows\\System32\\cmd.exe", const char* sid="S-1-5-21-1", const char* sess="3"){
    edr::Event ev; ev.type=EDR_EVT_PROCESS_START; ev.ts100ns=ts; ev.fields[edr::field::kType]="PROCESS_START"; ev.fields[edr::field::kImage]=img; if(cmd) ev.fields[edr::field::kCommandLine]=cmd; if(sid) ev.fields[edr::field::kUserSid]=sid; if(sess) ev.fields[edr::field::kSessionId]=sess; return ev;
}
edr::Event ScriptEvent(uint64_t ts, const char* body, const char* img="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", const char* sid="S-1-5-21-1", const char* sess="3"){
    edr::Event ev; ev.type=EDR_EVT_POWERSHELL_SCRIPT; ev.ts100ns=ts; ev.fields[edr::field::kType]="POWERSHELL_SCRIPT"; ev.fields[edr::field::kImage]=img; if(body) ev.fields[edr::field::kScriptBlockText]=body; if(sid) ev.fields[edr::field::kUserSid]=sid; if(sess) ev.fields[edr::field::kSessionId]=sess; return ev;
}
std::string Score(const edr::Event& e){
    auto it=e.fields.find(edr::field::kNetShareDiscoveryScore);
    return it==e.fields.end()?"":it->second;
}
void Feed(edr::NetShareDiscoveryDetector& d, edr::Event ev){ d.Enrich(ev); }
std::string Field(const edr::Event& e, const char* name){
    auto it=e.fields.find(name);
    return it==e.fields.end()?"":it->second;
}
bool Stamped(const edr::Event& e){ return e.fields.find(edr::field::kNetShareDiscoveryScore)!=e.fields.end(); }
/* dedup window 0 so a replayed burst re-stamps on cooldown, matching the
 * shipped tuning tests in the wsl suite. */
edr::NetShareDiscoveryDetector MakeDetector(bool enabled, uint32_t minScore, uint32_t windowSeconds, uint32_t minCommands, uint32_t dedupSeconds, size_t capacity){
    return edr::NetShareDiscoveryDetector(enabled, minScore, windowSeconds, minCommands, dedupSeconds, capacity);
}
}

void RunNetShareDiscoveryDetectorTests(){
    std::fprintf(stderr, "[netshare] TestDisabled\n");
    {
        auto d=MakeDetector(false,55,300,3,0,64);
        auto e1=ProcEvent(kSecond,"net view");
        auto e2=ProcEvent(2*kSecond,"net view \\\\host\\share");
        auto e3=ProcEvent(3*kSecond,"net use");
        d.Enrich(e1); d.Enrich(e2); d.Enrich(e3);
        NS_CHECK(!Stamped(e1)); NS_CHECK(!Stamped(e2)); NS_CHECK(!Stamped(e3));
    }
    std::fprintf(stderr, "[netshare] TestInspects\n");
    {
        NS_CHECK(edr::NetShareDiscoveryDetector::Inspects(EDR_EVT_PROCESS_START));
        NS_CHECK(edr::NetShareDiscoveryDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
        NS_CHECK(!edr::NetShareDiscoveryDetector::Inspects(EDR_EVT_PROCESS_STOP));
        NS_CHECK(!edr::NetShareDiscoveryDetector::Inspects(EDR_EVT_NET_CONNECT));
    }
    std::fprintf(stderr, "[netshare] TestSingleProbeSilent\n");
    {
        auto d=MakeDetector(true,55,300,3,0,64);
        auto e=ProcEvent(kSecond,"net view \\\\host\\share");
        d.Enrich(e);
        NS_CHECK(Score(e).empty());
        NS_CHECK(d.StateCount()==1);
    }
    std::fprintf(stderr, "[netshare] TestBurstFloor\n");
    {
        /* 3 distinct commands -> base 60, no bonus -> verdict "suspicious". */
        auto d=MakeDetector(true,55,300,3,0,64);
        auto e1=ProcEvent(1*kSecond,"net view");
        d.Enrich(e1);
        auto e2=ProcEvent(2*kSecond,"net use");
        d.Enrich(e2);
        auto e3=ProcEvent(3*kSecond,"wmic share get name");
        d.Enrich(e3);
        NS_CHECK(Score(e3)=="60");
        NS_CHECK(Field(e3,edr::field::kNetShareDiscoveryVerdict)=="suspicious");
        NS_CHECK(Field(e3,edr::field::kNetShareDiscoveryCommandCount)=="3");
    }
    std::fprintf(stderr, "[netshare] TestBurstEscalation\n");
    {
        /* 5 distinct -> 75 (malicious). */
        auto d=MakeDetector(true,55,300,3,0,64);
        Feed(d, ProcEvent(1*kSecond,"net view"));
        Feed(d, ProcEvent(2*kSecond,"net use"));
        Feed(d, ProcEvent(3*kSecond,"wmic share get name"));
        Feed(d, ProcEvent(4*kSecond,"wmic share get caption"));
        auto e5=ProcEvent(5*kSecond,"get-smbshare");
        d.Enrich(e5);
        NS_CHECK(Score(e5)=="75");
        NS_CHECK(Field(e5,edr::field::kNetShareDiscoveryVerdict)=="malicious");
        NS_CHECK(Field(e5,edr::field::kNetShareDiscoveryCommandCount)=="5");
    }
    {
        /* 6 distinct -> 85 (malicious). */
        auto d=MakeDetector(true,55,300,3,0,64);
        Feed(d, ProcEvent(1*kSecond,"net view"));
        Feed(d, ProcEvent(2*kSecond,"net use"));
        Feed(d, ProcEvent(3*kSecond,"wmic share get name"));
        Feed(d, ProcEvent(4*kSecond,"wmic share get caption"));
        Feed(d, ProcEvent(5*kSecond,"get-smbshare"));
        auto e6=ProcEvent(6*kSecond,"get-ciminstance win32_share");
        d.Enrich(e6);
        NS_CHECK(Score(e6)=="85");
        NS_CHECK(Field(e6,edr::field::kNetShareDiscoveryVerdict)=="malicious");
        NS_CHECK(Field(e6,edr::field::kNetShareDiscoveryCommandCount)=="6");
    }
    std::fprintf(stderr, "[netshare] TestEnumerationThenPivotBonus\n");
    {
        /* Local "net view" alone would score 60. Adding a remote-UNC "dir
         * \\host\share" sets remoteUnc -> enumeration-then-pivot bonus +10
         * over the base ladder for the same command count (3 -> 60 -> 70). */
        auto d=MakeDetector(true,55,300,3,0,64);
        Feed(d, ProcEvent(1*kSecond,"net view"));
        Feed(d, ProcEvent(2*kSecond,"net use"));
        auto e3=ProcEvent(3*kSecond,"dir \\\\host\\share");
        d.Enrich(e3);
        NS_CHECK(Score(e3)=="70");
        NS_CHECK(Field(e3,edr::field::kNetShareDiscoveryVerdict)=="suspicious");
    }
    std::fprintf(stderr, "[netshare] TestPrivilegedBonus\n");
    {
        /* 3 distinct local commands, one privileged via "psexec" -> base 60
         * + 10 privileged = 70 (no remoteUnc, so no pivot bonus). */
        auto d=MakeDetector(true,55,300,3,0,64);
        Feed(d, ProcEvent(1*kSecond,"net view"));
        Feed(d, ProcEvent(2*kSecond,"net use"));
        auto e3=ProcEvent(3*kSecond,"wmic share get name psexec");
        d.Enrich(e3);
        NS_CHECK(Score(e3)=="70");
        NS_CHECK(Field(e3,edr::field::kNetShareDiscoverySignals)=="privileged network share discovery burst");
    }
    std::fprintf(stderr, "[netshare] TestTargetsCaptured\n");
    {
        /* ExtractTargets lowers and stops each host token at the first
         * separator, so "\\hostA\share" contributes the token "\\hosta";
         * targets are comma-joined and non-empty. */
        auto d=MakeDetector(true,55,300,3,0,64);
        Feed(d, ProcEvent(1*kSecond,"net view \\\\hostA\\share"));
        Feed(d, ProcEvent(2*kSecond,"net view \\\\hostB\\share"));
        auto e3=ProcEvent(3*kSecond,"net use");
        d.Enrich(e3);
        const std::string targets=Field(e3,edr::field::kNetShareDiscoveryTargets);
        NS_CHECK(!targets.empty());
        NS_CHECK(targets.find("\\\\hosta")!=std::string::npos);
        NS_CHECK(targets.find("\\\\hostb")!=std::string::npos);
        NS_CHECK(targets.find(",")!=std::string::npos);
    }
    std::fprintf(stderr, "[netshare] TestMinScoreGate\n");
    {
        /* Base burst is 60; a minScore of 90 suppresses the stamp. */
        auto d=MakeDetector(true,90,300,3,0,64);
        Feed(d, ProcEvent(1*kSecond,"net view"));
        Feed(d, ProcEvent(2*kSecond,"net use"));
        auto e3=ProcEvent(3*kSecond,"wmic share get name");
        d.Enrich(e3);
        NS_CHECK(!Stamped(e3));
    }
    std::fprintf(stderr, "[netshare] TestPoweshellScriptSurface\n");
    {
        /* POWERSHELL_SCRIPT is scored from kScriptBlockText. */
        auto d=MakeDetector(true,55,300,3,0,64);
        Feed(d, ScriptEvent(1*kSecond,"net view"));
        Feed(d, ScriptEvent(2*kSecond,"net use"));
        auto e3=ScriptEvent(3*kSecond,"wmic share get name");
        d.Enrich(e3);
        NS_CHECK(Score(e3)=="60");
        NS_CHECK(Field(e3,edr::field::kNetShareDiscoveryVerdict)=="suspicious");
    }
    {
        /* kCommandLine is NOT the PowerShell surface: a PS event whose
         * payload only lives in kCommandLine must not be scored. */
        auto d=MakeDetector(true,55,300,3,0,64);
        edr::Event e1; e1.type=EDR_EVT_POWERSHELL_SCRIPT; e1.ts100ns=1*kSecond;
        e1.fields[edr::field::kType]="POWERSHELL_SCRIPT";
        e1.fields[edr::field::kImage]="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        e1.fields[edr::field::kUserSid]="S-1-5-21-1"; e1.fields[edr::field::kSessionId]="3";
        e1.fields[edr::field::kCommandLine]="net view";
        edr::Event e2=e1; e2.ts100ns=2*kSecond; e2.fields[edr::field::kCommandLine]="net use";
        edr::Event e3=e1; e3.ts100ns=3*kSecond; e3.fields[edr::field::kCommandLine]="wmic share get name";
        d.Enrich(e1); d.Enrich(e2); d.Enrich(e3);
        NS_CHECK(!Stamped(e3));
    }
    std::fprintf(stderr, "[netshare] TestPerActorIsolation\n");
    {
        /* Two actors, each below minCommands: neither crosses threshold. */
        auto d=MakeDetector(true,55,300,3,0,64);
        Feed(d, ProcEvent(1*kSecond,"net view",  "C:\\Windows\\System32\\cmd.exe","S-1-5-21-AAA","3"));
        Feed(d, ProcEvent(2*kSecond,"net use",  "C:\\Windows\\System32\\cmd.exe","S-1-5-21-AAA","3"));
        auto eB1=ProcEvent(1*kSecond,"net view","C:\\Windows\\System32\\cmd.exe","S-1-5-21-BBB","3");
        d.Enrich(eB1);
        NS_CHECK(!Stamped(eB1));
        NS_CHECK(d.StateCount()==2);
    }
    std::fprintf(stderr, "[netshare] TestOutOfOrderTimestampRejected\n");
    {
        /* Later ts then earlier ts: the earlier event is clamped (returns
         * false) so it cannot extend the window or add a command. */
        auto d=MakeDetector(true,55,300,3,0,64);
        Feed(d, ProcEvent(10*kSecond,"net view"));
        Feed(d, ProcEvent(5*kSecond,"net use"));
        auto e3=ProcEvent(11*kSecond,"wmic share get name");
        d.Enrich(e3);
        NS_CHECK(Score(e3).empty()); /* only 2 in-window commands */
    }
    std::fprintf(stderr, "[netshare] TestWindowExpiry\n");
    {
        /* 3 fast commands cross the burst floor, but windowSeconds=5 makes
         * the first two expire once a much-later event purges them; the
         * actor drops below minCommands so nothing is stamped. */
        auto d=MakeDetector(true,55,5,3,0,64);
        Feed(d, ProcEvent(1*kSecond,"net view"));
        Feed(d, ProcEvent(2*kSecond,"net use"));
        auto e3=ProcEvent(3*kSecond,"wmic share get name");
        d.Enrich(e3);
        NS_CHECK(Score(e3)=="60");
        auto e4=ProcEvent(600*kSecond,"get-smbshare");
        d.Enrich(e4);
        NS_CHECK(Score(e4).empty()); /* prior commands expired */
    }
    std::fprintf(stderr, "[netshare] TestCapacityReset\n");
    {
        /* Tiny capacity with many distinct actors: state resets rather than
         * growing unbounded; must not crash and StateCount stays bounded. */
        auto d=MakeDetector(true,55,300,3,0,16);
        for(int i=0;i<200;++i){
            const std::string sid="S-1-5-21-"+std::to_string(i);
            Feed(d, ProcEvent((1+i)*kSecond,"net view","C:\\Windows\\System32\\cmd.exe",sid.c_str(),"3"));
            NS_CHECK(d.StateCount()<=16);
        }
    }
    std::fprintf(stderr, "[netshare] TestStateCountAccessor\n");
    {
        auto d=MakeDetector(true,55,300,3,0,64);
        NS_CHECK(d.StateCount()==0);
        Feed(d, ProcEvent(1*kSecond,"net view","C:\\Windows\\System32\\cmd.exe","S-1-5-21-X1","3"));
        NS_CHECK(d.StateCount()==1);
        Feed(d, ProcEvent(1*kSecond,"net view","C:\\Windows\\System32\\cmd.exe","S-1-5-21-X2","3"));
        NS_CHECK(d.StateCount()==2);
    }
    std::fprintf(stderr, "[netshare] all passed\n");
}