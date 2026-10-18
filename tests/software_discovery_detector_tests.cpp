/*
 * software_discovery_detector_tests.cpp - Unit tests for
 * SoftwareDiscoveryDetector (T1518 / T1518.001).
 *
 * The contract is *breadth*, not volume: a lone `wmic product get` is routine
 * administration and stays silent; the detector only stamps once one actor
 * (image basename + owning user) has asked at least min_categories distinct
 * census questions inside the rolling window.
 *
 * Score ladder, read from software_discovery_detector.cpp:
 *   score = 60 + (count - 2) * 15, capped 100        (2 -> 60, 3 -> 75)
 *   +10 when the actor looks privileged, capped 100
 *   security_products present with count >= min_categories ->
 *       score = max(score, privileged ? 90 : 70)
 * Verdict: score >= 75 -> "malicious", otherwise "suspicious".
 */
#include "software_discovery_detector_tests.h"
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include "edr_event.h"
#include "event_bus.h"
#include "software_discovery_detector.h"

namespace {
#define SD_CHECK(c) Check((c), #c, __LINE__)
void Check(bool c,const char* e,int l){ if(!c) throw std::runtime_error(std::string("CHECK failed at ")+std::to_string(l)+": "+e); }
constexpr uint64_t kSecond=10000000ULL;
/* PROCESS_START carries the census text in kCommandLine. */
edr::Event ProcEvent(uint64_t ts, const char* image, const char* cmd, const char* sid=nullptr){
    edr::Event ev; ev.type=EDR_EVT_PROCESS_START; ev.ts100ns=ts; ev.fields[edr::field::kType]="PROCESS_START"; ev.fields[edr::field::kImage]=image; if(cmd) ev.fields[edr::field::kCommandLine]=cmd; if(sid) ev.fields[edr::field::kUserSid]=sid; return ev;
}
/* House contract: a POWERSHELL_SCRIPT body lives only in kScriptBlockText. */
edr::Event ScriptEvent(uint64_t ts, const char* image, const char* body, const char* sid=nullptr){
    edr::Event ev; ev.type=EDR_EVT_POWERSHELL_SCRIPT; ev.ts100ns=ts; ev.fields[edr::field::kType]="POWERSHELL_SCRIPT"; ev.fields[edr::field::kImage]=image; if(body) ev.fields[edr::field::kScriptBlockText]=body; if(sid) ev.fields[edr::field::kUserSid]=sid; return ev;
}
std::string Field(const edr::Event& e,const char* name){
    auto it=e.fields.find(name); return it==e.fields.end()?"":it->second;
}
std::string Score(const edr::Event& e){ return Field(e,edr::field::kSoftwareDiscoveryScore); }
std::string Verdict(const edr::Event& e){ return Field(e,edr::field::kSoftwareDiscoveryVerdict); }
std::string Categories(const edr::Event& e){ return Field(e,edr::field::kSoftwareDiscoveryCategories); }
std::string CategoryCount(const edr::Event& e){ return Field(e,edr::field::kSoftwareDiscoveryCategoryCount); }
/* One census command per category, exactly as Classify() spells the needles. */
const char* kInventory="wmic product get name";
const char* kSecurity="wmic /namespace:\\root\\securitycenter2 product get name";
const char* kApps="dir \"%ProgramFiles%\"";
const char* kImage="C:\\Windows\\System32\\cmd.exe";
}

void RunSoftwareDiscoveryDetectorTests(){
    std::fprintf(stderr, "[swdisc] TestDisabled\n");
    {
        /* A full sweep, but the detector is switched off. */
        edr::SoftwareDiscoveryDetector d(false,55,300,2,0,1024);
        auto a=ProcEvent(10*kSecond,kImage,kInventory,"S-1-5-18");
        d.Enrich(a);
        auto b=ProcEvent(11*kSecond,kImage,kSecurity,"S-1-5-18");
        d.Enrich(b);
        auto c=ProcEvent(12*kSecond,kImage,kApps,"S-1-5-18");
        d.Enrich(c);
        SD_CHECK(Score(c).empty());
        SD_CHECK(Verdict(c).empty());
        SD_CHECK(d.StateCount()==0);
    }
    std::fprintf(stderr, "[swdisc] TestInspects\n");
    {
        SD_CHECK(edr::SoftwareDiscoveryDetector::Inspects(EDR_EVT_PROCESS_START));
        SD_CHECK(edr::SoftwareDiscoveryDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
        SD_CHECK(!edr::SoftwareDiscoveryDetector::Inspects(EDR_EVT_FILE_CREATE));
        SD_CHECK(!edr::SoftwareDiscoveryDetector::Inspects(EDR_EVT_PROCESS_STOP));
    }
    std::fprintf(stderr, "[swdisc] TestLoneCommandSilent\n");
    {
        /* One category only: below min_categories, so nothing is stamped. */
        edr::SoftwareDiscoveryDetector d(true,55,300,2,0,1024);
        auto ev=ProcEvent(10*kSecond,kImage,kInventory,"S-1-5-21-1001");
        d.Enrich(ev);
        SD_CHECK(Score(ev).empty());
        SD_CHECK(CategoryCount(ev).empty());
        /* Repeating the same question never manufactures breadth. */
        for(int i=1;i<10;++i){ auto again=ProcEvent((10+i)*kSecond,kImage,kInventory,"S-1-5-21-1001"); d.Enrich(again); SD_CHECK(Score(again).empty()); }
    }
    std::fprintf(stderr, "[swdisc] TestBreadnessLowFloor\n");
    {
        /* Exactly min_categories=2 -> 60 + (2-2)*15 = 60 -> "suspicious". */
        edr::SoftwareDiscoveryDetector d(true,55,300,2,0,1024);
        auto a=ProcEvent(10*kSecond,kImage,kInventory,"S-1-5-21-2002");
        d.Enrich(a);
        auto b=ProcEvent(11*kSecond,kImage,kApps,"S-1-5-21-2002");
        d.Enrich(b);
        SD_CHECK(Score(b)=="60");
        SD_CHECK(Verdict(b)=="suspicious");
        SD_CHECK(CategoryCount(b)=="2");
        SD_CHECK(Categories(b)=="installed_apps,software_inventory");
        /* No security_products, so no T1518.001 escalation. */
        SD_CHECK(Field(b,edr::field::kSoftwareDiscoverySignals)=="software discovery across multiple inventory categories");
    }
    std::fprintf(stderr, "[swdisc] TestFullSweep\n");
    {
        /* All three categories -> 60 + (3-2)*15 = 75 -> "malicious".
         * security_products is present, so max(75, 70) leaves it at 75. */
        edr::SoftwareDiscoveryDetector d(true,55,300,2,0,1024);
        auto a=ProcEvent(10*kSecond,kImage,kInventory,"S-1-5-21-3003");
        d.Enrich(a);
        auto b=ProcEvent(11*kSecond,kImage,kSecurity,"S-1-5-21-3003");
        d.Enrich(b);
        auto c=ProcEvent(12*kSecond,kImage,kApps,"S-1-5-21-3003");
        d.Enrich(c);
        SD_CHECK(Score(c)=="75");
        SD_CHECK(Verdict(c)=="malicious");
        SD_CHECK(CategoryCount(c)=="3");
        SD_CHECK(Categories(c)=="installed_apps,security_products,software_inventory");
        SD_CHECK(Field(c,edr::field::kSoftwareDiscoverySignals)=="security software discovery across multiple categories");
    }
    std::fprintf(stderr, "[swdisc] TestPrivilegedBonus\n");
    {
        /* Same 2-category breadth, but a privileged command line: 60 + 10 = 70
         * -> "suspicious" (verdict flips at 75, not at the bonus). */
        /* Both events must share one actor key (image basename + SID): the
         * privilege flag lives on the actor, so a different image would start a
         * different investigator entirely. */
        edr::SoftwareDiscoveryDetector d(true,55,300,2,0,1024);
        auto a=ProcEvent(10*kSecond,kImage,kInventory,"S-1-5-21-4004");
        d.Enrich(a);
        SD_CHECK(Score(a).empty());
        auto b=ProcEvent(11*kSecond,kImage,"runas /user:CORP\\admin cmd /c dir \"%ProgramFiles%\"","S-1-5-21-4004");
        d.Enrich(b);
        SD_CHECK(Score(b)=="70");
        SD_CHECK(Verdict(b)=="suspicious");
        SD_CHECK(Field(b,edr::field::kSoftwareDiscoverySignals)=="privileged software inventory across multiple categories");
    }
    std::fprintf(stderr, "[swdisc] TestSecurityProductsFloor\n");
    {
        /* Unprivileged + security_products + breadth: max(60, 70) = 70. */
        edr::SoftwareDiscoveryDetector d(true,55,300,2,0,1024);
        auto a=ProcEvent(10*kSecond,kImage,kSecurity,"S-1-5-21-5005");
        d.Enrich(a);
        auto b=ProcEvent(11*kSecond,kImage,kInventory,"S-1-5-21-5005");
        d.Enrich(b);
        SD_CHECK(Score(b)=="70");
        SD_CHECK(Verdict(b)=="suspicious");
        SD_CHECK(Categories(b)=="security_products,software_inventory");

        /* Privileged + security_products + breadth: max(60+10, 90) = 90. */
        edr::SoftwareDiscoveryDetector p(true,55,300,2,0,1024);
        auto c=ProcEvent(10*kSecond,"C:\\Windows\\PsExec\\psexec.exe",kSecurity,"S-1-5-21-5006");
        p.Enrich(c);
        SD_CHECK(Score(c).empty());
        auto d2=ProcEvent(11*kSecond,"C:\\Windows\\PsExec\\psexec.exe","psexec \\\\host cmd /c wmic product get name","S-1-5-21-5006");
        p.Enrich(d2);
        SD_CHECK(Score(d2)=="90");
        SD_CHECK(Verdict(d2)=="malicious");
        SD_CHECK(Field(d2,edr::field::kSoftwareDiscoverySignals)=="privileged security software discovery across multiple categories");
    }
    std::fprintf(stderr, "[swdisc] TestMinScoreGate\n");
    {
        /* The 2-category case scores 60; a min_score of 75 suppresses it. */
        edr::SoftwareDiscoveryDetector d(true,75,300,2,0,1024);
        auto a=ProcEvent(10*kSecond,kImage,kInventory,"S-1-5-21-6006");
        d.Enrich(a);
        auto b=ProcEvent(11*kSecond,kImage,kApps,"S-1-5-21-6006");
        d.Enrich(b);
        SD_CHECK(Score(b).empty());
        SD_CHECK(d.StateCount()==1);
    }
    std::fprintf(stderr, "[swdisc] TestPoweshellScriptSurface\n");
    {
        /* The payload rides in kScriptBlockText and is scored from there. */
        edr::SoftwareDiscoveryDetector d(true,55,300,2,0,1024);
        const char* psImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        auto a=ScriptEvent(10*kSecond,psImage,"Get-WmiObject Win32_Product","S-1-5-21-7007");
        d.Enrich(a);
        SD_CHECK(Score(a).empty());
        /* The second body is a full census sweep in one script: Win32_Product
         * asks the inventory question and root/securitycenter2 plus
         * Win32_Product asks the security-product question, so this single
         * event carries two categories -> max(60, 70) = 70. */
        auto b=ScriptEvent(11*kSecond,psImage,"Get-CimInstance -Namespace root/securitycenter2 Win32_Product","S-1-5-21-7007");
        d.Enrich(b);
        SD_CHECK(Score(b)=="70");
        SD_CHECK(Verdict(b)=="suspicious");
        SD_CHECK(CategoryCount(b)=="2");
        SD_CHECK(Categories(b)=="security_products,software_inventory");
        /* A third census question reaches the full sweep: 60 + (3-2)*15 = 75. */
        auto b2=ScriptEvent(12*kSecond,psImage,"Get-ChildItem env:ProgramFiles","S-1-5-21-7007");
        d.Enrich(b2);
        SD_CHECK(Score(b2)=="75");
        SD_CHECK(Verdict(b2)=="malicious");
        SD_CHECK(CategoryCount(b2)=="3");

        /* kCommandLine is not the script surface: a POWERSHELL_SCRIPT event
         * whose census text sits only in kCommandLine must stay silent,
         * because Classify() runs on the image fallback ("powershell.exe")
         * which asks no census question. */
        edr::SoftwareDiscoveryDetector m(true,55,300,2,0,1024);
        edr::Event wrong; wrong.type=EDR_EVT_POWERSHELL_SCRIPT; wrong.ts100ns=20*kSecond;
        wrong.fields[edr::field::kType]="POWERSHELL_SCRIPT";
        wrong.fields[edr::field::kImage]=psImage;
        wrong.fields[edr::field::kCommandLine]=kInventory;
        m.Enrich(wrong);
        SD_CHECK(Score(wrong).empty());
    }
    std::fprintf(stderr, "[swdisc] TestPerActorIsolation\n");
    {
        /* Same census, two SIDs: each actor holds one category, so neither
         * reaches min_categories and neither stamps. */
        edr::SoftwareDiscoveryDetector d(true,55,300,2,0,1024);
        auto a=ProcEvent(10*kSecond,kImage,kInventory,"S-1-5-21-alice");
        d.Enrich(a);
        auto b=ProcEvent(11*kSecond,kImage,kApps,"S-1-5-21-bob");
        d.Enrich(b);
        SD_CHECK(Score(a).empty());
        SD_CHECK(Score(b).empty());
        SD_CHECK(d.StateCount()==2);
        /* Each user can then complete its own breadth independently. */
        auto c=ProcEvent(12*kSecond,kImage,kApps,"S-1-5-21-alice");
        d.Enrich(c);
        SD_CHECK(Score(c)=="60");
        SD_CHECK(d.StateCount()==2);
    }
    std::fprintf(stderr, "[swdisc] TestOutOfOrderTimestampRejected\n");
    {
        /* Analyze() returns false when now < lastSeen100ns, so the stale event
         * neither adds its category nor stamps nor extends the window. */
        edr::SoftwareDiscoveryDetector d(true,55,300,2,0,1024);
        auto a=ProcEvent(20*kSecond,kImage,kInventory,"S-1-5-21-8008");
        d.Enrich(a);
        auto b=ProcEvent(19*kSecond,kImage,kApps,"S-1-5-21-8008");
        d.Enrich(b);
        SD_CHECK(Score(b).empty());
        /* The actor still holds exactly the one category the accepted event
         * contributed -- the stale one was dropped entirely. */
        auto c=ProcEvent(21*kSecond,kImage,kSecurity,"S-1-5-21-8008");
        d.Enrich(c);
        SD_CHECK(Score(c)=="70");
        SD_CHECK(CategoryCount(c)=="2");
    }
    std::fprintf(stderr, "[swdisc] TestWindowExpiry\n");
    {
        /* 300s window: the inventory category is stamped at t=10s, then ages
         * out once the actor is seen more than 300s later, so the next breadth
         * event starts from one category again and stays silent. */
        edr::SoftwareDiscoveryDetector d(true,55,300,2,0,1024);
        auto a=ProcEvent(10*kSecond,kImage,kInventory,"S-1-5-21-9009");
        d.Enrich(a);
        SD_CHECK(Score(a).empty());
        auto b=ProcEvent(11*kSecond,kImage,kApps,"S-1-5-21-9009");
        d.Enrich(b);
        SD_CHECK(Score(b)=="60");

        /* t=312s: both t=10s and t=11s are older than the window -> purged. */
        auto c=ProcEvent(312*kSecond,kImage,kSecurity,"S-1-5-21-9009");
        d.Enrich(c);
        SD_CHECK(Score(c).empty());
        SD_CHECK(d.StateCount()==1);

        /* Still inside the window relative to t=312s, but only one category:
         * a pre-seeded score must survive untouched. */
        auto e=ProcEvent(313*kSecond,kImage,kSecurity,"S-1-5-21-9009");
        e.fields[edr::field::kSoftwareDiscoveryScore]="sentinel";
        d.Enrich(e);
        SD_CHECK(Field(e,edr::field::kSoftwareDiscoveryScore)=="sentinel");
    }
    std::fprintf(stderr, "[swdisc] TestCapacityReset\n");
    {
        /* 40 distinct SIDs against capacity 16: the map is cleared rather
         * than grown without bound, so StateCount() stays bounded and the
         * detector keeps working afterwards. */
        edr::SoftwareDiscoveryDetector d(true,55,300,2,0,16);
        for(int i=0;i<40;++i){
            auto ev=ProcEvent((10+i)*kSecond,kImage,kInventory,("S-1-5-21-c"+std::to_string(i)).c_str());
            d.Enrich(ev);
            SD_CHECK(d.StateCount()<=17);
        }
        SD_CHECK(d.StateCount()<=17);
        /* Census state is cheap to rebuild: the surviving actor still scores. */
        auto a=ProcEvent(100*kSecond,kImage,kInventory,"S-1-5-21-zz");
        d.Enrich(a);
        auto b=ProcEvent(101*kSecond,kImage,kApps,"S-1-5-21-zz");
        d.Enrich(b);
        SD_CHECK(Score(b)=="60");
    }
    std::fprintf(stderr, "[swdisc] TestStateCountAccessor\n");
    {
        edr::SoftwareDiscoveryDetector d(true,55,300,2,0,1024);
        SD_CHECK(d.StateCount()==0);
        auto a=ProcEvent(10*kSecond,kImage,kInventory,"S-1-5-21-a1");
        d.Enrich(a);
        SD_CHECK(d.StateCount()==1);
        auto b=ProcEvent(11*kSecond,kImage,kInventory,"S-1-5-21-b1");
        d.Enrich(b);
        SD_CHECK(d.StateCount()==2);
        /* A second event for the same actor re-uses its state row. */
        auto c=ProcEvent(12*kSecond,kImage,kApps,"S-1-5-21-a1");
        d.Enrich(c);
        SD_CHECK(d.StateCount()==2);
    }
    std::fprintf(stderr, "[swdisc] all passed\n");
}