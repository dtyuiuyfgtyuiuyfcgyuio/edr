/*
 * iso_mount_detector_tests.cpp - Unit tests for IsoMountDetector (T1553.005).
 */
#include "iso_mount_detector_tests.h"
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include "edr_event.h"
#include "event_bus.h"
#include "iso_mount_detector.h"

namespace {
#define SR_CHECK(c) Check((c), #c, __LINE__)
void Check(bool c,const char* e,int l){ if(!c) throw std::runtime_error(std::string("CHECK failed at ")+std::to_string(l)+": "+e); }
edr::Event ProcEvent(uint64_t ts, const char* img, const char* cmd){
    edr::Event ev; ev.type=EDR_EVT_PROCESS_START; ev.ts100ns=ts; ev.fields[edr::field::kType]="PROCESS_START"; ev.fields[edr::field::kImage]=img; if(cmd) ev.fields[edr::field::kCommandLine]=cmd; return ev;
}
edr::Event ScriptEvent(uint64_t ts, const char* body){
    edr::Event ev; ev.type=EDR_EVT_POWERSHELL_SCRIPT; ev.ts100ns=ts; ev.fields[edr::field::kType]="POWERSHELL_SCRIPT"; if(body) ev.fields[edr::field::kScriptBlockText]=body; return ev;
}
std::string Score(const edr::Event& e){
    auto it=e.fields.find(edr::field::kIsoMountScore);
    return it==e.fields.end()?"":it->second;
}
}

void RunIsoMountDetectorTests(){
    std::fprintf(stderr, "[isomount] TestDisabled\n");
    {
        edr::IsoMountDetector d(false,55,300,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","powershell Mount-DiskImage -ImagePath C:\\Users\\Public\\evil.iso");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[isomount] TestWritableMount\n");
    {
        edr::IsoMountDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","powershell Mount-DiskImage -ImagePath C:\\Users\\Public\\evil.iso");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[isomount] TestPlainMount\n");
    {
        edr::IsoMountDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","powershell Mount-DiskImage -ImagePath D:\\images\\tools.iso");
        d.Enrich(ev); SR_CHECK(Score(ev)=="85");
    }
    std::fprintf(stderr, "[isomount] TestExplorerMount\n");
    {
        edr::IsoMountDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\explorer.exe","explorer.exe C:\\Users\\Public\\Downloads\\evil.iso");
        d.Enrich(ev); SR_CHECK(Score(ev)=="75");
    }
    std::fprintf(stderr, "[isomount] TestScriptSurface\n");
    {
        edr::IsoMountDetector d(true,55,0,1024);
        auto ev=ScriptEvent(10000000ULL,"Mount-DiskImage -ImagePath \"$env:TEMP\\evil.vhd\"");
        d.Enrich(ev); SR_CHECK(Score(ev)=="90");
    }
    std::fprintf(stderr, "[isomount] TestEmptyScriptSilent\n");
    {
        edr::IsoMountDetector d(true,55,0,1024);
        auto ev=ScriptEvent(10000000ULL,nullptr);
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[isomount] TestDismInspectSilent\n");
    {
        edr::IsoMountDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\Dism.exe","dism /get-imageinfo /imagefile:C:\\images\\tools.iso");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[isomount] TestDismountSilent\n");
    {
        edr::IsoMountDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","powershell Dismount-DiskImage -ImagePath C:\\Users\\Public\\evil.iso");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[isomount] TestArchiveListSilent\n");
    {
        edr::IsoMountDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Program Files\\7-Zip\\7z.exe","7z l C:\\Users\\Public\\evil.iso");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[isomount] TestBenignSilent\n");
    {
        edr::IsoMountDetector d(true,55,0,1024);
        auto ev=ProcEvent(10000000ULL,"C:\\Windows\\System32\\notepad.exe","notepad.exe");
        d.Enrich(ev); SR_CHECK(Score(ev).empty());
    }
    std::fprintf(stderr, "[isomount] all passed\n");
}
