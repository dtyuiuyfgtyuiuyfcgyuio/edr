#include "ssh_abuse_detector_tests.h"
#include "ssh_abuse_detector.h"
#include "edr_event.h"
#include "event_bus.h"
#include <cstdio>
#include <stdexcept>
namespace edr {
#define CHECK(c) do{ if(!(c)){ std::fprintf(stderr,"check failed at %d: %s\n",__LINE__,#c); throw std::runtime_error("check failed"); } } while(0)
static Event MakeProc(const std::string& image, const std::string& cmd, uint64_t ts=10000000ULL){
    Event e; e.type=EDR_EVT_PROCESS_START; e.ts100ns=ts; e.pid=2001; e.ppid=500;
    e.fields[field::kType]="PROCESS_START"; e.fields[field::kImage]=image; e.fields[field::kCommandLine]=cmd; return e;
}
void RunSshAbuseDetectorTests(){
    std::fprintf(stderr,"[ssh_abuse] TestHostkeyNull90\n");
    {
        SshAbuseDetector d(true,55,300,1024);
        Event e=MakeProc("C:\\Windows\\System32\\OpenSSH\\ssh.exe","ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@evil.com",10000000ULL);
        d.Enrich(e); CHECK(e.fields.at(field::kSshAbuseScore)=="90"); CHECK(e.fields.at(field::kSshAbuseVerdict)=="malicious");
    }
    std::fprintf(stderr,"[ssh_abuse] TestHostkeyOnly85\n");
    {
        SshAbuseDetector d(true,55,300,1024);
        Event e=MakeProc("C:\\Program Files\\PuTTY\\plink.exe","plink -ssh -o StrictHostKeyChecking=no user@host",10000000ULL);
        d.Enrich(e); CHECK(e.fields.at(field::kSshAbuseScore)=="85");
    }
    std::fprintf(stderr,"[ssh_abuse] TestIdentity80\n");
    {
        SshAbuseDetector d(true,55,300,1024);
        Event e=MakeProc("C:\\Windows\\System32\\OpenSSH\\ssh.exe","ssh -i C:\\temp\\id_rsa user@host",10000000ULL);
        d.Enrich(e); CHECK(e.fields.at(field::kSshAbuseScore)=="80");
    }
    std::fprintf(stderr,"[ssh_abuse] TestPort60\n");
    {
        SshAbuseDetector d(true,55,300,1024);
        Event e=MakeProc("C:\\Windows\\System32\\OpenSSH\\ssh.exe","ssh -p 2222 user@host",10000000ULL);
        d.Enrich(e); CHECK(e.fields.at(field::kSshAbuseScore)=="60");
    }
    std::fprintf(stderr,"[ssh_abuse] TestPlain55\n");
    {
        SshAbuseDetector d(true,55,300,1024);
        Event e=MakeProc("C:\\Windows\\System32\\OpenSSH\\ssh.exe","ssh user@host",10000000ULL);
        d.Enrich(e); CHECK(e.fields.at(field::kSshAbuseScore)=="55"); CHECK(e.fields.at(field::kSshAbuseVerdict)=="suspicious");
    }
    std::fprintf(stderr,"[ssh_abuse] TestBoundaryBelow55Silent\n");
    {
        SshAbuseDetector d(true,75,300,1024);
        Event e=MakeProc("C:\\Windows\\System32\\OpenSSH\\ssh.exe","ssh user@host",10000000ULL);
        d.Enrich(e); CHECK(e.fields.find(field::kSshAbuseScore)==e.fields.end());
        Event e2=MakeProc("C:\\Windows\\System32\\OpenSSH\\ssh.exe","ssh -p 2222 user@host",10000000ULL);
        d.Enrich(e2); CHECK(e2.fields.find(field::kSshAbuseScore)==e2.fields.end());
    }
    std::fprintf(stderr,"[ssh_abuse] TestNegativeBenign\n");
    {
        SshAbuseDetector d(true,55,300,1024);
        Event e=MakeProc("C:\\Windows\\System32\\cmd.exe","cmd.exe /c dir C:\\",10000000ULL);
        d.Enrich(e); CHECK(e.fields.find(field::kSshAbuseScore)==e.fields.end());
        Event e2=MakeProc("C:\\Windows\\System32\\notepad.exe","notepad.exe",10000000ULL);
        d.Enrich(e2); CHECK(e2.fields.find(field::kSshAbuseScore)==e2.fields.end());
    }
    std::fprintf(stderr,"[ssh_abuse] TestDedupAndWidening\n");
    {
        SshAbuseDetector d(true,55,5,1024);
        Event e1=MakeProc("C:\\Windows\\System32\\OpenSSH\\ssh.exe","ssh user@host",10000000ULL);
        d.Enrich(e1); CHECK(e1.fields.at(field::kSshAbuseScore)=="55");
        Event e2=MakeProc("C:\\Windows\\System32\\OpenSSH\\ssh.exe","ssh user@host",20000000ULL);
        d.Enrich(e2); CHECK(e2.fields.find(field::kSshAbuseScore)==e2.fields.end());
        Event e3=MakeProc("C:\\Windows\\System32\\OpenSSH\\ssh.exe","ssh user@host",70000000ULL);
        d.Enrich(e3); CHECK(e3.fields.at(field::kSshAbuseScore)=="55");
    }
    std::fprintf(stderr,"[ssh_abuse] TestDisabledSilent\n");
    {
        SshAbuseDetector d(false,55,300,1024);
        Event e=MakeProc("C:\\Windows\\System32\\OpenSSH\\ssh.exe","ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@evil.com",10000000ULL);
        d.Enrich(e); CHECK(e.fields.find(field::kSshAbuseScore)==e.fields.end());
    }
    std::fprintf(stderr,"[ssh_abuse] TestCaseInsensitive\n");
    {
        SshAbuseDetector d(true,55,300,1024);
        Event e=MakeProc("C:\\Windows\\System32\\OpenSSH\\SSH.EXE","SSH -o StrictHostKeyChecking=No -o UserKnownHostsFile=/dev/null user@host",10000000ULL);
        d.Enrich(e); CHECK(e.fields.at(field::kSshAbuseScore)=="90");
    }
    std::fprintf(stderr,"[ssh_abuse] all passed\n");
}
} // namespace edr
