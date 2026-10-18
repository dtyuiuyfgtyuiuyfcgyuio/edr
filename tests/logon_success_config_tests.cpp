#include <windows.h>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"

int main(int argc, char** argv) {
    char directory[MAX_PATH] = {}, file[MAX_PATH] = {};
    if (!GetTempPathA(MAX_PATH, directory) || !GetTempFileNameA(directory, "lsc", 0, file)) return 2;
    try {
        const char* invalid[] = {
            R"({"logon_success":false})",
            R"({"logon_success":{"enable":"true"}})",
            R"({"logon_success":{"window_seconds":0}})",
            R"({"logon_success":{"state_capacity":8193}})",
            R"({"logon_success":{"min_failures":1}})",
            R"({"logon_success":{"min_failures":257}})",
            R"({"logon_success":{"min_failures":2.5}})",
            R"({"logon_success":{"typo":1}})",
            R"({"dns_failure":false})",
            R"({"dns_failure":{"enable":1}})",
            R"({"dns_failure":{"min_queries":257}})",
            R"({"dns_failure":{"min_distinct_names":0}})",
            R"({"dns_failure":{"min_failure_percent":101}})",
            R"({"dns_failure":{"min_high_entropy_failures":0}})",
            R"({"dns_failure":{"typo":1}})"
        };
        for (const char* content : invalid) {
            std::ofstream(file, std::ios::binary | std::ios::trunc) << content;
            edr::Config config;
            config.rulesPath = "unchanged";
            std::string error;
            if (edr::LoadConfigFile(file, config, error))
                throw std::runtime_error(std::string("invalid detection config accepted: ") + content);
            if (config.rulesPath != "unchanged" || error.empty())
                throw std::runtime_error("config failure was not atomic/observable");
        }
        std::ofstream(file, std::ios::binary | std::ios::trunc) <<
            R"({"logon_success":{"enable":true,"window_seconds":30,"state_capacity":256,"min_failures":2}})";
        edr::Config config;
        std::string error;
        if (edr::Config().logonSuccessEnable ||
            !edr::LoadConfigFile(file, config, error) || !config.logonSuccessEnable ||
            config.logonSuccessWindowSeconds != 30 || config.logonSuccessStateCapacity != 256 ||
            config.logonSuccessMinFailures != 2)
            throw std::runtime_error("valid/default config contract failed");
        std::ofstream(file, std::ios::binary | std::ios::trunc) <<
            R"({"dns_failure":{"enable":true,"window_seconds":30,"state_capacity":256,"min_queries":2,"min_distinct_names":4,"min_failure_percent":90,"min_high_entropy_failures":2}})";
        if (edr::Config().dnsFailureEnable ||
            !edr::LoadConfigFile(file, config, error) || !config.dnsFailureEnable ||
            config.dnsFailureWindowSeconds != 30 || config.dnsFailureStateCapacity != 256 ||
            config.dnsFailureMinQueries != 2 || config.dnsFailureMinDistinctNames != 4 ||
            config.dnsFailureMinFailurePercent != 90 || config.dnsFailureMinHighEntropyFailures != 2)
            throw std::runtime_error("valid/default DNS config contract failed");
        if (argc == 2) {
            edr::RuleEngine engine;
            engine.LoadFromFile(argv[1]);
            unsigned matched = 0;
            engine.SetAlertCallback([&](const edr::Alert& alert) {
                if (alert.ruleId == "EDR-517") {
                    ++matched;
                    if (alert.action != "alert") throw std::runtime_error("unsafe logon rule action");
                }
            });
            edr::Event event;
            event.type = EDR_EVT_LOGON;
            event.fields[edr::field::kType] = "LOGON";
            event.fields[edr::field::kOperationType] = "LOGON";
            event.fields[edr::field::kLogonSuccessScore] = "75";
            engine.OnEvent(event);
            if (matched != 1) throw std::runtime_error("logon success production rule missing");
            event.fields[edr::field::kLogonSuccessScore] = "74";
            engine.OnEvent(event);
            event.fields[edr::field::kLogonSuccessScore] = "75";
            event.fields[edr::field::kOperationType] = "LOGON_FAILURE";
            engine.OnEvent(event);
            if (matched != 1) throw std::runtime_error("logon success rule false positive");
            unsigned soft = 0, high = 0;
            engine.SetAlertCallback([&](const edr::Alert& alert) {
                if (alert.ruleId == "EDR-518") {
                    ++soft;
                    if (alert.action != "log") throw std::runtime_error("unsafe soft DNS rule action");
                }
                if (alert.ruleId == "EDR-519") {
                    ++high;
                    if (alert.action != "alert") throw std::runtime_error("unsafe DNS rule action");
                }
            });
            event = edr::Event{};
            event.type = EDR_EVT_DNS_QUERY;
            event.fields[edr::field::kType] = "DNS_QUERY";
            for (const char* score : {"54", "55", "74", "75", "100", "101"}) {
                event.fields[edr::field::kDnsFailureScore] = score;
                engine.OnEvent(event);
            }
            if (soft != 2 || high != 2) throw std::runtime_error("DNS failure production score bands missing");
            event.fields[edr::field::kType] = "LOGON";
            event.fields[edr::field::kDnsFailureScore] = "75";
            engine.OnEvent(event);
            if (soft != 2 || high != 2) throw std::runtime_error("DNS failure wrong-type false positive");
        }
        DeleteFileA(file);
        std::puts("logon_success config rejection tests passed");
        return 0;
    } catch (const std::exception& error) {
        DeleteFileA(file);
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
