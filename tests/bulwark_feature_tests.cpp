#include <exception>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include "dns_beacon_detector.h"
#include "dns_beacon_detector_tests.h"
#include "obfuscation_detector.h"
#include "obfuscation_detector_tests.h"
#include "rule_engine.h"
#include "alerter.h"

namespace {
#define PORT_CHECK(expr) Check((expr), #expr, __LINE__)
void Check(bool ok, const char* expr, int line) {
    if (!ok) throw std::runtime_error("Bulwark feature test line " +
        std::to_string(line) + ": " + expr);
}
edr::Event Command(const std::string& text, bool script = false) {
    edr::Event event;
    event.type = script ? EDR_EVT_POWERSHELL_SCRIPT : EDR_EVT_PROCESS_START;
    event.ts100ns = 100000000000ULL;
    event.fields[edr::field::kType] = script ? "POWERSHELL_SCRIPT" : "PROCESS_START";
    event.fields[script ? edr::field::kScriptBlockText : edr::field::kCommandLine] = text;
    return event;
}
edr::Event Domain(const std::string& name) {
    edr::Event event;
    event.type = EDR_EVT_DNS_QUERY;
    event.pid = 42;
    event.ts100ns = 100000000000ULL;
    event.processStartTime100ns = 90000000000ULL;
    event.source = "dns_etw";
    event.fields[edr::field::kSource] = event.source;
    event.fields["dns_phase"] = "completed";
    event.fields[edr::field::kType] = "DNS_QUERY";
    event.fields[edr::field::kImage] = "C:\\test.exe";
    event.fields[edr::field::kDnsQueryName] = name;
    return event;
}
bool Has(const edr::Event& event, const char* field) {
    return event.fields.count(field) != 0;
}
std::vector<std::string> Hits(edr::RuleEngine& engine, const edr::Event& event) {
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        if (alert.ruleId == "EDR-411" || alert.ruleId == "EDR-412" ||
            alert.ruleId == "EDR-513" || alert.ruleId == "EDR-514") {
            PORT_CHECK(alert.action == (alert.ruleId == "EDR-513" ||
                alert.ruleId == "EDR-514" ? "log" : "alert"));
            hits.push_back(alert.ruleId);
        }
    });
    engine.OnEvent(event);
    engine.SetAlertCallback({});
    return hits;
}
void Commands(edr::RuleEngine& engine) {
    // Chromium/Electron payloads and ordinary switches are statistical evidence only.
    for (const auto& text : {std::string("browser --gpu-preferences=") + std::string(132, 'A') + "==",
             std::string("tool -encode-file normal.txt"),
             std::string("tool --encryption-key normal.txt"),
             std::string("tool --joiner --replace-file")}) {
        edr::ObfuscationDetector detector(true, 55, 0, 64);
        auto event = Command(text);
        detector.Enrich(event);
        if (Has(event, "obfuscation_score")) {
            PORT_CHECK(event.fields.at("obfuscation_verdict") == "suspicious");
            PORT_CHECK(event.fields.at("obfuscation_hard_signal") == "false");
            PORT_CHECK(Hits(engine, event) == std::vector<std::string>{"EDR-513"});
        } else {
            PORT_CHECK(Hits(engine, event).empty());
        }
    }
    for (const auto& text : {std::string("powershell -c [char]65+[char]66"),
             std::string("powershell -c $x -join '' -replace 'a','b'"),
             std::string("powershell -c I`n`v`o`k`e-Expression $x"),
             std::string("powershell -ENC AAAA"),
             std::string("powershell \"-enc\" AAAA"),
             std::string("pwsh /EncodedCommand AAAA")}) {
        for (bool script : {false, true}) {
            edr::ObfuscationDetector detector(true, 55, 0, 64);
            auto event = Command(text, script);
            detector.Enrich(event);
            PORT_CHECK(Has(event, "obfuscation_score"));
            PORT_CHECK(event.fields.at("obfuscation_hard_signal") == "true");
            PORT_CHECK(Hits(engine, event) ==
                std::vector<std::string>{script ? "EDR-412" : "EDR-411"});
        }
    }
    for (const auto& text : {"powershell -c [char]65", "powershell -c $x -join ','",
             "powershell -c $x -replace 'a','b'", "cmd /c echo one^two"}) {
        edr::ObfuscationDetector detector(true, 55, 0, 64);
        auto event = Command(text);
        detector.Enrich(event);
        PORT_CHECK(!Has(event, "obfuscation_hard_signal") ||
            event.fields.at("obfuscation_hard_signal") == "false");
        const auto hits = Hits(engine, event);
        PORT_CHECK(hits.empty() || hits == std::vector<std::string>{"EDR-513"});
    }
    edr::ObfuscationDetector priority(true, 55, 300, 64);
    const std::string prefix = "tool " + std::string(170, 'A');
    auto soft = Command(prefix);
    priority.Enrich(soft);
    PORT_CHECK(soft.fields.at("obfuscation_hard_signal") == "false");
    auto strong = Command(prefix + " [char]65+[char]66");
    strong.ts100ns += 10000000ULL;
    priority.Enrich(strong);
    PORT_CHECK(strong.fields.at("obfuscation_hard_signal") == "true");
    auto duplicate = strong;
    duplicate.fields.erase("obfuscation_score");
    priority.Enrich(duplicate);
    PORT_CHECK(!Has(duplicate, "obfuscation_score"));
    RunObfuscationDetectorTests();
}
void Domains(edr::RuleEngine& engine) {
    edr::DnsBeaconDetector detector(true, 300, 64, 20, 10);
    for (const auto& name : {"qzxvbnmkjhgfdstrpl.com", "a1b2c3d4f5g6h7j8k9l0.com",
             "WWW.QZXVBNMKJHGFDSTRPL.COM.", "qzxvbnmkjhgfdstrpl.co.uk"}) {
        auto event = Domain(name);
        detector.Enrich(event);
        PORT_CHECK(Has(event, "dns_dga_score"));
        PORT_CHECK(std::stoi(event.fields.at("dns_dga_score")) >= 60);
        PORT_CHECK(!event.fields.at("dns_dga_signals").empty());
        PORT_CHECK(event.fields.at("dns_dga_label").find('.') == std::string::npos);
        PORT_CHECK(Hits(engine, event) == std::vector<std::string>{"EDR-514"});
    }
    for (const auto& name : {"example.com", "service.microsoft.com", "192.168.1.1", "::1",
             "localhost", "123456789012345.com", "xn--bcher-kva.de",
             "qzxvbnmkjhgfdstrpl.cloudfront.net", "qzxvbnmkjhgfdstrpl.example.com",
             "https://qzxvbnmkjhgfdstrpl.com/path", "qzxvbnmkjhgfdstrpl..com",
             "qzxvbnmkjhgfdstrpl_.com", "qzxvbnmkjhgfdstrpl.in-addr.arpa"}) {
        auto event = Domain(name);
        detector.Enrich(event);
        PORT_CHECK(!Has(event, "dns_dga_score"));
        PORT_CHECK(Hits(engine, event).empty());
    }
    for (const auto& name : {std::string(64, 'q') + ".com", std::string(254, 'q')}) {
        auto event = Domain(name);
        detector.Enrich(event);
        PORT_CHECK(!Has(event, "dns_dga_score"));
    }
    auto noImage = Domain("qzxvbnmkjhgfdstrpl.com");
    noImage.fields.erase(edr::field::kImage);
    noImage.pid = 0;
    noImage.processStartTime100ns = 0;
    detector.Enrich(noImage);
    PORT_CHECK(Has(noImage, "dns_dga_score"));
    PORT_CHECK(!Has(noImage, edr::field::kDnsBeaconScore));
    PORT_CHECK(Hits(engine, noImage) == std::vector<std::string>{"EDR-514"});
    auto unrelated = Domain("qzxvbnmkjhgfdstrpl.com");
    unrelated.type = EDR_EVT_NET_CONNECT;
    detector.Enrich(unrelated);
    PORT_CHECK(!Has(unrelated, "dns_dga_score"));
    edr::DnsBeaconDetector disabled(false, 300, 64, 20, 10);
    auto off = Domain("qzxvbnmkjhgfdstrpl.com");
    disabled.Enrich(off);
    PORT_CHECK(!Has(off, "dns_dga_score"));
    for (const auto& value : {"inf", "nan", "4.0junk", "-4", "9"}) {
        edr::DnsBeaconDetector strict(true, 300, 64, 1, 1);
        auto bad = Domain("example.com");
        bad.fields[edr::field::kDnsEntropy] = value;
        strict.Enrich(bad);
        PORT_CHECK(!Has(bad, edr::field::kDnsBeaconScore));
    }
    auto boundary = Domain("example.com");
    boundary.fields["dns_dga_score"] = "59";
    PORT_CHECK(Hits(engine, boundary).empty());
    boundary.fields["dns_dga_score"] = "60";
    PORT_CHECK(Hits(engine, boundary) == std::vector<std::string>{"EDR-514"});
    RunDnsBeaconDetectorTests();
}

std::vector<std::string> BeaconHits(edr::RuleEngine& engine, edr::Event& event,
                                  edr::DnsBeaconDetector& detector) {
    detector.Enrich(event);
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        if (alert.ruleId == "EDR-243" || alert.ruleId == "EDR-244") {
            PORT_CHECK(alert.action == "alert");
            hits.push_back(alert.ruleId);
        }
    });
    engine.OnEvent(event);
    engine.SetAlertCallback({});
    return hits;
}

void BeaconRules(edr::RuleEngine& engine) {
    std::cout << "[dns_beacon_rules] sliding window and production band upgrade\n";
    edr::DnsBeaconDetector detector(true, 30, 64, 10, 5);
    for (uint32_t index = 1; index <= 25; ++index) {
        auto event = Domain("query" + std::to_string(index) + ".example.com");
        event.ts100ns += index;
        event.fields[edr::field::kDnsEntropy] = "4.2";
        const auto hits = BeaconHits(engine, event, detector);
        if (index == 10 || index == 20) {
            PORT_CHECK(hits == std::vector<std::string>{index == 10 ? "EDR-244" : "EDR-243"});
            PORT_CHECK(event.fields.at(edr::field::kDnsBeaconQueryCount) == std::to_string(index));
        } else {
            PORT_CHECK(hits.empty());
        }
    }
    // Traffic stays active, but queries outside (now - window, now] cannot
    // contribute to a second episode. A new ten-query burst must rearm.
    for (uint32_t index = 1; index <= 10; ++index) {
        auto event = Domain("next" + std::to_string(index) + ".example.com");
        event.ts100ns += 31ULL * 10000000ULL + index;
        event.fields[edr::field::kDnsEntropy] = "4.2";
        const auto hits = BeaconHits(engine, event, detector);
        PORT_CHECK(hits == (index == 10 ? std::vector<std::string>{"EDR-244"}
                                        : std::vector<std::string>{}));
    }

    std::cout << "[dns_beacon_rules] process-instance isolation\n";
    edr::DnsBeaconDetector instances(true, 30, 64, 10, 5);
    for (uint32_t index = 1; index <= 10; ++index) {
        auto event = Domain("instance" + std::to_string(index) + ".example.com");
        event.ts100ns += index;
        if (index > 5) event.processStartTime100ns += 10000000ULL;
        event.fields[edr::field::kDnsEntropy] = "4.2";
        PORT_CHECK(BeaconHits(engine, event, instances).empty());
    }
}

void Delivery(edr::RuleEngine& engine) {
    struct Sink : edr::ISink {
        edr::RuleEngine& engine;
        edr::ObfuscationDetector command{true, 55, 0, 64};
        edr::DnsBeaconDetector dns{true, 300, 64, 20, 10};
        explicit Sink(edr::RuleEngine& rules) : engine(rules) {}
        void OnEvent(const edr::Event& original) override {
            edr::Event enriched(original);
            command.Enrich(enriched);
            dns.Enrich(enriched);
            engine.OnEvent(enriched);
        }
    } sink(engine);
    std::vector<std::string> lines;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        if (alert.ruleId == "EDR-411" || alert.ruleId == "EDR-412" ||
            alert.ruleId == "EDR-513" || alert.ruleId == "EDR-514")
            lines.push_back(edr::AlertToJsonLine(alert, false));
    });
    std::mutex mutex;
    std::condition_variable cv;
    size_t completed = 0;
    bool accepted = true;
    edr::EventBus bus(8);
    bus.Start(&sink);
    std::vector<edr::Event> events = {Command("tool [char]65+[char]66"),
        Command("tool [char]67+[char]68", true),
        Command("browser --gpu-preferences=" + std::string(132, 'A')),
        Domain("qzxvbnmkjhgfdstrpl.com")};
    for (auto& event : events) {
        event.onConsumed = [&](bool ok) {
            std::lock_guard<std::mutex> lock(mutex);
            accepted = accepted && ok;
            ++completed;
            cv.notify_one();
        };
        PORT_CHECK(bus.Push(event));
    }
    bool received = false;
    {
        std::unique_lock<std::mutex> lock(mutex);
        received = cv.wait_for(lock, std::chrono::seconds(5), [&] { return completed == 4; });
    }
    bus.Stop();
    engine.SetAlertCallback({});
    PORT_CHECK(received && accepted);
    PORT_CHECK(bus.SnapshotStats().consumerFailed == 0);
    PORT_CHECK(lines.size() == 4);
    PORT_CHECK(lines[0].find("EDR-411") != std::string::npos);
    PORT_CHECK(lines[1].find("EDR-412") != std::string::npos);
    PORT_CHECK(lines[2].find("EDR-513") != std::string::npos);
    PORT_CHECK(lines[3].find("EDR-514") != std::string::npos);
    PORT_CHECK(lines[2].find("obfuscation_hard_signal") != std::string::npos);
    PORT_CHECK(lines[3].find("dns_dga_signals") != std::string::npos);
    PORT_CHECK(lines[3].find("dns_dga_label") != std::string::npos);
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) throw std::runtime_error("production rules path required");
        edr::RuleEngine engine;
        engine.LoadFromFile(argv[1]);
        const std::string group = argc > 2 ? argv[2] : "all";
        if (group != "all" && group != "command" && group != "dns" && group != "beacon")
            throw std::runtime_error("unknown test group: " + group);
        if (group == "all" || group == "command") Commands(engine);
        if (group == "all" || group == "dns") Domains(engine);
        if (group == "all" || group == "dns" || group == "beacon") BeaconRules(engine);
        if (group == "all") Delivery(engine);
        std::cout << "Bulwark feature tests passed: " << group << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
