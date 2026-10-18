/*
 * dotnet_proxy_exec_detector.h - .NET assembly-registration tool proxy
 * execution detector (T1218.009).
 *
 * Detects abuse of the signed .NET assembly registration utilities
 * regsvcs.exe / regasm.exe as proxy-execution launchers: remote/UNC
 * assemblies, assemblies staged in user-writable directories, /U
 * unregistration of writable/remote assemblies, and assembly arguments
 * that pivot into a script interpreter. Bare regsvcs/regasm stays silent.
 *
 * Scope: ONLY the regsvcs.exe / regasm.exe image basenames (case
 * insensitive). Compiler-class utilities (csc/vbc/jsc/ilasm/msbuild/
 * installutil/Workflow.Compiler) belong to dev_util_proxy_detector; the
 * mavinject/verclsid/syncappvpublishingserver/infdefaultinstall/hnccl set
 * belongs to signed_binary_abuse_detector. Neither is touched here.
 */

#ifndef EDR_DOTNET_PROXY_EXEC_DETECTOR_H
#define EDR_DOTNET_PROXY_EXEC_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include "edr_event.h"
#include "event_bus.h"

namespace edr {

namespace field {
/* Output keys for this detector. The canonical definitions are added to
 * edr::field in event_bus.h during integration; this guarded block keeps
 * the standalone compile probe (which runs before the shared header is
 * wired) buildable, and collapses to nothing once the wiring is present.
 * The integration step must paste the SAME guarded block into event_bus.h
 * so exactly one definition survives either build order. */
#ifndef EDR_FIELD_DOTNET_PROXY_EXEC
#define EDR_FIELD_DOTNET_PROXY_EXEC 1
constexpr const char* kDotnetProxyExecScore = "dotnet_proxy_exec_score";
constexpr const char* kDotnetProxyExecVerdict = "dotnet_proxy_exec_verdict";
constexpr const char* kDotnetProxyExecSignals = "dotnet_proxy_exec_signals";
constexpr const char* kDotnetProxyExecText = "dotnet_proxy_exec_text";
#endif
} // namespace field

class DotnetProxyExecDetector {
public:
    DotnetProxyExecDetector(bool enabled, uint32_t minScore,
                            uint32_t dedupWindowSeconds, size_t stateCapacity);
    void Enrich(Event& event);
    static bool Inspects(uint16_t type);
    size_t StateCount() const { return m_state.size(); }
private:
    struct Finding { uint32_t score=0; const char* signal=""; };
    static bool ClassifyPayload(const std::string& combinedLower,
                                const std::string& imageLower,
                                const std::string& parentLower,
                                Finding* out);
    void Stamp(Event& e, const Finding& f, const std::string& k);
    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_capacity;
    std::unordered_map<std::string,uint64_t> m_state;
    static constexpr uint64_t kFiletimeTicksPerSecond=10000000ULL;
};
} // namespace edr
#endif /* EDR_DOTNET_PROXY_EXEC_DETECTOR_H */
