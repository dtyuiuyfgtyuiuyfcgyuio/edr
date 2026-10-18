#ifndef EDR_AMSI_ENRICHER_H
#define EDR_AMSI_ENRICHER_H

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "event_bus.h"

namespace edr {

class IAmsiPlatform {
public:
    virtual ~IAmsiPlatform() = default;
    virtual HRESULT Initialize(const wchar_t* applicationName,
                               void** context) = 0;
    virtual HRESULT ScanBuffer(void* context, const void* buffer,
                               uint32_t byteLength, const wchar_t* contentName,
                               uint32_t* result) = 0;
    virtual void Uninitialize(void* context) = 0;
};

class AmsiEnricher {
public:
    AmsiEnricher(bool enabled, uint32_t maxContentChars,
                 IAmsiPlatform& platform);
    ~AmsiEnricher();

    AmsiEnricher(const AmsiEnricher&) = delete;
    AmsiEnricher& operator=(const AmsiEnricher&) = delete;

    bool IsEligible(const Event& event) const;
    void EnrichEligible(Event& event);
    void Shutdown();

    bool InitializationFailed() const;
    HRESULT InitializationHresult() const { return m_initResult; }

private:
    bool SelectSource(const Event& event, const std::string*& content,
                      const char*& source) const;

    bool m_enabled;
    uint32_t m_maxContentChars;
    IAmsiPlatform& m_platform;
    void* m_context = nullptr;
    HRESULT m_initResult = S_OK;
};

} // namespace edr

#endif
