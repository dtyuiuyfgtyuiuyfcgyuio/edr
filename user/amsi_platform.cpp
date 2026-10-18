#include "amsi_platform.h"

#include <amsi.h>

namespace edr {

class NativeAmsiPlatform final : public IAmsiPlatform {
public:
    HRESULT Initialize(const wchar_t* applicationName, void** context) override {
        HAMSICONTEXT nativeContext = nullptr;
        const HRESULT result = AmsiInitialize(applicationName, &nativeContext);
        *context = nativeContext;
        return result;
    }

    HRESULT ScanBuffer(void* context, const void* buffer, uint32_t byteLength,
                       const wchar_t* contentName, uint32_t* result) override {
        AMSI_RESULT nativeResult = AMSI_RESULT_CLEAN;
        const HRESULT scanResult = AmsiScanBuffer(
            reinterpret_cast<HAMSICONTEXT>(context),
            const_cast<void*>(buffer),
            byteLength, contentName, nullptr, &nativeResult);
        *result = static_cast<uint32_t>(nativeResult);
        return scanResult;
    }

    void Uninitialize(void* context) override {
        AmsiUninitialize(reinterpret_cast<HAMSICONTEXT>(context));
    }
};

std::unique_ptr<IAmsiPlatform> CreateNativeAmsiPlatform() {
    return std::make_unique<NativeAmsiPlatform>();
}

} // namespace edr
