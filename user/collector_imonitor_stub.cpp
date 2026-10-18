#include "collector.h"

namespace edr {

class IMonitorUnavailableCollector : public ICollector {
public:
    bool Start(EventBus*) override { return false; }
    void Stop() override {}
};

ICollector* CreateIMonitorCollector(bool enableProcessOpen,
                                    bool enableRemoteThread,
                                    bool enableCredentialMonitor,
                                    bool enableInjectionDeep) {
    (void)enableProcessOpen;
    (void)enableRemoteThread;
    (void)enableCredentialMonitor;
    (void)enableInjectionDeep;
    return new IMonitorUnavailableCollector();
}

} // namespace edr
