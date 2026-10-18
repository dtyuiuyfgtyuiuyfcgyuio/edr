/*
 * collector_hooks_stub.cpp - Stub for hooks collector when iMonitor SDK/ATL
 * is not available in the build environment.
 */
#include "collector.h"
#include "config.h"

namespace edr {

ICollector* CreateHooksCollector(const Config&) {
    return nullptr;
}

} // namespace edr
