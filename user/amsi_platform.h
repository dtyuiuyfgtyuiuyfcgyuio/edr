#ifndef EDR_AMSI_PLATFORM_H
#define EDR_AMSI_PLATFORM_H

#include <memory>

#include "amsi_enricher.h"

namespace edr {

std::unique_ptr<IAmsiPlatform> CreateNativeAmsiPlatform();

} // namespace edr

#endif
