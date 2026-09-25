#include "platform/platform.h"

namespace delta_nids::platform {

PlatformInfo current_platform() noexcept {
    return {OperatingSystem::linux, "Linux"};
}

}  // namespace delta_nids::platform
