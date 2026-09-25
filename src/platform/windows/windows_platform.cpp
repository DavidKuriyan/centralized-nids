#include "platform/platform.h"

namespace delta_nids::platform {

PlatformInfo current_platform() noexcept {
    return {OperatingSystem::windows, "Windows"};
}

}  // namespace delta_nids::platform
