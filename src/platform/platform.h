#pragma once

#include <string_view>

namespace delta_nids::platform {

enum class OperatingSystem {
    linux,
    windows,
    unsupported,
};

struct PlatformInfo {
    OperatingSystem operating_system;
    std::string_view name;
};

[[nodiscard]] PlatformInfo current_platform() noexcept;

}  // namespace delta_nids::platform
