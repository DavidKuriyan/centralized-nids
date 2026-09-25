#pragma once

#include <string_view>

namespace delta_nids::core {

[[nodiscard]] constexpr std::string_view version() noexcept {
    return "0.1.0";
}

}  // namespace delta_nids::core
