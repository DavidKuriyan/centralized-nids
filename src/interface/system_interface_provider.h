#pragma once

#include <memory>

#include "interface/interface_provider.h"

namespace delta_nids::interface {

[[nodiscard]] std::unique_ptr<InterfaceProvider> make_system_interface_provider();

}  // namespace delta_nids::interface
