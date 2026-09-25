#pragma once

#include <string>
#include <vector>

#include "interface/interface_info.h"

namespace delta_nids::interface {

class InterfaceProvider {
public:
    virtual ~InterfaceProvider() = default;
    virtual std::vector<InterfaceInfo> list_interfaces() const = 0;
    virtual bool validate_interface(const std::string& identifier) const = 0;
};

}  // namespace delta_nids::interface
