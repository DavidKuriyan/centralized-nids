#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "protocol/inspectors.h"
#include "protocol/service_identifier.h"

namespace delta_nids::protocol {

class InspectorManager {
public:
    InspectorManager();

    [[nodiscard]] InspectionResult inspect(Service service,
                                           const InspectionContext& context,
                                           const std::vector<std::uint8_t>& data);
    void reset(Service service);

private:
    std::map<Service, std::unique_ptr<ProtocolInspector>> inspectors_;
};

}  // namespace delta_nids::protocol
