#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "flow/flow.h"

namespace delta_nids::protocol {

enum class InspectionStatus { incomplete, complete, malformed, limit_exceeded };
enum class InspectionDirection { client_to_server, server_to_client };

struct InspectionContext {
    std::uint64_t flow_id = 0;
    InspectionDirection direction = InspectionDirection::client_to_server;
    std::size_t maximum_buffered_bytes = 64U * 1024U;
};

struct InspectionResult {
    InspectionStatus status = InspectionStatus::incomplete;
    std::string service;
    std::map<std::string, std::string> fields;
    std::string error;
    std::vector<std::uint8_t> detection_data;
};

class ProtocolInspector {
public:
    virtual ~ProtocolInspector() = default;
    [[nodiscard]] virtual InspectionResult inspect(const InspectionContext& context,
                                                   const std::vector<std::uint8_t>& data) = 0;
    virtual void reset() = 0;
};

}  // namespace delta_nids::protocol
