#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "flow/flow.h"
#include "packet/packet.h"

namespace delta_nids::protocol {

enum class ServiceConfidence { unknown = 0, suspected = 1, identified = 2, conflicted = 3 };

enum class Service {
    unknown,
    http,
    dns,
    tls,
    ssh,
    ftp,
    smtp,
    smb,
    icmp,
    generic_tcp,
    generic_udp,
};

struct ServiceEvidence {
    Service service = Service::unknown;
    std::string source;
    int confidence = 0;
};

struct ServiceIdentity {
    Service service = Service::unknown;
    ServiceConfidence confidence = ServiceConfidence::unknown;
    int score = 0;
    std::vector<ServiceEvidence> evidence;
};

struct ServiceIdentifierConfig {
    std::size_t maximum_inspection_bytes = 4096;
};

class ServiceIdentifier {
public:
    explicit ServiceIdentifier(ServiceIdentifierConfig config = {});

    [[nodiscard]] ServiceIdentity identify(const flow::Flow& flow,
                                           const packet::Packet& packet,
                                           const std::vector<std::uint8_t>& stream_bytes) const;
};

[[nodiscard]] const char* service_name(Service service) noexcept;
[[nodiscard]] const char* confidence_name(ServiceConfidence confidence) noexcept;

}  // namespace delta_nids::protocol
