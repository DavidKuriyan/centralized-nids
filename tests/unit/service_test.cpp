#include <cassert>
#include <cstdint>
#include <vector>

#include "flow/flow.h"
#include "protocol/service_identifier.h"

namespace {

delta_nids::packet::Packet packet(delta_nids::packet::TransportProtocol protocol,
                                  std::uint16_t port,
                                  std::vector<std::uint8_t> payload) {
    delta_nids::packet::Packet value;
    value.transport = protocol;
    value.source = {delta_nids::packet::AddressFamily::ipv4, {192, 0, 2, 1}};
    value.destination = {delta_nids::packet::AddressFamily::ipv4, {198, 51, 100, 2}};
    value.source_port = 40000;
    value.destination_port = port;
    value.payload = std::move(payload);
    value.capture_length = static_cast<std::uint32_t>(value.payload.size());
    return value;
}

delta_nids::flow::Flow flow_for(const delta_nids::packet::Packet& packet) {
    delta_nids::flow::Flow flow;
    flow.client = delta_nids::flow::source_endpoint(packet);
    flow.server = delta_nids::flow::destination_endpoint(packet);
    return flow;
}

}  // namespace

int main() {
    using namespace delta_nids::protocol;
    ServiceIdentifier identifier;

    auto http = packet(delta_nids::packet::TransportProtocol::tcp, 80, {'G', 'E', 'T', ' ', '/'});
    auto http_identity = identifier.identify(flow_for(http), http, {});
    assert(http_identity.service == Service::http);
    assert(http_identity.confidence == ServiceConfidence::identified);

    auto tls = packet(delta_nids::packet::TransportProtocol::tcp, 443, {0x16, 0x03, 0x03});
    auto tls_identity = identifier.identify(flow_for(tls), tls, {});
    assert(tls_identity.service == Service::tls);
    assert(tls_identity.confidence == ServiceConfidence::identified);

    auto generic = packet(delta_nids::packet::TransportProtocol::tcp, 12345, {'x'});
    auto generic_identity = identifier.identify(flow_for(generic), generic, {});
    assert(generic_identity.service == Service::generic_tcp);
    assert(generic_identity.confidence == ServiceConfidence::suspected);

    auto conflicting = packet(delta_nids::packet::TransportProtocol::tcp, 443, {'G', 'E', 'T', ' ', '/'});
    auto conflict_identity = identifier.identify(flow_for(conflicting), conflicting, {});
    assert(conflict_identity.confidence == ServiceConfidence::conflicted);

    return 0;
}
