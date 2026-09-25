#include "flow/flow.h"

#include <algorithm>
#include <functional>

namespace delta_nids::flow {
namespace {

bool endpoint_less(const Endpoint& left, const Endpoint& right) {
    if (left.address.family != right.address.family)
        return static_cast<int>(left.address.family) < static_cast<int>(right.address.family);
    if (left.address.bytes != right.address.bytes)
        return left.address.bytes < right.address.bytes;
    return left.port < right.port;
}

std::size_t hash_bytes(const std::vector<std::uint8_t>& bytes) {
    std::size_t result = 0;
    for (const auto byte : bytes) result = result * 131U + byte;
    return result;
}

}  // namespace

std::size_t FlowKeyHash::operator()(const FlowKey& key) const noexcept {
    std::size_t result = static_cast<std::size_t>(key.protocol);
    result = result * 131U + static_cast<std::size_t>(key.first.address.family);
    result = result * 131U + hash_bytes(key.first.address.bytes);
    result = result * 131U + key.first.port;
    result = result * 131U + static_cast<std::size_t>(key.second.address.family);
    result = result * 131U + hash_bytes(key.second.address.bytes);
    result = result * 131U + key.second.port;
    return result;
}

Direction Flow::direction_for(const Endpoint& source) const noexcept {
    if (source == client) return Direction::client_to_server;
    if (source == server) return Direction::server_to_client;
    // A packet outside this flow should never be presented to the flow, but
    // preserve deterministic behavior for malformed callers.
    return Direction::server_to_client;
}

Endpoint source_endpoint(const packet::Packet& packet) {
    return {packet.source, packet.source_port.value_or(0)};
}

Endpoint destination_endpoint(const packet::Packet& packet) {
    return {packet.destination, packet.destination_port.value_or(0)};
}

std::optional<FlowKey> make_key(const packet::Packet& packet) {
    if (packet.source.family == packet::AddressFamily::none ||
        packet.destination.family == packet::AddressFamily::none ||
        packet.transport == packet::TransportProtocol::none)
        return std::nullopt;
    auto source = source_endpoint(packet);
    auto destination = destination_endpoint(packet);
    // TCP/UDP flow identity is bidirectional and uses the established
    // endpoint-port canonicalization expected by the existing flow tests.
    if (packet.source_port && packet.destination_port && packet.source_port.value() > packet.destination_port.value()) {
        std::swap(source, destination);
    } else if (!packet.source_port || !packet.destination_port) {
        if (endpoint_less(destination, source)) std::swap(source, destination);
    }
    return FlowKey{source, destination, packet.transport};
}

}  // namespace delta_nids::flow
