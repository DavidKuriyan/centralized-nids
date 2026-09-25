#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <memory>

#include "packet/packet.h"
#include "flow/tcp_reassembly.h"

namespace delta_nids::flow {

enum class Direction { client_to_server, server_to_client };
enum class FlowState { new_flow, established, closing, closed, expired };
enum class ExpirationReason { idle_timeout, lifetime_timeout, capacity, explicit_flush };

struct Endpoint {
    packet::IpAddress address;
    std::uint16_t port = 0;

    [[nodiscard]] bool operator==(const Endpoint& other) const noexcept {
        return address == other.address && port == other.port;
    }
};

struct FlowKey {
    Endpoint first;
    Endpoint second;
    packet::TransportProtocol protocol = packet::TransportProtocol::none;

    [[nodiscard]] bool operator==(const FlowKey& other) const noexcept {
        return protocol == other.protocol && first == other.first && second == other.second;
    }
};

struct FlowKeyHash {
    [[nodiscard]] std::size_t operator()(const FlowKey& key) const noexcept;
};

struct FlowStats {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    std::uint64_t client_packets = 0;
    std::uint64_t server_packets = 0;
    std::uint64_t client_bytes = 0;
    std::uint64_t server_bytes = 0;
    std::uint64_t retransmissions = 0;
    std::uint64_t out_of_order = 0;
};

struct Flow {
    std::uint64_t id = 0;
    FlowKey key;
    Endpoint client;
    Endpoint server;
    FlowState state = FlowState::new_flow;
    std::int64_t start_time = 0;
    std::int64_t last_seen = 0;
    std::string service;
    FlowStats stats;
    std::unique_ptr<TcpStreamTracker> client_stream;
    std::unique_ptr<TcpStreamTracker> server_stream;

    [[nodiscard]] Direction direction_for(const Endpoint& source) const noexcept;
};

[[nodiscard]] std::optional<FlowKey> make_key(const packet::Packet& packet);
[[nodiscard]] Endpoint source_endpoint(const packet::Packet& packet);
[[nodiscard]] Endpoint destination_endpoint(const packet::Packet& packet);

}  // namespace delta_nids::flow
