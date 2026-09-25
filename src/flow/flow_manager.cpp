#include "flow/flow_manager.h"

#include "protocol/service_identifier.h"

#include <algorithm>
#include <stdexcept>
#include <iterator>

namespace delta_nids::flow {

FlowManager::FlowManager(FlowManagerConfig config) : config_(config) {
    if (config_.idle_timeout_seconds < 0 || config_.lifetime_timeout_seconds < 0)
        throw std::invalid_argument("flow timeouts cannot be negative");
    if (config_.maximum_flows == 0)
        throw std::invalid_argument("maximum flow count must be greater than zero");
}

Flow& FlowManager::process(const packet::Packet& packet) {
    const auto key = make_key(packet);
    if (!key) throw std::invalid_argument("packet cannot produce a flow key");

    auto found = flows_.find(*key);
    if (found == flows_.end()) {
        auto flow = std::make_unique<Flow>();
        flow->id = next_id_++;
        flow->key = *key;
        flow->client = source_endpoint(packet);
        flow->server = destination_endpoint(packet);
        if (packet.transport == packet::TransportProtocol::tcp) {
            flow->client_stream = std::make_unique<TcpStreamTracker>(
                StreamDirection::client_to_server, config_.tcp_reassembly);
            flow->server_stream = std::make_unique<TcpStreamTracker>(
                StreamDirection::server_to_client, config_.tcp_reassembly);
        }
        flow->start_time = packet.timestamp_seconds;
        flow->last_seen = packet.timestamp_seconds;
        found = flows_.emplace(*key, std::move(flow)).first;
        ++statistics_.created;
    }

    Flow& flow = *found->second;
    const auto flow_id = flow.id;
    flow.last_seen = std::max(flow.last_seen, packet.timestamp_seconds);
    ++flow.stats.packets;
    flow.stats.bytes += packet.capture_length;
    const auto direction = flow.direction_for(source_endpoint(packet));
    if (direction == Direction::client_to_server) {
        ++flow.stats.client_packets;
        flow.stats.client_bytes += packet.capture_length;
    } else {
        ++flow.stats.server_packets;
        flow.stats.server_bytes += packet.capture_length;
    }
    update_tcp_state(flow, packet);
    const auto identity = protocol::ServiceIdentifier().identify(flow, packet, {});
    if (flow.service.empty() || identity.confidence == protocol::ServiceConfidence::identified) {
        flow.service = protocol::service_name(identity.service);
    }
    if (flow.stats.client_packets > 0 && flow.stats.server_packets > 0)
        flow.state = FlowState::established;
    ++statistics_.packets;
    if (flows_.size() > config_.maximum_flows) {
        auto oldest = std::min_element(flows_.begin(), flows_.end(), [&](const auto& left, const auto& right) {
            if (left.second->last_seen != right.second->last_seen)
                return left.second->last_seen < right.second->last_seen;
            return left.second->id < right.second->id;
        });
        if (oldest->second->id == flow_id) {
            auto candidate = std::next(oldest);
            if (candidate == flows_.end()) candidate = flows_.begin();
            oldest = candidate;
        }
        flows_.erase(oldest);
        ++statistics_.evicted;
    }
    return flow;
}

std::vector<ExpiredFlow> FlowManager::expire(std::int64_t now) {
    std::vector<ExpiredFlow> result;
    for (auto iterator = flows_.begin(); iterator != flows_.end();) {
        const auto& flow = *iterator->second;
        const bool lifetime = config_.lifetime_timeout_seconds > 0 &&
            now - flow.start_time >= config_.lifetime_timeout_seconds;
        const bool idle = config_.idle_timeout_seconds > 0 &&
            now - flow.last_seen >= config_.idle_timeout_seconds;
        if (!lifetime && !idle) {
            ++iterator;
            continue;
        }
        const auto reason = lifetime ? ExpirationReason::lifetime_timeout : ExpirationReason::idle_timeout;
        Flow expired = std::move(*iterator->second);
        expired.state = FlowState::expired;
        result.push_back({std::move(expired), reason});
        iterator = flows_.erase(iterator);
        ++statistics_.expired;
    }
    return result;
}

std::vector<ExpiredFlow> FlowManager::flush() {
    std::vector<ExpiredFlow> result;
    result.reserve(flows_.size());
    for (auto& entry : flows_) {
        entry.second->state = FlowState::closed;
        result.push_back({std::move(*entry.second), ExpirationReason::explicit_flush});
    }
    flows_.clear();
    return result;
}

const FlowManagerStatistics& FlowManager::statistics() const noexcept { return statistics_; }
std::size_t FlowManager::size() const noexcept { return flows_.size(); }

const Flow* FlowManager::find(const FlowKey& key) const {
    const auto iterator = flows_.find(key);
    return iterator == flows_.end() ? nullptr : iterator->second.get();
}

void FlowManager::evict_if_needed(std::vector<ExpiredFlow>& expired) {
    while (flows_.size() > config_.maximum_flows) {
        auto oldest = std::min_element(flows_.begin(), flows_.end(), [](const auto& left, const auto& right) {
            if (left.second->last_seen != right.second->last_seen)
                return left.second->last_seen < right.second->last_seen;
            return left.second->id < right.second->id;
        });
        Flow evicted = std::move(*oldest->second);
        evicted.state = FlowState::expired;
        expired.push_back({std::move(evicted), ExpirationReason::capacity});
        flows_.erase(oldest);
        ++statistics_.evicted;
    }
}

void FlowManager::update_tcp_state(Flow& flow, const packet::Packet& packet) {
    if (packet.transport != packet::TransportProtocol::tcp || !packet.tcp) return;
    const bool fin = (packet.tcp->flags & 0x01U) != 0;
    const bool rst = (packet.tcp->flags & 0x04U) != 0;
    if (fin || rst) flow.state = FlowState::closing;
    auto* tracker = flow.direction_for(source_endpoint(packet)) == Direction::client_to_server
        ? flow.client_stream.get() : flow.server_stream.get();
    if (tracker) {
        const auto result = tracker->insert(packet.tcp->sequence, packet.payload, fin, rst);
        if (result.disposition == SegmentDisposition::retransmission) ++flow.stats.retransmissions;
        if (result.disposition == SegmentDisposition::overlap || result.disposition == SegmentDisposition::conflicting_overlap) ++flow.stats.out_of_order;
    }
}

}  // namespace delta_nids::flow
