#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "flow/flow.h"

namespace delta_nids::flow {

struct FlowManagerConfig {
    std::int64_t idle_timeout_seconds = 300;
    std::int64_t lifetime_timeout_seconds = 86400;
    std::size_t maximum_flows = 100000;
    TcpReassemblyConfig tcp_reassembly;
};

struct FlowManagerStatistics {
    std::uint64_t created = 0;
    std::uint64_t expired = 0;
    std::uint64_t evicted = 0;
    std::uint64_t packets = 0;
};

struct ExpiredFlow {
    Flow flow;
    ExpirationReason reason = ExpirationReason::explicit_flush;
};

class FlowManager {
public:
    explicit FlowManager(FlowManagerConfig config = {});

    [[nodiscard]] Flow& process(const packet::Packet& packet);
    [[nodiscard]] std::vector<ExpiredFlow> expire(std::int64_t now);
    [[nodiscard]] std::vector<ExpiredFlow> flush();
    [[nodiscard]] const FlowManagerStatistics& statistics() const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] const Flow* find(const FlowKey& key) const;

private:
    void evict_if_needed(std::vector<ExpiredFlow>& expired);
    void update_tcp_state(Flow& flow, const packet::Packet& packet);

    FlowManagerConfig config_;
    std::uint64_t next_id_ = 1;
    FlowManagerStatistics statistics_;
    std::unordered_map<FlowKey, std::unique_ptr<Flow>, FlowKeyHash> flows_;
};

}  // namespace delta_nids::flow
