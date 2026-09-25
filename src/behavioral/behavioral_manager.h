#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "behavioral/behavioral_detector.h"

namespace delta_nids::behavioral {

struct BehavioralMetrics {
    std::uint64_t packets_observed = 0;
    std::uint64_t events_generated = 0;
};

class BehavioralManager {
public:
    explicit BehavioralManager(BehavioralConfig config = {});

    [[nodiscard]] std::vector<BehavioralEvent> observe(const packet::Packet& packet,
                                                       const flow::Flow& flow);
    void expire(std::int64_t now);
    void reset();
    [[nodiscard]] const BehavioralMetrics& metrics() const noexcept;

private:
    std::vector<std::unique_ptr<BehavioralDetector>> detectors_;
    BehavioralMetrics metrics_;
};

}  // namespace delta_nids::behavioral
