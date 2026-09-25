#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "detection/detection_buffer.h"
#include "detection/rule.h"
#include "flow/flow.h"

namespace delta_nids::detection {

struct MatchContext {
    const flow::Flow* flow = nullptr;
    BufferDirection direction = BufferDirection::not_applicable;
    const BufferSet* buffers = nullptr;
};

struct RuleMatch {
    const Rule* rule = nullptr;
    std::size_t offset = 0;
    std::vector<std::uint8_t> evidence;
    std::string explanation;
};

class RuleMatcher {
public:
    RuleMatcher() = default;
    explicit RuleMatcher(std::vector<Rule> rules);

    void set_rules(std::vector<Rule> rules);
    [[nodiscard]] const std::vector<Rule>& rules() const noexcept;
    [[nodiscard]] std::vector<RuleMatch> match(const MatchContext& context) const;

private:
    std::vector<Rule> rules_;
};

}  // namespace delta_nids::detection
