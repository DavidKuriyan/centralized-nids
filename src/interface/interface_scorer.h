#pragma once

#include <vector>

#include "interface/interface_info.h"

namespace delta_nids::interface {

class InterfaceScorer {
public:
    [[nodiscard]] ScoredInterface score(const InterfaceInfo& info) const;
    [[nodiscard]] std::vector<ScoredInterface> rank(
        const std::vector<InterfaceInfo>& interfaces) const;
};

}  // namespace delta_nids::interface
