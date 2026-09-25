#pragma once

#include <memory>
#include <string>
#include <vector>

#include "interface/interface_provider.h"
#include "interface/interface_scorer.h"

namespace delta_nids::interface {

class InterfaceManager {
public:
    explicit InterfaceManager(std::unique_ptr<InterfaceProvider> provider);

    [[nodiscard]] std::vector<ScoredInterface> list_interfaces() const;
    [[nodiscard]] SelectionResult select_auto() const;
    [[nodiscard]] SelectionResult select_explicit(const std::string& identifier) const;
    [[nodiscard]] bool validate_interface(const std::string& identifier) const;

private:
    std::unique_ptr<InterfaceProvider> provider_;
    InterfaceScorer scorer_;
};

}  // namespace delta_nids::interface
