#include "interface/interface_manager.h"

#include <utility>

namespace delta_nids::interface {

InterfaceManager::InterfaceManager(std::unique_ptr<InterfaceProvider> provider)
    : provider_(std::move(provider)) {}

std::vector<ScoredInterface> InterfaceManager::list_interfaces() const {
    return scorer_.rank(provider_->list_interfaces());
}

SelectionResult InterfaceManager::select_auto() const {
    SelectionResult result;
    result.mode = CaptureMode::auto_select;
    result.candidates = list_interfaces();
    if (result.candidates.empty()) {
        result.error = "no network interfaces were discovered";
        return result;
    }
    for (const auto& candidate : result.candidates) {
        if (candidate.suitable) {
            result.interface = candidate;
            result.selected = true;
            return result;
        }
    }
    result.error = "no suitable capture interface was found";
    return result;
}

SelectionResult InterfaceManager::select_explicit(const std::string& identifier) const {
    SelectionResult result;
    result.mode = CaptureMode::explicit_interface;
    result.candidates = list_interfaces();
    for (const auto& candidate : result.candidates) {
        if (candidate.info.name == identifier || candidate.info.stable_id == identifier) {
            result.interface = candidate;
            result.selected = candidate.suitable;
            if (!result.selected) result.error = "explicit interface is not suitable for capture";
            return result;
        }
    }
    result.error = "interface not found: " + identifier;
    return result;
}

bool InterfaceManager::validate_interface(const std::string& identifier) const {
    return select_explicit(identifier).selected;
}

}  // namespace delta_nids::interface
