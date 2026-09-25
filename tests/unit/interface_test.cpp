#include <cassert>
#include <memory>
#include <string>
#include <vector>

#include "interface/interface_manager.h"

namespace {

using delta_nids::interface::AdminState;
using delta_nids::interface::CaptureBackend;
using delta_nids::interface::InterfaceInfo;
using delta_nids::interface::InterfaceManager;
using delta_nids::interface::InterfaceProvider;
using delta_nids::interface::InterfaceType;
using delta_nids::interface::LinkState;

class FakeProvider final : public InterfaceProvider {
public:
    std::vector<InterfaceInfo> list_interfaces() const override { return interfaces; }
    bool validate_interface(const std::string& identifier) const override {
        for (const auto& info : interfaces)
            if (info.name == identifier || info.stable_id == identifier) return true;
        return false;
    }
    std::vector<InterfaceInfo> interfaces;
};

InterfaceInfo usable(std::string id, bool route) {
    InterfaceInfo info;
    info.stable_id = std::move(id);
    info.name = info.stable_id;
    info.ipv4_addresses = {"192.0.2.10"};
    info.administrative_state = AdminState::up;
    info.operational_state = AdminState::up;
    info.link_state = LinkState::up;
    info.type = InterfaceType::ethernet;
    info.capture_capable = true;
    info.capture_backend = CaptureBackend::libpcap;
    info.default_route = route;
    return info;
}

}  // namespace

int main() {
    auto provider = std::make_unique<FakeProvider>();
    provider->interfaces = {usable("secondary", false), usable("primary", true)};
    InterfaceManager manager(std::move(provider));

    const auto automatic = manager.select_auto();
    assert(automatic.selected);
    assert(automatic.interface.info.name == "primary");
    assert(automatic.interface.reason == "active default-route interface");

    const auto explicit_selection = manager.select_explicit("secondary");
    assert(explicit_selection.selected);
    assert(explicit_selection.interface.info.name == "secondary");
    assert(manager.validate_interface("primary"));
    assert(!manager.validate_interface("missing"));

    return 0;
}
