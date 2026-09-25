#include "interface/system_interface_provider.h"
#include "platform/platform.h"
#include <cassert>

int main() {
    auto provider = delta_nids::interface::make_system_interface_provider();
    assert(provider != nullptr);
    const auto interfaces = provider->list_interfaces();
#ifdef _WIN32
    assert(delta_nids::platform::current_platform().operating_system == delta_nids::platform::OperatingSystem::windows);
    for (const auto& info : interfaces) {
        assert(!info.stable_id.empty());
        assert(info.capture_backend == delta_nids::interface::CaptureBackend::npcap);
    }
#else
    assert(delta_nids::platform::current_platform().operating_system == delta_nids::platform::OperatingSystem::linux);
#endif
    return 0;
}
