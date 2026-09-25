#include <cassert>

#include "platform/platform.h"

int main() {
    const auto info = delta_nids::platform::current_platform();
    assert(info.operating_system != delta_nids::platform::OperatingSystem::unsupported);
    assert(!info.name.empty());
    return 0;
}
