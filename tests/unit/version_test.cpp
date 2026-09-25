#include <cassert>
#include <string_view>

#include "core/version.h"

int main() {
    assert(delta_nids::core::version() == std::string_view{"0.1.0"});
    return 0;
}
