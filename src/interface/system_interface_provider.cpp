#include "interface/system_interface_provider.h"

#include <memory>

namespace delta_nids::interface {

#if defined(_WIN32)
std::unique_ptr<InterfaceProvider> make_windows_interface_provider();
#else
std::unique_ptr<InterfaceProvider> make_linux_interface_provider();
#endif

std::unique_ptr<InterfaceProvider> make_system_interface_provider() {
#if defined(_WIN32)
    return make_windows_interface_provider();
#else
    return make_linux_interface_provider();
#endif
}

}  // namespace delta_nids::interface
