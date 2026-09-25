#include "interface/interface_provider.h"
#include "telemetry/telemetry.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>

namespace delta_nids::interface {
namespace {

class LinuxInterfaceProvider final : public InterfaceProvider {
public:
    std::vector<InterfaceInfo> list_interfaces() const override {
        std::unordered_map<std::string, InterfaceInfo> interfaces;
        ifaddrs* addresses = nullptr;
        if (getifaddrs(&addresses) != 0) { telemetry::MetricsRegistry::global().increment("interface_enumeration_errors"); return {}; }

        for (auto* current = addresses; current != nullptr; current = current->ifa_next) {
            if (current->ifa_name == nullptr) continue;
            auto& info = interfaces[current->ifa_name];
            info.name = current->ifa_name;
            info.stable_id = current->ifa_name;
            info.description = current->ifa_name;
            info.capture_capable = true;
            info.capture_backend = CaptureBackend::libpcap;
            info.administrative_state = (current->ifa_flags & IFF_UP) ? AdminState::up : AdminState::down;
            info.operational_state = info.administrative_state;
            info.link_state = (current->ifa_flags & IFF_RUNNING) ? LinkState::up : LinkState::unknown;
            info.loopback = (current->ifa_flags & IFF_LOOPBACK) != 0;
            info.type = info.loopback ? InterfaceType::loopback : InterfaceType::unknown;
            info.virtual_or_tunnel = false;

            if (current->ifa_addr == nullptr) continue;
            const auto family = current->ifa_addr->sa_family;
            char buffer[INET6_ADDRSTRLEN] = {};
            if (family == AF_INET) {
                const auto* address = reinterpret_cast<const sockaddr_in*>(current->ifa_addr);
                if (inet_ntop(AF_INET, &address->sin_addr, buffer, sizeof(buffer)))
                    info.ipv4_addresses.emplace_back(buffer);
            } else if (family == AF_INET6) {
                const auto* address = reinterpret_cast<const sockaddr_in6*>(current->ifa_addr);
                if (inet_ntop(AF_INET6, &address->sin6_addr, buffer, sizeof(buffer)))
                    info.ipv6_addresses.emplace_back(buffer);
            }
        }
        freeifaddrs(addresses);

        std::vector<InterfaceInfo> result;
        result.reserve(interfaces.size());
        for (auto& entry : interfaces) result.push_back(std::move(entry.second));
        return result;
    }

    bool validate_interface(const std::string& identifier) const override {
        for (const auto& info : list_interfaces())
            if (info.name == identifier || info.stable_id == identifier) return true;
        return false;
    }
};

}  // namespace

std::unique_ptr<InterfaceProvider> make_linux_interface_provider() {
    return std::make_unique<LinuxInterfaceProvider>();
}

}  // namespace delta_nids::interface
