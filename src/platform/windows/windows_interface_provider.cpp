#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#ifdef interface
#undef interface
#endif
#include "interface/interface_provider.h"
#include "telemetry/telemetry.h"

#include <memory>
#include <string>
#include <vector>

namespace delta_nids::interface {
namespace {

class WindowsInterfaceProvider final : public InterfaceProvider {
public:
    std::vector<InterfaceInfo> list_interfaces() const override {
        ULONG size = 0;
        if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW) {
            telemetry::MetricsRegistry::global().increment("interface_enumeration_errors");
            return {};
        }
        std::vector<unsigned char> storage(size);
        auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
        if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &size) != NO_ERROR) {
            telemetry::MetricsRegistry::global().increment("interface_enumeration_errors");
            return {};
        }

        std::vector<InterfaceInfo> result;
        for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
            InterfaceInfo info;
            info.stable_id = adapter->AdapterName ? adapter->AdapterName : "";
            info.name = adapter->FriendlyName ? wide_to_utf8(adapter->FriendlyName) : info.stable_id;
            info.description = adapter->Description ? wide_to_utf8(adapter->Description) : info.name;
            info.capture_capable = true;
            telemetry::MetricsRegistry::global().increment("interfaces_discovered");
            info.capture_backend = CaptureBackend::npcap;
            info.administrative_state = AdminState::up;
            info.operational_state = adapter->OperStatus == IfOperStatusUp ? AdminState::up : AdminState::down;
            info.link_state = adapter->OperStatus == IfOperStatusUp ? LinkState::up : LinkState::down;
            info.loopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
            info.virtual_or_tunnel = adapter->IfType == IF_TYPE_TUNNEL || adapter->IfType == IF_TYPE_PROP_VIRTUAL;
            info.type = info.loopback ? InterfaceType::loopback :
                        info.virtual_or_tunnel ? InterfaceType::virtual_interface : InterfaceType::unknown;

            char address[INET6_ADDRSTRLEN] = {};
            for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
                if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                    auto* value = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
                    if (InetNtopA(AF_INET, &value->sin_addr, address, sizeof(address)))
                        info.ipv4_addresses.emplace_back(address);
                } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
                    auto* value = reinterpret_cast<sockaddr_in6*>(unicast->Address.lpSockaddr);
                    if (InetNtopA(AF_INET6, &value->sin6_addr, address, sizeof(address)))
                        info.ipv6_addresses.emplace_back(address);
                }
            }
            result.push_back(std::move(info));
        }
        return result;
    }

    bool validate_interface(const std::string& identifier) const override {
        for (const auto& info : list_interfaces())
            if (info.name == identifier || info.stable_id == identifier) return true;
        return false;
    }

private:
    static std::string wide_to_utf8(const wchar_t* value) {
        if (!value) return {};
        const int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
        std::string result(static_cast<std::size_t>(size > 0 ? size - 1 : 0), '\0');
        if (size > 1)
            WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), size, nullptr, nullptr);
        return result;
    }
};

}  // namespace

std::unique_ptr<InterfaceProvider> make_windows_interface_provider() {
    return std::make_unique<WindowsInterfaceProvider>();
}

}  // namespace delta_nids::interface
#endif
