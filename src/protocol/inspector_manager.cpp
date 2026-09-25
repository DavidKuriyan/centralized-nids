#include "protocol/inspector_manager.h"

namespace delta_nids::protocol {

InspectorManager::InspectorManager() {
    inspectors_.emplace(Service::http, make_http_inspector());
    inspectors_.emplace(Service::dns, make_dns_inspector());
    inspectors_.emplace(Service::tls, make_tls_inspector());
    inspectors_.emplace(Service::ssh, make_ssh_inspector());
    inspectors_.emplace(Service::icmp, make_icmp_inspector());
    inspectors_.emplace(Service::generic_tcp, make_generic_tcp_inspector());
    inspectors_.emplace(Service::generic_udp, make_generic_udp_inspector());
}

InspectionResult InspectorManager::inspect(Service service,
                                            const InspectionContext& context,
                                            const std::vector<std::uint8_t>& data) {
    const auto iterator = inspectors_.find(service);
    if (iterator == inspectors_.end()) {
        InspectionResult result;
        result.service = service_name(service);
        result.status = InspectionStatus::malformed;
        result.error = "no inspector registered for service";
        return result;
    }
    return iterator->second->inspect(context, data);
}

void InspectorManager::reset(Service service) {
    const auto iterator = inspectors_.find(service);
    if (iterator != inspectors_.end()) iterator->second->reset();
}

}  // namespace delta_nids::protocol
