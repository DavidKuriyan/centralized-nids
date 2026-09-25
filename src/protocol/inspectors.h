#pragma once

#include <memory>

#include "protocol/inspector.h"

namespace delta_nids::protocol {

[[nodiscard]] std::unique_ptr<ProtocolInspector> make_http_inspector();
[[nodiscard]] std::unique_ptr<ProtocolInspector> make_dns_inspector();
[[nodiscard]] std::unique_ptr<ProtocolInspector> make_tls_inspector();
[[nodiscard]] std::unique_ptr<ProtocolInspector> make_ssh_inspector();
[[nodiscard]] std::unique_ptr<ProtocolInspector> make_icmp_inspector();
[[nodiscard]] std::unique_ptr<ProtocolInspector> make_generic_tcp_inspector();
[[nodiscard]] std::unique_ptr<ProtocolInspector> make_generic_udp_inspector();

}  // namespace delta_nids::protocol
