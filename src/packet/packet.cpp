#include "packet/packet.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <array>
#include <cstring>

namespace delta_nids::packet {

std::string IpAddress::to_string() const {
    char output[INET6_ADDRSTRLEN] = {};
    const int family_value = family == AddressFamily::ipv4 ? AF_INET :
                             family == AddressFamily::ipv6 ? AF_INET6 : AF_UNSPEC;
    if (family_value == AF_UNSPEC || bytes.size() != (family_value == AF_INET ? 4U : 16U)) return {};
    if (!inet_ntop(family_value, bytes.data(), output, sizeof(output))) return {};
    return output;
}

bool IpAddress::operator==(const IpAddress& other) const noexcept {
    return family == other.family && bytes == other.bytes;
}

}  // namespace delta_nids::packet
