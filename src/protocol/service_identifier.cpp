#include "protocol/service_identifier.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string_view>

namespace delta_nids::protocol {
namespace {

bool starts_with(const std::vector<std::uint8_t>& bytes, std::string_view value) {
    if (bytes.size() < value.size()) return false;
    for (std::size_t index = 0; index < value.size(); ++index)
        if (bytes[index] != static_cast<std::uint8_t>(value[index])) return false;
    return true;
}

void add_evidence(ServiceIdentity& identity, Service service, const char* source, int confidence) {
    identity.evidence.push_back({service, source, confidence});
}

}  // namespace

ServiceIdentifier::ServiceIdentifier(ServiceIdentifierConfig config) {
    if (config.maximum_inspection_bytes == 0)
        throw std::invalid_argument("service inspection limit must be greater than zero");
}

ServiceIdentity ServiceIdentifier::identify(const flow::Flow& flow,
                                            const packet::Packet& packet,
                                            const std::vector<std::uint8_t>& stream_bytes) const {
    ServiceIdentity identity;
    const auto port = packet.destination_port.value_or(flow.server.port);
    const auto& bytes = stream_bytes.empty() ? packet.payload : stream_bytes;

    if (packet.transport == packet::TransportProtocol::icmp ||
        packet.transport == packet::TransportProtocol::icmpv6) {
        identity.service = Service::icmp;
        identity.confidence = ServiceConfidence::identified;
        identity.score = 100;
        add_evidence(identity, Service::icmp, "ICMP transport", 100);
        return identity;
    }

    if (packet.transport == packet::TransportProtocol::tcp) {
        if (port == 80 || port == 8080 || port == 8000) add_evidence(identity, Service::http, "HTTP port hint", 25);
        if (port == 443 || port == 8443) add_evidence(identity, Service::tls, "TLS port hint", 25);
        if (port == 22) add_evidence(identity, Service::ssh, "SSH port hint", 25);
        if (port == 21) add_evidence(identity, Service::ftp, "FTP port hint", 25);
        if (port == 25 || port == 587 || port == 465) add_evidence(identity, Service::smtp, "SMTP port hint", 25);
        if (port == 445 || port == 139) add_evidence(identity, Service::smb, "SMB port hint", 25);

        if (starts_with(bytes, "GET ") || starts_with(bytes, "POST ") ||
            starts_with(bytes, "PUT ") || starts_with(bytes, "HEAD ") ||
            starts_with(bytes, "HTTP/1.")) {
            add_evidence(identity, Service::http, "HTTP message signature", 80);
        }
        if (bytes.size() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 && bytes[2] <= 0x04)
            add_evidence(identity, Service::tls, "TLS record signature", 80);
        if (starts_with(bytes, "SSH-")) add_evidence(identity, Service::ssh, "SSH banner signature", 80);
        if (starts_with(bytes, "220 ") || starts_with(bytes, "EHLO ") || starts_with(bytes, "HELO "))
            add_evidence(identity, Service::smtp, "SMTP message signature", 70);
        if (starts_with(bytes, "USER ") || starts_with(bytes, "220-"))
            add_evidence(identity, Service::ftp, "FTP message signature", 60);
    } else if (packet.transport == packet::TransportProtocol::udp) {
        if (port == 53) add_evidence(identity, Service::dns, "DNS port hint", 25);
        if (bytes.size() >= 12)
            add_evidence(identity, Service::dns, "DNS header shape", 55);
    }

    for (const auto& evidence : identity.evidence) {
        if (evidence.confidence > identity.score) {
            identity.score = evidence.confidence;
            identity.service = evidence.service;
        }
    }
    const auto has_strong_conflict = [&identity] {
        for (const auto& left : identity.evidence)
            for (const auto& right : identity.evidence)
                if (left.service != right.service &&
                    ((left.confidence >= 70 && right.confidence >= 25) ||
                     (right.confidence >= 70 && left.confidence >= 25)))
                    return true;
        return false;
    };
    const bool strong_conflict = has_strong_conflict();
    if (identity.evidence.empty()) {
        identity.service = packet.transport == packet::TransportProtocol::tcp ? Service::generic_tcp : Service::generic_udp;
        identity.confidence = ServiceConfidence::suspected;
        identity.score = 10;
        add_evidence(identity, identity.service, "transport fallback", 10);
    } else if (strong_conflict) {
        identity.confidence = ServiceConfidence::conflicted;
    } else if (identity.score >= 70) {
        identity.confidence = ServiceConfidence::identified;
    } else {
        identity.confidence = ServiceConfidence::suspected;
    }

    Service highest = Service::unknown;
    int highest_score = -1;
    for (const auto& evidence : identity.evidence) {
        if (evidence.confidence > highest_score) {
            highest = evidence.service;
            highest_score = evidence.confidence;
        }
    }
    if (!strong_conflict) {
        for (const auto& evidence : identity.evidence) {
            if (evidence.service != highest && evidence.confidence >= 70) {
                identity.confidence = ServiceConfidence::conflicted;
                break;
            }
        }
    }
    return identity;
}

const char* service_name(Service service) noexcept {
    switch (service) {
        case Service::http: return "HTTP";
        case Service::dns: return "DNS";
        case Service::tls: return "TLS";
        case Service::ssh: return "SSH";
        case Service::ftp: return "FTP";
        case Service::smtp: return "SMTP";
        case Service::smb: return "SMB";
        case Service::icmp: return "ICMP";
        case Service::generic_tcp: return "generic_tcp";
        case Service::generic_udp: return "generic_udp";
        default: return "unknown";
    }
}

const char* confidence_name(ServiceConfidence confidence) noexcept {
    switch (confidence) {
        case ServiceConfidence::suspected: return "suspected";
        case ServiceConfidence::identified: return "identified";
        case ServiceConfidence::conflicted: return "conflicted";
        default: return "unknown";
    }
}

}  // namespace delta_nids::protocol
