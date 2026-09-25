#include "detection/buffer_builder.h"

#include <string>

namespace delta_nids::detection {
namespace {

std::vector<std::uint8_t> text(const std::string& value) {
    return {value.begin(), value.end()};
}

void add_field(BufferSet& buffers, BufferName name, const protocol::InspectionResult& result,
               const char* field, BufferDirection direction) {
    const auto iterator = result.fields.find(field);
    if (iterator == result.fields.end()) return;
    BufferProvenance provenance;
    provenance.direction = direction;
    provenance.complete = result.status == protocol::InspectionStatus::complete;
    provenance.transformations.push_back("protocol_field");
    (void)buffers.add(name, text(iterator->second), std::move(provenance));
}

}  // namespace

BufferSet build_packet_buffers(const packet::Packet& packet, std::uint64_t flow_id,
                               std::size_t maximum_bytes,
                               const std::vector<std::uint8_t>* reassembled_stream,
                               BufferDirection stream_direction) {
    BufferSet buffers(maximum_bytes);
    BufferProvenance provenance;
    provenance.flow_id = flow_id;
    provenance.complete = packet.status == packet::DecodeStatus::valid;
    (void)buffers.add(BufferName::payload, packet.payload, provenance);
    if (reassembled_stream != nullptr && !reassembled_stream->empty()) {
        auto stream_provenance = provenance;
        stream_provenance.direction = stream_direction;
        stream_provenance.complete = false;
        stream_provenance.transformations.push_back("tcp_reassembly");
        (void)buffers.add(BufferName::stream, *reassembled_stream, stream_provenance);
    }
    if (packet.transport == packet::TransportProtocol::tcp) {
        (void)buffers.add(BufferName::tcp, {}, provenance);
    } else if (packet.transport == packet::TransportProtocol::udp) {
        (void)buffers.add(BufferName::udp, {}, provenance);
    } else if (packet.transport == packet::TransportProtocol::icmp ||
               packet.transport == packet::TransportProtocol::icmpv6) {
        (void)buffers.add(BufferName::icmp, {}, provenance);
    }
    return buffers;
}

void add_inspection_buffers(BufferSet& buffers, const protocol::InspectionResult& result,
                            BufferDirection direction) {
    const auto provenance = BufferProvenance{0, direction, 0,
        result.status == protocol::InspectionStatus::complete,
        false, result.status == protocol::InspectionStatus::limit_exceeded,
        {"inspector_result"}};
    if (!result.detection_data.empty())
        (void)buffers.add(BufferName::stream, result.detection_data, provenance);

    if (result.service == "HTTP") {
        add_field(buffers, BufferName::http_uri, result, "normalized_uri", direction);
        add_field(buffers, BufferName::http_method, result, "http_method", direction);
        add_field(buffers, BufferName::http_host, result, "http_host", direction);
        add_field(buffers, BufferName::http_user_agent, result, "http_user_agent", direction);
        add_field(buffers, BufferName::http_headers, result, "header.host", direction);
    } else if (result.service == "DNS") {
        add_field(buffers, BufferName::dns_query, result, "query_name", direction);
        if (result.fields.find("message_type") != result.fields.end() &&
            result.fields.at("message_type") == "response")
            (void)buffers.add(BufferName::dns_response, result.detection_data, provenance);
    } else if (result.service == "TLS") {
        if (result.fields.find("handshake_type") != result.fields.end())
            (void)buffers.add(BufferName::tls_handshake, result.detection_data, provenance);
    }
}

}  // namespace delta_nids::detection
