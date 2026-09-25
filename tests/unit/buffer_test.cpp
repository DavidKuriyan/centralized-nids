#include <cassert>
#include <cstdint>
#include <vector>

#include "detection/buffer_builder.h"

int main() {
    using namespace delta_nids::detection;

    const auto uri = normalize_uri({'%', '2', 'e', 't', 'c', '\\', 'p', 'a', 's', 's'});
    assert(uri == std::vector<std::uint8_t>({'.', 't', 'c', '/', 'p', 'a', 's', 's'}));
    const auto headers = normalize_header_names({'H','o','s','t',':',' ','x','\r','\n','U','s','e','r',':',' ','y'});
    assert(headers[0] == 'h' && headers[9] == 'u');

    BufferSet buffers(5);
    BufferProvenance provenance;
    provenance.flow_id = 42;
    provenance.direction = BufferDirection::client_to_server;
    provenance.complete = true;
    assert(buffers.add(BufferName::http_uri, {'a', 'b'}, provenance));
    const auto* value = buffers.get(BufferName::http_uri);
    assert(value != nullptr);
    assert(value->provenance.flow_id == 42);
    assert(value->provenance.direction == BufferDirection::client_to_server);
    assert(!buffers.add(BufferName::http_host, {'1', '2', '3', '4'}, provenance));
    assert(buffers.total_bytes() == 2);

    delta_nids::packet::Packet packet;
    packet.status = delta_nids::packet::DecodeStatus::valid;
    packet.transport = delta_nids::packet::TransportProtocol::tcp;
    packet.payload = {'G', 'E', 'T'};
    packet.capture_length = 3;
    auto packet_buffers = build_packet_buffers(packet, 99);
    assert(packet_buffers.get(BufferName::payload) != nullptr);
    assert(packet_buffers.get(BufferName::payload)->provenance.flow_id == 99);
    return 0;
}
