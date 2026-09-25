#pragma once

#include <vector>

#include "detection/detection_buffer.h"
#include "packet/packet.h"
#include "protocol/inspector.h"

namespace delta_nids::detection {

[[nodiscard]] BufferSet build_packet_buffers(const packet::Packet& packet,
                                             std::uint64_t flow_id,
                                             std::size_t maximum_bytes = 64U * 1024U,
                                             const std::vector<std::uint8_t>* reassembled_stream = nullptr,
                                             BufferDirection stream_direction = BufferDirection::not_applicable);

void add_inspection_buffers(BufferSet& buffers,
                            const protocol::InspectionResult& result,
                            BufferDirection direction);

}  // namespace delta_nids::detection
