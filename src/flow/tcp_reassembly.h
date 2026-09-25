#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace delta_nids::flow {

enum class StreamDirection { client_to_server, server_to_client };
enum class SegmentDisposition { accepted, retransmission, overlap, conflicting_overlap, ignored };

struct TcpReassemblyConfig {
    std::size_t maximum_buffered_bytes = 64U * 1024U * 1024U;
    std::size_t maximum_buffered_segments = 100000;
};

struct ReassembledChunk {
    StreamDirection direction;
    std::uint64_t stream_offset = 0;
    std::vector<std::uint8_t> bytes;
    bool complete = false;
    bool gap_before = false;
    bool end_of_stream = false;
};

struct TcpSegmentResult {
    SegmentDisposition disposition = SegmentDisposition::ignored;
    std::vector<ReassembledChunk> chunks;
    std::size_t buffered_bytes = 0;
    bool fin_seen = false;
    bool rst_seen = false;
};

class TcpStreamTracker {
public:
    explicit TcpStreamTracker(StreamDirection direction, TcpReassemblyConfig config = {});

    [[nodiscard]] TcpSegmentResult insert(std::uint32_t sequence,
                                          const std::vector<std::uint8_t>& payload,
                                          bool fin, bool rst);
    [[nodiscard]] std::vector<ReassembledChunk> flush(bool end_of_stream = true);
    [[nodiscard]] std::size_t buffered_bytes() const noexcept;
    [[nodiscard]] bool fin_seen() const noexcept;
    [[nodiscard]] bool rst_seen() const noexcept;
    [[nodiscard]] std::uint64_t next_sequence() const noexcept;

private:
    struct Segment {
        std::uint32_t sequence;
        std::vector<std::uint8_t> bytes;
        bool fin = false;
        bool rst = false;
    };

    [[nodiscard]] bool contains_exact(std::uint32_t sequence,
                                      const std::vector<std::uint8_t>& payload) const;
    [[nodiscard]] std::vector<ReassembledChunk> drain_contiguous();
    [[nodiscard]] std::vector<ReassembledChunk> drain_all(bool end_of_stream);

    StreamDirection direction_;
    TcpReassemblyConfig config_;
    bool initialized_ = false;
    bool fin_seen_ = false;
    bool rst_seen_ = false;
    std::uint32_t next_sequence_ = 0;
    std::uint64_t stream_offset_ = 0;
    std::size_t buffered_bytes_ = 0;
    std::map<std::uint32_t, Segment> segments_;
};

}  // namespace delta_nids::flow
