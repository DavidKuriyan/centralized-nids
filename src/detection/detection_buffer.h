#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace delta_nids::detection {

enum class BufferName {
    raw_packet,
    ethernet,
    ip,
    ipv6,
    tcp,
    udp,
    icmp,
    payload,
    stream,
    http_uri,
    http_method,
    http_headers,
    http_host,
    http_user_agent,
    http_request_body,
    http_response_body,
    dns_query,
    dns_response,
    tls_sni,
    tls_handshake,
};

enum class BufferDirection { not_applicable, client_to_server, server_to_client };

struct BufferProvenance {
    std::uint64_t flow_id = 0;
    BufferDirection direction = BufferDirection::not_applicable;
    std::uint64_t stream_offset = 0;
    bool complete = false;
    bool gap_before = false;
    bool truncated = false;
    std::vector<std::string> transformations;
};

struct DetectionBuffer {
    BufferName name = BufferName::raw_packet;
    std::vector<std::uint8_t> data;
    BufferProvenance provenance;
};

class BufferSet {
public:
    explicit BufferSet(std::size_t maximum_bytes = 64U * 1024U);

    [[nodiscard]] bool add(BufferName name, std::vector<std::uint8_t> data,
                           BufferProvenance provenance = {});
    [[nodiscard]] const DetectionBuffer* get(BufferName name) const noexcept;
    [[nodiscard]] std::size_t total_bytes() const noexcept;
    [[nodiscard]] std::size_t maximum_bytes() const noexcept;
    void clear();

private:
    std::size_t maximum_bytes_;
    std::size_t total_bytes_ = 0;
    std::map<BufferName, DetectionBuffer> buffers_;
};

[[nodiscard]] const char* buffer_name(BufferName name) noexcept;
[[nodiscard]] std::vector<std::uint8_t> normalize_uri(const std::vector<std::uint8_t>& input);
[[nodiscard]] std::vector<std::uint8_t> normalize_header_names(const std::vector<std::uint8_t>& input);

}  // namespace delta_nids::detection
