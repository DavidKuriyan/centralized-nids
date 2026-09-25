#include "detection/detection_buffer.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace delta_nids::detection {

BufferSet::BufferSet(std::size_t maximum_bytes) : maximum_bytes_(maximum_bytes) {
    if (maximum_bytes_ == 0) throw std::invalid_argument("detection buffer limit must be greater than zero");
}

bool BufferSet::add(BufferName name, std::vector<std::uint8_t> data, BufferProvenance provenance) {
    const auto previous = buffers_.find(name);
    const auto previous_size = previous == buffers_.end() ? 0U : previous->second.data.size();
    if (data.size() - std::min(data.size(), previous_size) > maximum_bytes_ - std::min(maximum_bytes_, total_bytes_)) {
        provenance.truncated = true;
        return false;
    }
    total_bytes_ -= previous_size;
    total_bytes_ += data.size();
    buffers_[name] = DetectionBuffer{name, std::move(data), std::move(provenance)};
    return true;
}

const DetectionBuffer* BufferSet::get(BufferName name) const noexcept {
    const auto iterator = buffers_.find(name);
    return iterator == buffers_.end() ? nullptr : &iterator->second;
}

std::size_t BufferSet::total_bytes() const noexcept { return total_bytes_; }
std::size_t BufferSet::maximum_bytes() const noexcept { return maximum_bytes_; }
void BufferSet::clear() { buffers_.clear(); total_bytes_ = 0; }

const char* buffer_name(BufferName name) noexcept {
    switch (name) {
        case BufferName::raw_packet: return "raw_packet";
        case BufferName::ethernet: return "ethernet";
        case BufferName::ip: return "ip";
        case BufferName::ipv6: return "ipv6";
        case BufferName::tcp: return "tcp";
        case BufferName::udp: return "udp";
        case BufferName::icmp: return "icmp";
        case BufferName::payload: return "payload";
        case BufferName::stream: return "stream";
        case BufferName::http_uri: return "http_uri";
        case BufferName::http_method: return "http_method";
        case BufferName::http_headers: return "http_headers";
        case BufferName::http_host: return "http_host";
        case BufferName::http_user_agent: return "http_user_agent";
        case BufferName::http_request_body: return "http_request_body";
        case BufferName::http_response_body: return "http_response_body";
        case BufferName::dns_query: return "dns_query";
        case BufferName::dns_response: return "dns_response";
        case BufferName::tls_sni: return "tls_sni";
        case BufferName::tls_handshake: return "tls_handshake";
    }
    return "unknown";
}

std::vector<std::uint8_t> normalize_uri(const std::vector<std::uint8_t>& input) {
    std::vector<std::uint8_t> result;
    result.reserve(input.size());
    for (std::size_t index = 0; index < input.size(); ++index) {
        if (input[index] == '%' && index + 2 < input.size() &&
            std::isxdigit(input[index + 1]) && std::isxdigit(input[index + 2])) {
            const auto hex = [](std::uint8_t value) -> std::uint8_t {
                if (value >= '0' && value <= '9') return value - '0';
                if (value >= 'a' && value <= 'f') return value - 'a' + 10;
                return value - 'A' + 10;
            };
            result.push_back(static_cast<std::uint8_t>((hex(input[index + 1]) << 4) | hex(input[index + 2])));
            index += 2;
        } else if (input[index] == '\\') {
            result.push_back('/');
        } else {
            result.push_back(input[index]);
        }
    }
    return result;
}

std::vector<std::uint8_t> normalize_header_names(const std::vector<std::uint8_t>& input) {
    std::vector<std::uint8_t> result = input;
    bool name = true;
    for (auto& value : result) {
        if (name && value >= 'A' && value <= 'Z') value = static_cast<std::uint8_t>(value - 'A' + 'a');
        if (value == ':') name = false;
        if (value == '\r' || value == '\n') name = true;
    }
    return result;
}

}  // namespace delta_nids::detection
