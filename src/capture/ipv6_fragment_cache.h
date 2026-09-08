// ipv6_fragment_cache.h  —  Delta-NIDS bounded IPv6 fragment reassembly cache
//
// SPAN environments can deliver all fragments of a fragmented IPv6 datagram
// because the mirror copies every frame.  Without reassembly, the first
// fragment (which carries the transport header) would be processed normally,
// but subsequent fragments (which lack a transport header) would be classified
// as "other" protocol and miss higher-level inspection.
//
// This cache associates fragments by (src, dst, fragment_id), buffers them,
// and emits a complete reassembled CapturedPacket when all pieces arrive.
// Hard limits prevent memory exhaustion:
//   - Maximum pending fragment groups : kMaxGroups
//   - Maximum total buffered bytes     : kMaxBytes
//   - Idle timeout per group           : kTimeoutSeconds
#pragma once

#include "capture/packet_capture.h"

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace delta_nids::capture {

// Fragment group key: uniquely identifies a fragmented IPv6 datagram.
struct FragmentKey {
    std::vector<std::uint8_t> src;  // 16-byte IPv6 address
    std::vector<std::uint8_t> dst;  // 16-byte IPv6 address
    std::uint32_t             id;   // Fragment Identification field

    bool operator<(const FragmentKey& other) const noexcept {
        if (src != other.src) return src < other.src;
        if (dst != other.dst) return dst < other.dst;
        return id < other.id;
    }
};

// A single fragment stored in the cache.
struct Fragment {
    std::uint16_t             offset;       // in bytes (already × 8)
    bool                      last;         // M-bit == 0  → last fragment
    std::vector<std::uint8_t> data;         // fragment payload bytes
    std::uint8_t              next_header;  // transport protocol
    std::int64_t              arrived;      // capture timestamp (seconds)
};

class IPv6FragmentCache {
public:
    // Configurable limits.
    static constexpr std::size_t kMaxGroups        = 1024;
    static constexpr std::size_t kMaxBytes         = 32 * 1024 * 1024; // 32 MiB
    static constexpr std::int64_t kTimeoutSeconds  = 30;

    // Attempt to reassemble a fragment.
    // Returns the fully reassembled payload bytes (transport-layer data) when
    // all fragments of the datagram have arrived, or std::nullopt otherwise.
    //
    // Parameters:
    //   key      - fragment group identifier
    //   fragment - the arriving fragment
    //   out_next_header - filled with the final transport protocol on success
    std::optional<std::vector<std::uint8_t>> add(
        const FragmentKey& key,
        Fragment fragment,
        std::uint8_t& out_next_header) noexcept;

    // Remove expired groups older than kTimeoutSeconds.
    // Call periodically (e.g. every few seconds) from the capture thread.
    void expire(std::int64_t now) noexcept;

    [[nodiscard]] std::size_t group_count()  const noexcept { return groups_.size(); }
    [[nodiscard]] std::size_t buffered_bytes() const noexcept { return total_bytes_; }

private:
    struct Group {
        std::vector<Fragment> fragments;
        bool                  have_last = false;
        std::int64_t          last_seen = 0;
    };

    void evict_lru() noexcept;

    std::map<FragmentKey, Group> groups_;
    std::size_t total_bytes_ = 0;
};

}  // namespace delta_nids::capture
