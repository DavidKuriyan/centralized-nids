#include "capture/ipv6_fragment_cache.h"

#include <algorithm>
#include <iterator>
#include <numeric>

namespace delta_nids::capture {

std::optional<std::vector<std::uint8_t>> IPv6FragmentCache::add(
    const FragmentKey& key,
    Fragment fragment,
    std::uint8_t& out_next_header) noexcept {

    // Enforce capacity limits before inserting a new group.
    if (groups_.find(key) == groups_.end()) {
        if (groups_.size() >= kMaxGroups) evict_lru();
    }
    if (total_bytes_ + fragment.data.size() > kMaxBytes) {
        // Budget exhausted — discard the arriving fragment silently.
        // The datagram will not reassemble; this is safe (packets are
        // dropped conservatively rather than OOM crashing).
        return std::nullopt;
    }

    auto& group = groups_[key];
    total_bytes_ += fragment.data.size();
    if (fragment.last) group.have_last = true;
    group.last_seen = fragment.arrived;
    group.fragments.push_back(std::move(fragment));

    // Check if we have all fragments: last-fragment arrived AND offsets
    // form a contiguous sequence from 0.
    if (!group.have_last) return std::nullopt;

    // Sort by offset.
    std::sort(group.fragments.begin(), group.fragments.end(),
              [](const Fragment& a, const Fragment& b) {
                  return a.offset < b.offset;
              });

    // Verify contiguity: each fragment must start where the previous one ended.
    std::uint16_t expected_offset = 0;
    for (const auto& frag : group.fragments) {
        if (frag.offset != expected_offset) return std::nullopt;
        expected_offset = static_cast<std::uint16_t>(expected_offset + frag.data.size());
    }

    // Reassemble.
    std::vector<std::uint8_t> payload;
    payload.reserve(expected_offset);
    out_next_header = group.fragments.front().next_header;
    for (const auto& frag : group.fragments) {
        payload.insert(payload.end(), frag.data.begin(), frag.data.end());
    }

    // Free the accounting bytes.
    for (const auto& frag : group.fragments) {
        if (total_bytes_ >= frag.data.size())
            total_bytes_ -= frag.data.size();
    }
    groups_.erase(key);

    return payload;
}

void IPv6FragmentCache::expire(std::int64_t now) noexcept {
    for (auto it = groups_.begin(); it != groups_.end();) {
        if (now - it->second.last_seen >= kTimeoutSeconds) {
            for (const auto& frag : it->second.fragments) {
                if (total_bytes_ >= frag.data.size())
                    total_bytes_ -= frag.data.size();
            }
            it = groups_.erase(it);
        } else {
            ++it;
        }
    }
}

void IPv6FragmentCache::evict_lru() noexcept {
    if (groups_.empty()) return;
    // Find the oldest group by last_seen timestamp.
    auto oldest = std::min_element(groups_.begin(), groups_.end(),
        [](const auto& a, const auto& b) {
            return a.second.last_seen < b.second.last_seen;
        });
    for (const auto& frag : oldest->second.fragments) {
        if (total_bytes_ >= frag.data.size())
            total_bytes_ -= frag.data.size();
    }
    groups_.erase(oldest);
}

}  // namespace delta_nids::capture
