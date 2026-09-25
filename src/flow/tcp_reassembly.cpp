#include "flow/tcp_reassembly.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace delta_nids::flow {

TcpStreamTracker::TcpStreamTracker(StreamDirection direction, TcpReassemblyConfig config)
    : direction_(direction), config_(config) {
    if (config_.maximum_buffered_bytes == 0 || config_.maximum_buffered_segments == 0)
        throw std::invalid_argument("TCP reassembly limits must be greater than zero");
}

TcpSegmentResult TcpStreamTracker::insert(std::uint32_t sequence,
                                          const std::vector<std::uint8_t>& payload,
                                          bool fin, bool rst) {
    TcpSegmentResult result;
    result.buffered_bytes = buffered_bytes_;
    result.fin_seen = fin_seen_;
    result.rst_seen = rst_seen_;
    if (payload.empty() && !fin && !rst) return result;

    if (rst) {
        rst_seen_ = true;
        result.rst_seen = true;
    }
    if (fin) fin_seen_ = true;
    if (payload.empty()) {
        result.disposition = SegmentDisposition::accepted;
        result.chunks = drain_contiguous();
        result.fin_seen = fin_seen_;
        return result;
    }

    if (!initialized_) {
        initialized_ = true;
        next_sequence_ = sequence;
    }

    const std::uint64_t end = static_cast<std::uint64_t>(sequence) + payload.size();
    const std::uint64_t next = next_sequence_;
    if (end <= next) {
        result.disposition = SegmentDisposition::retransmission;
        result.chunks = drain_contiguous();
        result.buffered_bytes = buffered_bytes_;
        return result;
    }

    std::uint32_t insert_sequence = sequence;
    std::vector<std::uint8_t> insert_payload = payload;
    if (static_cast<std::uint64_t>(sequence) < next) {
        const auto trim = static_cast<std::size_t>(next - sequence);
        insert_sequence = next_sequence_;
        insert_payload.assign(payload.begin() + static_cast<std::ptrdiff_t>(trim), payload.end());
        result.disposition = SegmentDisposition::overlap;
    } else {
        result.disposition = SegmentDisposition::accepted;
    }

    for (const auto& entry : segments_) {
        const auto existing_start = entry.first;
        const auto existing_end = static_cast<std::uint64_t>(existing_start) + entry.second.bytes.size();
        const auto new_start = insert_sequence;
        const auto new_end = static_cast<std::uint64_t>(insert_sequence) + insert_payload.size();
        if (new_end <= existing_start || new_start >= existing_end) continue;
        const auto overlap_start = std::max<std::uint64_t>(new_start, existing_start);
        const auto overlap_end = std::min(new_end, existing_end);
        for (std::uint64_t position = overlap_start; position < overlap_end; ++position) {
            const auto new_index = static_cast<std::size_t>(position - new_start);
            const auto old_index = static_cast<std::size_t>(position - existing_start);
            if (insert_payload[new_index] != entry.second.bytes[old_index]) {
                result.disposition = SegmentDisposition::conflicting_overlap;
                break;
            }
        }
        if (result.disposition == SegmentDisposition::conflicting_overlap) break;
    }

    if (result.disposition == SegmentDisposition::conflicting_overlap) {
        result.buffered_bytes = buffered_bytes_;
        return result;
    }

    // Preserve the first-seen bytes for an overlap. Only non-overlapping
    // portions are inserted, making retransmission behavior deterministic.
    std::vector<std::uint8_t> uncovered;
    uncovered.reserve(insert_payload.size());
    std::uint32_t uncovered_sequence = insert_sequence;
    for (std::size_t index = 0; index < insert_payload.size(); ++index) {
        const auto position = static_cast<std::uint64_t>(insert_sequence) + index;
        bool already_present = false;
        for (const auto& entry : segments_) {
            const auto start = entry.first;
            const auto end_segment = static_cast<std::uint64_t>(start) + entry.second.bytes.size();
            if (position >= start && position < end_segment) {
                already_present = true;
                break;
            }
        }
        if (!already_present) {
            if (uncovered.empty()) uncovered_sequence = static_cast<std::uint32_t>(position);
            uncovered.push_back(insert_payload[index]);
        } else if (!uncovered.empty()) {
            segments_.emplace(uncovered_sequence, Segment{uncovered_sequence, std::move(uncovered)});
            buffered_bytes_ += segments_.find(uncovered_sequence)->second.bytes.size();
            uncovered.clear();
        }
    }
    if (!uncovered.empty()) {
        segments_.emplace(uncovered_sequence, Segment{uncovered_sequence, std::move(uncovered)});
        buffered_bytes_ += segments_.find(uncovered_sequence)->second.bytes.size();
    }

    while (buffered_bytes_ > config_.maximum_buffered_bytes || segments_.size() > config_.maximum_buffered_segments) {
        auto last = std::prev(segments_.end());
        buffered_bytes_ -= last->second.bytes.size();
        segments_.erase(last);
    }

    result.chunks = drain_contiguous();
    result.buffered_bytes = buffered_bytes_;
    result.fin_seen = fin_seen_;
    result.rst_seen = rst_seen_;
    return result;
}

std::vector<ReassembledChunk> TcpStreamTracker::drain_contiguous() {
    std::vector<ReassembledChunk> result;
    if (!initialized_) return result;
    bool gap_before = false;
    while (!segments_.empty()) {
        auto iterator = segments_.begin();
        if (iterator->first != next_sequence_) {
            gap_before = true;
            break;
        }
        auto bytes = std::move(iterator->second.bytes);
        buffered_bytes_ -= bytes.size();
        segments_.erase(iterator);
        const auto offset = stream_offset_;
        stream_offset_ += bytes.size();
        next_sequence_ += static_cast<std::uint32_t>(bytes.size());
        result.push_back({direction_, offset, std::move(bytes), true, gap_before, false});
        gap_before = false;
    }
    return result;
}

std::vector<ReassembledChunk> TcpStreamTracker::drain_all(bool end_of_stream) {
    std::vector<ReassembledChunk> result;
    bool gap_before = false;
    for (auto& entry : segments_) {
        if (entry.first != next_sequence_) gap_before = true;
        auto bytes = std::move(entry.second.bytes);
        const auto offset = stream_offset_;
        stream_offset_ += bytes.size();
        next_sequence_ = entry.first + static_cast<std::uint32_t>(bytes.size());
        result.push_back({direction_, offset, std::move(bytes), !gap_before, gap_before, false});
        gap_before = false;
    }
    segments_.clear();
    buffered_bytes_ = 0;
    if (!result.empty() && end_of_stream) result.back().end_of_stream = true;
    return result;
}

std::vector<ReassembledChunk> TcpStreamTracker::flush(bool end_of_stream) {
    return drain_all(end_of_stream);
}

std::size_t TcpStreamTracker::buffered_bytes() const noexcept { return buffered_bytes_; }
bool TcpStreamTracker::fin_seen() const noexcept { return fin_seen_; }
bool TcpStreamTracker::rst_seen() const noexcept { return rst_seen_; }
std::uint64_t TcpStreamTracker::next_sequence() const noexcept { return next_sequence_; }

}  // namespace delta_nids::flow
