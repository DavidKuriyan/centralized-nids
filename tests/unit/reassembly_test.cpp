#include <cassert>
#include <cstdint>
#include <vector>

#include "flow/tcp_reassembly.h"

int main() {
    using namespace delta_nids::flow;
    TcpStreamTracker tracker(StreamDirection::client_to_server, {64, 8});

    auto first = tracker.insert(100, {'a', 'b'}, false, false);
    assert(first.disposition == SegmentDisposition::accepted);
    assert(first.chunks.size() == 1);
    assert(first.chunks[0].bytes == std::vector<std::uint8_t>({'a', 'b'}));
    assert(first.chunks[0].stream_offset == 0);

    auto out_of_order = tracker.insert(104, {'e', 'f'}, false, false);
    assert(out_of_order.chunks.empty());
    auto middle = tracker.insert(102, {'c', 'd'}, false, false);
    assert(middle.chunks.size() == 2);
    assert(middle.chunks[0].bytes == std::vector<std::uint8_t>({'c', 'd'}));
    assert(middle.chunks[1].bytes == std::vector<std::uint8_t>({'e', 'f'}));

    auto retransmission = tracker.insert(100, {'a', 'b'}, false, false);
    assert(retransmission.disposition == SegmentDisposition::retransmission);
    assert(retransmission.chunks.empty());

    auto overlap = tracker.insert(105, {'f', 'g'}, false, false);
    assert(overlap.disposition == SegmentDisposition::overlap);
    assert(overlap.chunks.size() == 1);
    assert(overlap.chunks[0].bytes == std::vector<std::uint8_t>({'g'}));

    auto fin = tracker.insert(107, {}, true, false);
    assert(fin.fin_seen);
    assert(tracker.fin_seen());

    TcpStreamTracker limited(StreamDirection::server_to_client, {3, 8});
    auto buffered = limited.insert(10, {'x', 'y', 'z', 'w'}, false, false);
    assert(buffered.buffered_bytes <= 3);
    assert(limited.buffered_bytes() <= 3);

    return 0;
}
