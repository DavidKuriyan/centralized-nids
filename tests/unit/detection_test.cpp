#include <cassert>
#include <cstdint>

#include "detection/detection_engine.h"

int main() {
    using namespace delta_nids::detection;
    delta_nids::flow::Flow flow;
    flow.id = 77;
    flow.key.protocol = delta_nids::packet::TransportProtocol::tcp;
    flow.client = {{delta_nids::packet::AddressFamily::ipv4, {192, 0, 2, 10}}, 40000};
    flow.server = {{delta_nids::packet::AddressFamily::ipv4, {198, 51, 100, 20}}, 80};
    flow.service = "HTTP";

    Rule rule;
    rule.sid = 2001;
    rule.revision = 4;
    rule.protocol = delta_nids::packet::TransportProtocol::tcp;
    rule.service = delta_nids::protocol::Service::http;
    rule.direction = RuleDirection::client_to_server;
    rule.buffer = BufferName::http_uri;
    rule.content = {'/','e','t','c'};
    rule.message = "HTTP sensitive path";
    rule.severity = RuleSeverity::high;
    rule.priority = 1;

    BufferSet buffers;
    BufferProvenance provenance;
    provenance.flow_id = flow.id;
    provenance.direction = BufferDirection::client_to_server;
    provenance.complete = true;
    assert(buffers.add(BufferName::http_uri, {'/','e','t','c','/','p'}, provenance));

    DetectionEngine engine({rule});
    MatchContext context{&flow, BufferDirection::client_to_server, &buffers};
    const auto events = engine.detect(context, 1234);
    assert(events.size() == 1);
    assert(events.front().sid == 2001);
    assert(events.front().revision == 4);
    assert(events.front().flow_id == 77);
    assert(events.front().severity == RuleSeverity::high);
    assert(!events.front().evidence.empty());
    assert(events.front().explanation.find("buffer http_uri") != std::string::npos);
    assert(engine.metrics().rules_loaded == 1);
    assert(engine.metrics().rules_matched == 1);

    context.direction = BufferDirection::server_to_client;
    assert(engine.detect(context, 1235).empty());
    return 0;
}
