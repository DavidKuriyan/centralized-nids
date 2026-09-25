#include <cassert>
#include <cstdint>
#include <vector>

#include "detection/rule_matcher.h"

int main() {
    using namespace delta_nids::detection;
    delta_nids::flow::Flow flow;
    flow.key.protocol = delta_nids::packet::TransportProtocol::tcp;
    flow.client = {{delta_nids::packet::AddressFamily::ipv4, {192, 0, 2, 10}}, 40000};
    flow.server = {{delta_nids::packet::AddressFamily::ipv4, {198, 51, 100, 20}}, 80};
    flow.service = "HTTP";

    Rule rule;
    rule.sid = 1001;
    rule.protocol = delta_nids::packet::TransportProtocol::tcp;
    rule.service = delta_nids::protocol::Service::http;
    rule.direction = RuleDirection::client_to_server;
    rule.buffer = BufferName::http_uri;
    rule.content = {'/','E','T','C'};
    rule.content_chain = {{'/','E','T','C'}};
    rule.nocase = true;
    rule.offset = 0;
    rule.depth = 20;
    rule.message = "URI test";

    BufferSet buffers;
    BufferProvenance provenance;
    provenance.flow_id = 1;
    provenance.direction = BufferDirection::client_to_server;
    assert(buffers.add(BufferName::http_uri, {'/','e','t','c','/','p','a','s','s','w','d'}, provenance));

    RuleMatcher matcher({rule});
    MatchContext context{&flow, BufferDirection::client_to_server, &buffers};
    const auto matches = matcher.match(context);
    assert(matches.size() == 1);
    assert(matches.front().offset == 0);
    assert(matches.front().evidence == std::vector<std::uint8_t>({'/','e','t','c'}));

    context.direction = BufferDirection::server_to_client;
    assert(matcher.match(context).empty());

    rule.offset = 5;
    matcher.set_rules({rule});
    context.direction = BufferDirection::client_to_server;
    assert(matcher.match(context).empty());

    Rule chain_rule = rule;
    chain_rule.offset.reset();
    chain_rule.depth.reset();
    chain_rule.content_chain = {{'e','t','c'}, {'p','a','s','s'}};
    chain_rule.content = chain_rule.content_chain.front();
    matcher.set_rules({chain_rule});
    assert(matcher.match(context).size() == 1);
    chain_rule.distance = 10;
    matcher.set_rules({chain_rule});
    assert(matcher.match(context).empty());
    return 0;
}
