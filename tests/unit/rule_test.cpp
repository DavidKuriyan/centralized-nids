#include <cassert>
#include <cstdint>
#include <string>

#include "detection/rule.h"
#include "detection/rule_matcher.h"

namespace {
bool matches_port(const delta_nids::detection::Rule& rule, std::uint16_t port) {
    delta_nids::flow::Flow flow;
    flow.key.protocol = delta_nids::packet::TransportProtocol::tcp;
    flow.client = {{delta_nids::packet::AddressFamily::ipv4, {192, 0, 2, 10}}, 40000};
    flow.server = {{delta_nids::packet::AddressFamily::ipv4, {198, 51, 100, 20}}, port};
    flow.service = "generic_tcp";
    delta_nids::detection::BufferSet buffers;
    delta_nids::detection::BufferProvenance provenance;
    provenance.flow_id = 1;
    provenance.direction = delta_nids::detection::BufferDirection::client_to_server;
    buffers.add(delta_nids::detection::BufferName::payload, {'t','e','s','t'}, provenance);
    delta_nids::detection::RuleMatcher matcher({rule});
    delta_nids::detection::MatchContext context{&flow, delta_nids::detection::BufferDirection::client_to_server, &buffers};
    return !matcher.match(context).empty();
}
}

int main() {
    const auto valid = delta_nids::detection::load_rules("tests/fixtures/valid.rules.json");
    assert(valid.valid());
    assert(valid.rules.size() == 1);
    assert(valid.rules.front().sid == 1000001);
    assert(valid.rules.front().service == delta_nids::protocol::Service::http);
    assert(valid.rules.front().buffer == delta_nids::detection::BufferName::http_uri);
    assert(valid.rules.front().threshold.has_value());

    const auto invalid = delta_nids::detection::load_rules("tests/fixtures/invalid.rules.json");
    assert(!invalid.valid());
    assert(invalid.rules.empty());
    assert(invalid.errors.size() >= 3);

    // Canonical port syntax: comma lists, brackets, ranges, and variables
    // compile to one PortRange per token and match identically to the Python
    // engine.
    const auto ports = delta_nids::detection::load_rules("tests/fixtures/portlist.rules.json");
    assert(ports.valid());
    assert(ports.rules.size() == 4);

    const auto& list_rule = ports.rules[0];
    assert(list_rule.destination_ports.size() == 2);
    assert(matches_port(list_rule, 80));
    assert(matches_port(list_rule, 443));
    assert(!matches_port(list_rule, 8080));

    const auto& bracket_rule = ports.rules[1];
    assert(matches_port(bracket_rule, 8080));
    assert(matches_port(bracket_rule, 8443));
    assert(!matches_port(bracket_rule, 80));

    const auto& range_rule = ports.rules[2];
    assert(matches_port(range_rule, 1));
    assert(matches_port(range_rule, 1024));
    assert(!matches_port(range_rule, 1025));

    const auto& variable_rule = ports.rules[3];
    assert(matches_port(variable_rule, 80));
    assert(matches_port(variable_rule, 8080));
    assert(!matches_port(variable_rule, 443));
    return 0;
}
