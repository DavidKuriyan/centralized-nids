#include "detection/rule_matcher.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace delta_nids::detection {
namespace {

bool address_in_network(const packet::IpAddress& address, const Network& network) {
    if (address.family != network.family || network.address.size() != address.bytes.size()) return false;
    const auto full_bytes = network.prefix_length / 8;
    const auto remainder = network.prefix_length % 8;
    for (std::size_t index = 0; index < static_cast<std::size_t>(full_bytes); ++index)
        if (address.bytes[index] != network.address[index]) return false;
    if (remainder != 0) {
        const auto mask = static_cast<std::uint8_t>(0xffU << (8U - remainder));
        if ((address.bytes[full_bytes] & mask) != (network.address[full_bytes] & mask)) return false;
    }
    return true;
}

bool port_matches(const std::vector<PortRange>& ranges, const std::optional<std::uint16_t>& port) {
    if (ranges.empty()) return true;
    if (!port) return false;
    for (const auto& range : ranges)
        if (*port >= range.first && *port <= range.last) return true;
    return false;
}

std::vector<std::uint8_t> fold(const std::vector<std::uint8_t>& value, bool nocase) {
    if (!nocase) return value;
    auto result = value;
    for (auto& byte : result) byte = static_cast<std::uint8_t>(std::tolower(static_cast<unsigned char>(byte)));
    return result;
}

std::optional<std::size_t> find_content(const std::vector<std::uint8_t>& data,
                                        const std::vector<std::uint8_t>& content,
                                        bool nocase, std::size_t begin, std::size_t end) {
    if (content.empty() || begin > data.size()) return std::nullopt;
    end = std::min(end, data.size());
    if (content.size() > end - begin) return std::nullopt;
    const auto needle = fold(content, nocase);
    for (std::size_t offset = begin; offset + needle.size() <= end; ++offset) {
        bool matched = true;
        for (std::size_t index = 0; index < needle.size(); ++index) {
            const auto byte = nocase ? static_cast<std::uint8_t>(std::tolower(static_cast<unsigned char>(data[offset + index]))) : data[offset + index];
            if (byte != needle[index]) { matched = false; break; }
        }
        if (matched) return offset;
    }
    return std::nullopt;
}

bool protocol_matches(const Rule& rule, const flow::Flow& flow) {
    return rule.protocol == packet::TransportProtocol::none || rule.protocol == flow.key.protocol;
}

}  // namespace

RuleMatcher::RuleMatcher(std::vector<Rule> rules) : rules_(std::move(rules)) {}
void RuleMatcher::set_rules(std::vector<Rule> rules) { rules_ = std::move(rules); }
const std::vector<Rule>& RuleMatcher::rules() const noexcept { return rules_; }

std::vector<RuleMatch> RuleMatcher::match(const MatchContext& context) const {
    std::vector<RuleMatch> matches;
    if (!context.flow || !context.buffers) return matches;
    const auto& flow = *context.flow;
    const auto source = flow.client.address;
    const auto destination = flow.server.address;
    for (const auto& rule : rules_) {
        if (!protocol_matches(rule, flow)) continue;
        if (rule.service && flow.service != protocol::service_name(*rule.service)) continue;
        if (rule.direction == RuleDirection::client_to_server && context.direction != BufferDirection::client_to_server) continue;
        if (rule.direction == RuleDirection::server_to_client && context.direction != BufferDirection::server_to_client) continue;
        if (rule.source_network && !address_in_network(source, *rule.source_network)) continue;
        if (rule.destination_network && !address_in_network(destination, *rule.destination_network)) continue;
        if (!port_matches(rule.source_ports, std::optional<std::uint16_t>(flow.client.port))) continue;
        if (!port_matches(rule.destination_ports, std::optional<std::uint16_t>(flow.server.port))) continue;
        const auto* buffer = context.buffers->get(rule.buffer);
        if (!buffer || rule.content.empty()) continue;
        const auto& data = buffer->data;
        const auto begin = rule.offset.value_or(0);
        const auto end = rule.depth ? begin + *rule.depth : data.size();
        const auto chain = rule.content_chain.empty() ? std::vector<std::vector<std::uint8_t>>{rule.content} : rule.content_chain;
        std::size_t cursor = begin;
        std::size_t first_offset = 0;
        std::size_t last_end = begin;
        bool chain_matched = true;
        for (std::size_t chain_index = 0; chain_index < chain.size(); ++chain_index) {
            const auto& content = chain[chain_index];
            const auto match_begin = chain_index == 0 ? begin : cursor + rule.distance.value_or(0);
            const auto match_end = rule.within && chain_index > 0
                ? std::min(end, match_begin + *rule.within) : end;
            const auto found = find_content(data, content, rule.nocase, match_begin, match_end);
            if (!found) { chain_matched = false; break; }
            if (chain_index == 0) first_offset = *found;
            cursor = *found + content.size();
            last_end = cursor;
        }
        if (!chain_matched) continue;
        RuleMatch match;
        match.rule = &rule;
        match.offset = first_offset;
        match.evidence.assign(data.begin() + static_cast<std::ptrdiff_t>(first_offset),
                              data.begin() + static_cast<std::ptrdiff_t>(last_end));
        std::ostringstream explanation;
        explanation << "rule " << rule.sid << " matched buffer " << buffer_name(rule.buffer)
                    << " at offset " << first_offset;
        match.explanation = explanation.str();
        matches.push_back(std::move(match));
    }
    return matches;
}

}  // namespace delta_nids::detection
