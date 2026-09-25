#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "detection/detection_buffer.h"
#include "packet/packet.h"
#include "protocol/service_identifier.h"

namespace delta_nids::detection {

enum class RuleAction { alert, log };
enum class RuleDirection { any, client_to_server, server_to_client };

enum class RuleSeverity { info, low, medium, high, critical };

struct PortRange {
    std::uint16_t first = 0;
    std::uint16_t last = 65535;
};

struct Network {
    packet::AddressFamily family = packet::AddressFamily::none;
    std::vector<std::uint8_t> address;
    std::uint8_t prefix_length = 0;
};

struct Threshold {
    std::uint32_t count = 1;
    std::uint32_t seconds = 0;
};

struct Rule {
    std::uint32_t gid = 1;
    std::uint32_t sid = 0;
    std::uint32_t revision = 1;
    RuleAction action = RuleAction::alert;
    packet::TransportProtocol protocol = packet::TransportProtocol::none;
    std::optional<Network> source_network;
    std::optional<Network> destination_network;
    // Empty vectors mean "any". Canonical multi-port rules ("80,443",
    // "1:1024", "$HTTP_PORTS") compile into one PortRange per token so
    // dashboard, API, and file-loaded rules all match identically.
    std::vector<PortRange> source_ports;
    std::vector<PortRange> destination_ports;
    RuleDirection direction = RuleDirection::any;
    std::optional<protocol::Service> service;
    BufferName buffer = BufferName::payload;
    std::vector<std::vector<std::uint8_t>> content_chain;
    std::vector<std::uint8_t> content;
    bool nocase = false;
    std::optional<std::size_t> offset;
    std::optional<std::size_t> depth;
    std::optional<std::size_t> distance;
    std::optional<std::size_t> within;
    std::optional<Threshold> threshold;
    std::string suppression_key;
    std::string classification;
    RuleSeverity severity = RuleSeverity::medium;
    std::uint32_t priority = 3;
    std::string message;
    std::string source_file;
};

struct RuleValidationError {
    std::size_t index = 0;
    std::string field;
    std::string message;
};

struct RuleLoadResult {
    std::vector<Rule> rules;
    std::vector<RuleValidationError> errors;
    [[nodiscard]] bool valid() const noexcept { return errors.empty(); }
};

[[nodiscard]] RuleLoadResult load_rules(const std::string& path);
[[nodiscard]] const char* action_name(RuleAction action) noexcept;
[[nodiscard]] const char* severity_name(RuleSeverity severity) noexcept;
[[nodiscard]] std::string rule_format_documentation();

}  // namespace delta_nids::detection
