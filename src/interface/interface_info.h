#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace delta_nids::interface {

enum class AdminState { unknown, up, down };
enum class LinkState { unknown, up, down };
enum class InterfaceType { unknown, ethernet, wifi, loopback, tunnel, virtual_interface };
enum class CaptureBackend { unavailable, libpcap, npcap };

enum class CaptureMode { auto_select, explicit_interface, pcap, span };

struct InterfaceInfo {
    std::string stable_id;
    std::string name;
    std::string description;
    std::vector<std::string> ipv4_addresses;
    std::vector<std::string> ipv6_addresses;
    std::string mac_address;
    AdminState administrative_state = AdminState::unknown;
    AdminState operational_state = AdminState::unknown;
    LinkState link_state = LinkState::unknown;
    InterfaceType type = InterfaceType::unknown;
    bool loopback = false;
    bool virtual_or_tunnel = false;
    bool capture_capable = false;
    CaptureBackend capture_backend = CaptureBackend::unavailable;
    bool default_route = false;
};

struct ScoredInterface {
    InterfaceInfo info;
    int score = 0;
    bool suitable = false;
    std::string reason;
};

struct SelectionResult {
    CaptureMode mode = CaptureMode::auto_select;
    bool selected = false;
    bool span_mode = false;    // true when SPAN / port-mirror mode is active
    bool promiscuous = false;  // true when promiscuous capture was requested
    ScoredInterface interface;
    std::vector<ScoredInterface> candidates;
    std::string error;
};

}  // namespace delta_nids::interface
