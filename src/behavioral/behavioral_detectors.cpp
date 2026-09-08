#include "behavioral/behavioral_manager.h"

#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <utility>

namespace delta_nids::behavioral {
namespace {

std::string ip_string(const packet::IpAddress& value) { return value.to_string(); }
std::string protocol_string(packet::TransportProtocol value) {
    switch (value) {
        case packet::TransportProtocol::tcp: return "TCP";
        case packet::TransportProtocol::udp: return "UDP";
        case packet::TransportProtocol::icmp: return "ICMP";
        case packet::TransportProtocol::icmpv6: return "ICMPv6";
        default: return "other";
    }
}
std::string probe_class(std::uint8_t flags) {
    if ((flags & 0x02U) && !(flags & (0x10U | 0x04U | 0x01U))) return "syn";
    if (flags == 0x10U) return "ack";
    if (flags == (0x01U | 0x10U)) return "maimon";
    if (flags == 0x01U) return "fin";
    if (flags == 0) return "null";
    if (flags == (0x01U | 0x08U | 0x20U)) return "xmas";
    return {};
}

bool is_host_discovery_probe(const packet::Packet& packet) {
    if (packet.transport == packet::TransportProtocol::icmp && packet.icmp)
        return packet.icmp->type == 8; // IPv4 Echo Request
    if (packet.transport == packet::TransportProtocol::icmpv6 && packet.icmp) {
        // ICMPv6 Echo Request (128) is a host-discovery probe.
        // ICMPv6 Neighbor Discovery types (133-137) are normal IPv6 operations
        // and must NOT be treated as reconnaissance probes:
        //   133 Router Solicitation
        //   134 Router Advertisement
        //   135 Neighbor Solicitation
        //   136 Neighbor Advertisement
        //   137 Redirect
        const auto t = packet.icmp->type;
        if (t >= 133 && t <= 137) return false;
        return t == 128; // Echo Request only
    }
    if (packet.transport == packet::TransportProtocol::tcp && packet.tcp)
        return (packet.tcp->flags & 0x02U) != 0 &&
               (packet.tcp->flags & (0x10U | 0x04U)) == 0;
    return false;
}


struct Window {
    std::deque<std::int64_t> times;
    void add(std::int64_t now, std::int64_t span) {
        times.push_back(now);
        while (!times.empty() && now - times.front() > span) times.pop_front();
    }
};

class PortScanDetector final : public BehavioralDetector {
public:
    explicit PortScanDetector(BehavioralConfig config) : config_(config) {}
    void observe(const packet::Packet& packet, const flow::Flow& flow, std::vector<BehavioralEvent>& events) override {
        if (!packet.source_port || !packet.destination_port || packet.transport == packet::TransportProtocol::icmp) return;
        // Skip ICMPv6 entirely — it has no ports and ND traffic must not be
        // classified as a port scan.
        if (packet.transport == packet::TransportProtocol::icmpv6) return;
        std::string scan_class;
        if (packet.transport == packet::TransportProtocol::tcp && packet.tcp) {
            scan_class = probe_class(packet.tcp->flags);
            if (scan_class.empty()) return;
            // ACK-only probes are ambiguous without reverse response evidence;
            // the native detector does not yet correlate quoted responses.
            if (scan_class == "ack") return;
        } else if (packet.transport == packet::TransportProtocol::udp) {
            // UDP response traffic must not be counted as outbound probes.
            if (*packet.source_port == 53 || *packet.source_port == 67 ||
                *packet.source_port == 68 || *packet.source_port == 123) return;
            scan_class = "udp";
        } else {
            return;
        }
        const auto source = ip_string(packet.source);
        const auto destination = ip_string(packet.destination);
        const auto key = source + "|" + destination + "|" + protocol_string(packet.transport) + "|" + scan_class;
        auto state_iterator = states_.find(key);
        if (state_iterator == states_.end()) {
            if (states_.size() >= config_.maximum_sources && !states_.empty()) states_.erase(states_.begin());
            state_iterator = states_.emplace(key, State{}).first;
        }
        auto& state = state_iterator->second;
        if (std::find_if(state.observations.begin(), state.observations.end(),
                         [&](const auto& observation) { return observation.second == *packet.destination_port; }) == state.observations.end())
            state.observations.emplace_back(packet.timestamp_seconds, *packet.destination_port);
        if (state.observations.size() > config_.maximum_destinations_per_source)
            state.observations.pop_front();
        while (!state.observations.empty() &&
               packet.timestamp_seconds - state.observations.front().first > config_.window_seconds)
            state.observations.pop_front();
        std::set<std::uint16_t> ports;
        for (const auto& observation : state.observations) ports.insert(observation.second);
        if (ports.size() < config_.port_scan_threshold) state.emitted = false;
        if (ports.size() >= config_.port_scan_threshold && !state.emitted) {
            state.emitted = true;
            const auto message = "possible " + scan_class + " port scan";
            const auto explanation = "source contacted one destination on " +
                std::to_string(ports.size()) + " distinct destination ports within the configured window";
            events.push_back({BehavioralType::port_scan, packet.timestamp_seconds, flow.id, source, destination,
                              protocol_string(packet.transport), message, explanation, 85});
        }
    }
    void expire(std::int64_t now) override {
        for (auto iterator = states_.begin(); iterator != states_.end();) {
            if (!iterator->second.observations.empty() && now - iterator->second.observations.back().first > config_.window_seconds) iterator = states_.erase(iterator);
            else ++iterator;
        }
    }
    void reset() override { states_.clear(); }
private:
    struct State { std::deque<std::pair<std::int64_t, std::uint16_t>> observations; bool emitted = false; };
    BehavioralConfig config_;
    std::map<std::string, State> states_;
};

// Returns true when the address is globally routable (i.e. an Internet destination).
// Globally-routable destinations are ordinary client egress and should NOT be
// counted toward local host-sweep thresholds.
bool is_globally_routable(const packet::IpAddress& address) {
    if (address.family == packet::AddressFamily::ipv6) {
        if (address.bytes.size() < 16) return false;
        // Link-local: fe80::/10
        if ((address.bytes[0] == 0xfe) && ((address.bytes[1] & 0xc0U) == 0x80U)) return false;
        // Loopback: ::1
        if (std::all_of(address.bytes.begin(), address.bytes.begin() + 15,
                        [](std::uint8_t b) { return b == 0; }) && address.bytes[15] == 1)
            return false;
        // Unique-local (ULA): fc00::/7
        if ((address.bytes[0] & 0xfeU) == 0xfcU) return false;
        // Multicast: ff00::/8
        if (address.bytes[0] == 0xff) return false;
        // Unspecified ::
        if (std::all_of(address.bytes.begin(), address.bytes.end(),
                        [](std::uint8_t b) { return b == 0; })) return false;
        return true; // globally routable IPv6
    }
    // IPv4 private/reserved ranges.
    if (address.bytes.size() < 4) return true;
    const auto a = address.bytes[0], b = address.bytes[1], c = address.bytes[2];
    if (a == 10) return false;
    if (a == 127) return false;
    if (a == 169 && b == 254) return false;
    if (a == 172 && b >= 16 && b <= 31) return false;
    if (a == 192 && b == 168) return false;
    if (a == 192 && b == 0 && c == 2) return false;
    if (a == 198 && b == 51 && c == 100) return false;
    if (a == 203 && b == 0 && c == 113) return false;
    if (a == 198 && b >= 18 && b <= 19) return false;
    if (a == 100 && b >= 64 && b <= 127) return false; // CGNAT
    if (a >= 224) return false; // multicast/reserved
    return true;
}

class HostSweepDetector final : public BehavioralDetector {
public:
    explicit HostSweepDetector(BehavioralConfig config) : config_(config) {}
    void observe(const packet::Packet& packet, const flow::Flow& flow, std::vector<BehavioralEvent>& events) override {
        if (!is_host_discovery_probe(packet)) return;
        if (is_globally_routable(packet.destination)) return;
        // For ICMPv6, also skip multicast destinations (ff00::/8) — these are
        // normal Neighbor Discovery / Router Discovery multicasts, not sweeps.
        if (packet.transport == packet::TransportProtocol::icmpv6 &&
            packet.destination.family == packet::AddressFamily::ipv6 &&
            !packet.destination.bytes.empty() &&
            packet.destination.bytes[0] == 0xff) return;
        const auto source = ip_string(packet.source);
        const auto protocol = protocol_string(packet.transport);
        const auto key = source + "|" + protocol;
        auto state_iterator = states_.find(key);
        if (state_iterator == states_.end()) {
            if (states_.size() >= config_.maximum_sources && !states_.empty()) states_.erase(states_.begin());
            state_iterator = states_.emplace(key, State{}).first;
        }
        auto& state = state_iterator->second;
        state.observations.emplace_back(packet.timestamp_seconds, ip_string(packet.destination));
        while (!state.observations.empty() &&
               packet.timestamp_seconds - state.observations.front().first > config_.window_seconds)
            state.observations.pop_front();
        while (state.observations.size() > config_.maximum_destinations_per_source)
            state.observations.pop_front();
        std::set<std::string> destinations;
        for (const auto& observation : state.observations) destinations.insert(observation.second);
        if (destinations.size() < config_.host_sweep_threshold) state.emitted = false;
        if (destinations.size() >= config_.host_sweep_threshold && !state.emitted) {
            state.emitted = true;
            events.push_back({BehavioralType::host_sweep, packet.timestamp_seconds, flow.id, source, ip_string(packet.destination),
                              protocol, "possible host sweep",
                              "source contacted " + std::to_string(destinations.size()) + " unique non-Internet hosts within the configured window", 80});
        }
    }
    void expire(std::int64_t now) override {
        for (auto iterator = states_.begin(); iterator != states_.end();) {
            if (!iterator->second.observations.empty() &&
                now - iterator->second.observations.back().first > config_.window_seconds)
                iterator = states_.erase(iterator);
            else ++iterator;
        }
    }
    void reset() override { states_.clear(); }
private:
    struct State {
        std::deque<std::pair<std::int64_t, std::string>> observations;
        bool emitted = false;
    };
    BehavioralConfig config_;
    std::map<std::string, State> states_;
};

class RepeatedConnectionDetector final : public BehavioralDetector {
public:
    RepeatedConnectionDetector(BehavioralConfig config, BehavioralType type, std::string service)
        : config_(config), type_(type), service_(std::move(service)) {}
    void observe(const packet::Packet& packet, const flow::Flow& flow, std::vector<BehavioralEvent>& events) override {
        if (packet.transport != packet::TransportProtocol::tcp || !packet.tcp) return;
        const bool failed = (packet.tcp->flags & 0x04U) != 0 || (packet.tcp->flags & 0x01U) != 0;
        if (type_ == BehavioralType::brute_force) {
            if (flow.service != service_) return;
            // A brute-force campaign opens a new TCP connection per
            // authentication attempt (banner exchange + auth round-trip); each
            // plain SYN toward the SSH service is one observable attempt. Bare
            // RST/FIN closures additionally count as aborted attempts.
            const bool new_connection = (packet.tcp->flags & 0x02U) != 0 &&
                                        (packet.tcp->flags & 0x10U) == 0 &&
                                        (packet.tcp->flags & 0x04U) == 0;
            if (!failed && !new_connection) return;
        } else if (!failed) {
            return;
        }
        const auto key = ip_string(packet.source) + ":" + ip_string(packet.destination) + ":" + std::to_string(packet.destination_port.value_or(0));
        auto& state = states_[key];
        state.add(packet.timestamp_seconds, config_.window_seconds);
        if (state.times.size() >= (type_ == BehavioralType::brute_force ? config_.brute_force_threshold : config_.connection_flood_threshold) && !state.emitted) {
            state.emitted = true;
            events.push_back({type_, packet.timestamp_seconds, flow.id, ip_string(packet.source), ip_string(packet.destination), "TCP",
                              type_ == BehavioralType::brute_force ? "repeated SSH authentication attempts" : "connection flood pattern",
                              "observed " + std::to_string(state.times.size()) + " qualifying TCP events within the configured window", 75});
        }
    }
    void expire(std::int64_t now) override {
        for (auto iterator = states_.begin(); iterator != states_.end();) {
            if (!iterator->second.times.empty() && now - iterator->second.times.back() > config_.window_seconds) iterator = states_.erase(iterator);
            else ++iterator;
        }
    }
    void reset() override { states_.clear(); }
private:
    struct State : Window { bool emitted = false; };
    BehavioralConfig config_; BehavioralType type_; std::string service_; std::map<std::string, State> states_;
};

class DnsAnomalyDetector final : public BehavioralDetector {
public:
    explicit DnsAnomalyDetector(BehavioralConfig config) : config_(config) {}
    void observe(const packet::Packet& packet, const flow::Flow& flow, std::vector<BehavioralEvent>& events) override {
        if (flow.service != "DNS" || packet.payload.empty()) return;
        auto& state = states_[ip_string(packet.source)];
        state.add(packet.timestamp_seconds, config_.window_seconds);
        if (state.times.size() >= config_.dns_query_threshold && !state.emitted) {
            state.emitted = true;
            events.push_back({BehavioralType::dns_anomaly, packet.timestamp_seconds, flow.id, ip_string(packet.source), ip_string(packet.destination), "UDP",
                              "high DNS query rate", "source generated " + std::to_string(state.times.size()) + " DNS observations within the configured window", 65});
        }
    }
    void expire(std::int64_t now) override { for (auto iterator = states_.begin(); iterator != states_.end();) { if (now - iterator->second.times.back() > config_.window_seconds) iterator = states_.erase(iterator); else ++iterator; } }
    void reset() override { states_.clear(); }
private:
    struct State : Window { bool emitted = false; };
    BehavioralConfig config_; std::map<std::string, State> states_;
};

class TcpAnomalyDetector final : public BehavioralDetector {
public:
    void observe(const packet::Packet& packet, const flow::Flow& flow, std::vector<BehavioralEvent>& events) override {
        if (packet.transport != packet::TransportProtocol::tcp || !packet.tcp) return;
        const auto flags = packet.tcp->flags;
        if ((flags & 0x02U) && (flags & 0x01U)) {
            events.push_back({BehavioralType::tcp_anomaly, packet.timestamp_seconds, flow.id, ip_string(packet.source), ip_string(packet.destination), "TCP",
                              "invalid TCP SYN/FIN combination", "TCP flags contain SYN and FIN simultaneously", 90});
        }
    }
    void expire(std::int64_t) override {}
    void reset() override {}
};

}  // namespace

BehavioralManager::BehavioralManager(BehavioralConfig config) {
    detectors_.push_back(std::make_unique<PortScanDetector>(config));
    detectors_.push_back(std::make_unique<HostSweepDetector>(config));
    detectors_.push_back(std::make_unique<RepeatedConnectionDetector>(config, BehavioralType::brute_force, "SSH"));
    detectors_.push_back(std::make_unique<RepeatedConnectionDetector>(config, BehavioralType::connection_flood, ""));
    detectors_.push_back(std::make_unique<DnsAnomalyDetector>(config));
    detectors_.push_back(std::make_unique<TcpAnomalyDetector>());
}

std::vector<BehavioralEvent> BehavioralManager::observe(const packet::Packet& packet, const flow::Flow& flow) {
    std::vector<BehavioralEvent> events;
    ++metrics_.packets_observed;
    for (const auto& detector : detectors_) detector->observe(packet, flow, events);
    metrics_.events_generated += events.size();
    return events;
}
void BehavioralManager::expire(std::int64_t now) { for (const auto& detector : detectors_) detector->expire(now); }
void BehavioralManager::reset() { for (const auto& detector : detectors_) detector->reset(); }
const BehavioralMetrics& BehavioralManager::metrics() const noexcept { return metrics_; }

const char* behavioral_type_name(BehavioralType type) noexcept {
    switch (type) { case BehavioralType::port_scan: return "port_scan"; case BehavioralType::host_sweep: return "host_sweep"; case BehavioralType::brute_force: return "brute_force"; case BehavioralType::connection_flood: return "connection_flood"; case BehavioralType::dns_anomaly: return "dns_anomaly"; case BehavioralType::tcp_anomaly: return "tcp_anomaly"; }
    return "unknown";
}

}  // namespace delta_nids::behavioral
