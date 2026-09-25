#include "interface/interface_scorer.h"

#include <algorithm>
#include <string>

namespace delta_nids::interface {
namespace {

bool has_address(const InterfaceInfo& info) {
    return !info.ipv4_addresses.empty() || !info.ipv6_addresses.empty();
}

bool unsuitable(const InterfaceInfo& info) {
    return !info.capture_capable ||
           info.administrative_state == AdminState::down ||
           info.operational_state == AdminState::down ||
           info.link_state == LinkState::down;
}

}  // namespace

ScoredInterface InterfaceScorer::score(const InterfaceInfo& info) const {
    ScoredInterface result;
    result.info = info;
    result.suitable = !unsuitable(info);

    if (info.capture_capable) result.score += 40;
    if (info.operational_state == AdminState::up) result.score += 25;
    if (info.link_state == LinkState::up) result.score += 20;
    if (info.default_route) result.score += 30;
    if (!info.ipv4_addresses.empty()) result.score += 10;
    if (!info.ipv6_addresses.empty()) result.score += 5;
    if (!info.loopback) result.score += 15;
    if (info.type == InterfaceType::ethernet || info.type == InterfaceType::wifi) {
        result.score += 5;
    }
    if (info.virtual_or_tunnel) result.score -= 10;
    if (info.link_state == LinkState::down) result.score -= 40;
    if (info.loopback) result.score -= 50;
    if (info.administrative_state == AdminState::down) result.score -= 60;

    if (!info.capture_capable) {
        result.reason = "not capture capable";
    } else if (info.administrative_state == AdminState::down) {
        result.reason = "administratively down";
    } else if (info.operational_state == AdminState::down) {
        result.reason = "operationally down";
    } else if (info.link_state == LinkState::down) {
        result.reason = "link is down";
    } else if (info.default_route) {
        result.reason = "active default-route interface";
    } else if (info.virtual_or_tunnel) {
        result.reason = "active capture-capable virtual/tunnel interface";
    } else if (info.loopback) {
        result.reason = "loopback fallback";
    } else if (has_address(info)) {
        result.reason = "active capture-capable interface with address";
    } else {
        result.reason = "active capture-capable interface";
    }

    return result;
}

std::vector<ScoredInterface> InterfaceScorer::rank(
    const std::vector<InterfaceInfo>& interfaces) const {
    std::vector<ScoredInterface> ranked;
    ranked.reserve(interfaces.size());
    for (const auto& info : interfaces) ranked.push_back(score(info));

    std::sort(ranked.begin(), ranked.end(), [](const auto& left, const auto& right) {
        if (left.suitable != right.suitable) return left.suitable > right.suitable;
        if (left.score != right.score) return left.score > right.score;
        if (left.info.stable_id != right.info.stable_id) {
            return left.info.stable_id < right.info.stable_id;
        }
        return left.info.name < right.info.name;
    });
    return ranked;
}

}  // namespace delta_nids::interface
