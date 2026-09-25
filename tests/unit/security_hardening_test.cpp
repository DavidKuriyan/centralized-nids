#include "api/api_server.h"
#include "detection/rule.h"
#include "packet/packet.h"
#include <cassert>
#include <cstdio>
#include <fstream>
#include <vector>
int main() {
    delta_nids::capture::CapturedPacket packet{1,0,14,14,std::vector<std::uint8_t>(14,0)};
    const auto decoded = delta_nids::packet::decode(packet, "test");
    assert(decoded.status == delta_nids::packet::DecodeStatus::unsupported || decoded.status == delta_nids::packet::DecodeStatus::malformed);
    const std::string path = "security-invalid-rules.json";
    { std::ofstream file(path); file << "[{\"sid\":1,\"action\":\"DROP\",\"protocol\":\"TCP\"}]"; }
    const auto rules = delta_nids::detection::load_rules(path); std::remove(path.c_str()); assert(!rules.valid());
    bool rejected = false;
    try { delta_nids::storage::StorageConfig config{"", 1}; (void)delta_nids::storage::make_sqlite_storage(config); }
    catch (...) { rejected = true; }
    assert(rejected);
    rejected = false;
    try { delta_nids::api::ServerConfig config{"127.0.0.1", 1, 10}; (void)config; delta_nids::api::ServerConfig valid{"127.0.0.1", 12345, 10}; (void)valid; }
    catch (...) { rejected = true; }
    assert(!rejected);
    return 0;
}
