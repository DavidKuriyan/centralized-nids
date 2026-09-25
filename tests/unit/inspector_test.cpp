#include <cassert>
#include <cstdint>
#include <vector>

#include "protocol/inspector_manager.h"

int main() {
    using namespace delta_nids::protocol;
    InspectorManager manager;
    InspectionContext context;
    context.flow_id = 7;

    const std::vector<std::uint8_t> http = {
        'G','E','T',' ','/','e','t','c','/','p','a','s','s','w','d',' ',
        'H','T','T','P','/','1','.','1','\r','\n','H','o','s','t',':',' ',
        'e','x','a','m','p','l','e','.','t','e','s','t','\r','\n','\r','\n'
    };
    auto http_result = manager.inspect(Service::http, context, http);
    assert(http_result.status == InspectionStatus::complete);
    assert(http_result.fields.at("http_method") == "GET");
    assert(http_result.fields.at("http_uri") == "/etc/passwd");

    const std::vector<std::uint8_t> dns = {0x12,0x34,0x01,0x00,0x00,0x01,0,0,0,0,0,0,3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    auto dns_result = manager.inspect(Service::dns, context, dns);
    assert(dns_result.status == InspectionStatus::complete);
    assert(dns_result.fields.at("query_name") == "www.example.com");

    const std::vector<std::uint8_t> tls = {0x16,0x03,0x03,0,1,1};
    auto tls_result = manager.inspect(Service::tls, context, tls);
    assert(tls_result.status == InspectionStatus::complete);
    assert(tls_result.fields.at("encrypted_application_data") == "false");

    const std::vector<std::uint8_t> ssh = {'S','S','H','-','2','.'};
    auto ssh_result = manager.inspect(Service::ssh, context, ssh);
    assert(ssh_result.status == InspectionStatus::complete);

    InspectionContext limited = context;
    limited.maximum_buffered_bytes = 2;
    auto limited_result = manager.inspect(Service::http, limited, http);
    assert(limited_result.status == InspectionStatus::limit_exceeded);

    const std::vector<std::uint8_t> incomplete = {'G','E','T',' '};
    auto incomplete_result = manager.inspect(Service::http, context, incomplete);
    assert(incomplete_result.status == InspectionStatus::incomplete);
    return 0;
}
