#include "protocol/inspectors.h"

#include <algorithm>
#include <string>

namespace delta_nids::protocol {
namespace {

class SimpleInspector final : public ProtocolInspector {
public:
    explicit SimpleInspector(std::string service) : service_(std::move(service)) {}

    InspectionResult inspect(const InspectionContext& context,
                             const std::vector<std::uint8_t>& data) override {
        InspectionResult result;
        result.service = service_;
        if (data.size() > context.maximum_buffered_bytes) {
            result.status = InspectionStatus::limit_exceeded;
            result.error = service_ + " input exceeds configured inspection limit";
            return result;
        }
        result.fields["payload_length"] = std::to_string(data.size());
        if (service_ == "SSH" && data.size() >= 4) {
            const std::string text(data.begin(), data.begin() + 4);
            if (text != "SSH-") {
                result.status = InspectionStatus::malformed;
                result.error = "invalid SSH banner";
                return result;
            }
            result.fields["banner_prefix"] = "SSH-";
        }
        result.detection_data = data;
        result.status = data.empty() ? InspectionStatus::incomplete : InspectionStatus::complete;
        return result;
    }

    void reset() override {}

private:
    std::string service_;
};

}  // namespace

std::unique_ptr<ProtocolInspector> make_ssh_inspector() {
    return std::make_unique<SimpleInspector>("SSH");
}
std::unique_ptr<ProtocolInspector> make_icmp_inspector() {
    return std::make_unique<SimpleInspector>("ICMP");
}
std::unique_ptr<ProtocolInspector> make_generic_tcp_inspector() {
    return std::make_unique<SimpleInspector>("generic_tcp");
}
std::unique_ptr<ProtocolInspector> make_generic_udp_inspector() {
    return std::make_unique<SimpleInspector>("generic_udp");
}

}  // namespace delta_nids::protocol
