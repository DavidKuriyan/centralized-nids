#include "protocol/inspectors.h"

#include <string>

namespace delta_nids::protocol {
namespace {

class DnsInspector final : public ProtocolInspector {
public:
    InspectionResult inspect(const InspectionContext& context,
                             const std::vector<std::uint8_t>& data) override {
        InspectionResult result;
        result.service = "DNS";
        if (data.size() > context.maximum_buffered_bytes) {
            result.status = InspectionStatus::limit_exceeded;
            result.error = "DNS input exceeds configured inspection limit";
            return result;
        }
        if (data.size() < 12) {
            result.status = InspectionStatus::incomplete;
            return result;
        }
        result.fields["transaction_id"] = std::to_string((data[0] << 8) | data[1]);
        const bool response = (data[2] & 0x80U) != 0;
        result.fields["message_type"] = response ? "response" : "query";
        result.fields["question_count"] = std::to_string((data[4] << 8) | data[5]);
        result.fields["answer_count"] = std::to_string((data[6] << 8) | data[7]);
        result.fields["response_code"] = std::to_string(data[3] & 0x0fU);
        if ((data[4] << 8 | data[5]) == 0) {
            result.status = InspectionStatus::complete;
            result.detection_data = data;
            return result;
        }
        std::size_t cursor = 12;
        std::string name;
        while (cursor < data.size()) {
            const auto length = data[cursor++];
            if (length == 0) break;
            if ((length & 0xc0U) != 0 || length > 63 || cursor + length > data.size()) {
                result.status = InspectionStatus::malformed;
                result.error = "invalid DNS name label";
                return result;
            }
            if (!name.empty()) name += '.';
            name.append(reinterpret_cast<const char*>(data.data() + cursor), length);
            cursor += length;
            if (name.size() > 253) {
                result.status = InspectionStatus::malformed;
                result.error = "DNS name exceeds maximum length";
                return result;
            }
        }
        if (cursor + 4 > data.size()) {
            result.status = InspectionStatus::incomplete;
            return result;
        }
        result.fields["query_name"] = name;
        result.fields["query_type"] = std::to_string((data[cursor] << 8) | data[cursor + 1]);
        result.status = InspectionStatus::complete;
        result.detection_data = data;
        return result;
    }
    void reset() override {}
};

}  // namespace

std::unique_ptr<ProtocolInspector> make_dns_inspector() {
    return std::make_unique<DnsInspector>();
}

}  // namespace delta_nids::protocol
