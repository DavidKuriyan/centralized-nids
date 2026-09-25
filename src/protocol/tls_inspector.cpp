#include "protocol/inspectors.h"

namespace delta_nids::protocol {
namespace {

class TlsInspector final : public ProtocolInspector {
public:
    InspectionResult inspect(const InspectionContext& context,
                             const std::vector<std::uint8_t>& data) override {
        InspectionResult result;
        result.service = "TLS";
        if (data.size() > context.maximum_buffered_bytes) {
            result.status = InspectionStatus::limit_exceeded;
            result.error = "TLS input exceeds configured inspection limit";
            return result;
        }
        if (data.size() < 5) {
            result.status = InspectionStatus::incomplete;
            return result;
        }
        if (data[0] < 20 || data[0] > 24 || data[1] != 3 || data[2] > 4) {
            result.status = InspectionStatus::malformed;
            result.error = "invalid TLS record header";
            return result;
        }
        const auto length = static_cast<std::size_t>((data[3] << 8) | data[4]);
        if (length > context.maximum_buffered_bytes || data.size() < length + 5) {
            result.status = data.size() < length + 5 ? InspectionStatus::incomplete : InspectionStatus::limit_exceeded;
            return result;
        }
        result.fields["record_type"] = std::to_string(data[0]);
        result.fields["record_version"] = "3." + std::to_string(data[2]);
        result.fields["encrypted_application_data"] = data[0] == 23 ? "true" : "false";
        if (data[0] == 22 && length > 0) result.fields["handshake_type"] = std::to_string(data[5]);
        result.detection_data.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(length + 5));
        result.status = InspectionStatus::complete;
        return result;
    }
    void reset() override {}
};

}  // namespace

std::unique_ptr<ProtocolInspector> make_tls_inspector() {
    return std::make_unique<TlsInspector>();
}

}  // namespace delta_nids::protocol
