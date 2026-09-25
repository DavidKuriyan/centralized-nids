#include "protocol/inspectors.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace delta_nids::protocol {
namespace {

class HttpInspector final : public ProtocolInspector {
public:
    InspectionResult inspect(const InspectionContext& context,
                             const std::vector<std::uint8_t>& data) override {
        InspectionResult result;
        result.service = "HTTP";
        if (data.size() > context.maximum_buffered_bytes) {
            result.status = InspectionStatus::limit_exceeded;
            result.error = "HTTP input exceeds configured inspection limit";
            return result;
        }
        const std::string text(data.begin(), data.end());
        const auto separator = text.find("\r\n\r\n");
        if (separator == std::string::npos) {
            result.status = InspectionStatus::incomplete;
            return result;
        }
        const auto first_line_end = text.find("\r\n");
        if (first_line_end == std::string::npos || first_line_end > separator) {
            result.status = InspectionStatus::malformed;
            result.error = "HTTP headers have no valid request/response line";
            return result;
        }
        const std::string first_line = text.substr(0, first_line_end);
        if (first_line.rfind("HTTP/", 0) == 0) {
            std::istringstream line(first_line);
            std::string version;
            int status = 0;
            line >> version >> status;
            if (version.empty() || status < 100 || status > 999) {
                result.status = InspectionStatus::malformed;
                result.error = "invalid HTTP response line";
                return result;
            }
            result.fields["http_version"] = version;
            result.fields["response_status"] = std::to_string(status);
        } else {
            std::istringstream line(first_line);
            std::string method;
            std::string uri;
            std::string version;
            line >> method >> uri >> version;
            if (method.empty() || uri.empty() || version.rfind("HTTP/", 0) != 0) {
                result.status = InspectionStatus::malformed;
                result.error = "invalid HTTP request line";
                return result;
            }
            result.fields["http_method"] = method;
            result.fields["http_uri"] = uri;
            result.fields["normalized_uri"] = normalize_uri(uri);
            result.fields["http_version"] = version;
        }
        std::size_t cursor = first_line_end + 2;
        while (cursor < separator) {
            const auto end = text.find("\r\n", cursor);
            if (end == std::string::npos || end > separator) {
                result.status = InspectionStatus::malformed;
                result.error = "invalid HTTP header termination";
                return result;
            }
            const auto colon = text.find(':', cursor);
            if (colon == std::string::npos || colon > end || colon == cursor) {
                result.status = InspectionStatus::malformed;
                result.error = "invalid HTTP header";
                return result;
            }
            std::string name = text.substr(cursor, colon - cursor);
            std::string value = text.substr(colon + 1, end - colon - 1);
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            result.fields["header." + name] = value;
            if (name == "host") result.fields["http_host"] = value;
            if (name == "user-agent") result.fields["http_user_agent"] = value;
            if (name == "content-type") result.fields["content_type"] = value;
            if (name == "content-length") result.fields["content_length"] = value;
            cursor = end + 2;
        }
        result.detection_data.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(separator));
        result.status = InspectionStatus::complete;
        return result;
    }

    void reset() override {}

private:
    static std::string normalize_uri(const std::string& uri) {
        std::string normalized = uri;
        std::replace(normalized.begin(), normalized.end(), '\\', '/');
        return normalized;
    }
};

}  // namespace

std::unique_ptr<ProtocolInspector> make_http_inspector() {
    return std::make_unique<HttpInspector>();
}

}  // namespace delta_nids::protocol
