#pragma once

#include <cstdint>
#include <map>
#include <vector>

#include "alert/alert.h"

namespace delta_nids::alert {

class AlertManager {
public:
    explicit AlertManager(AlertConfig config = {});

    [[nodiscard]] std::vector<Alert> ingest(const detection::DetectionEvent& event,
                                            const std::string& source_ip,
                                            const std::string& destination_ip,
                                            std::uint16_t source_port = 0,
                                            std::uint16_t destination_port = 0);
    [[nodiscard]] const std::map<std::string, Alert>& alerts() const noexcept;
    [[nodiscard]] std::uint64_t suppressed_events() const noexcept;
    [[nodiscard]] std::uint64_t emitted_alerts() const noexcept;
    void expire(std::int64_t now);
    void clear();

private:
    Alert make_alert(const detection::DetectionEvent& event, const std::string& source_ip,
                     const std::string& destination_ip, std::uint16_t source_port,
                     std::uint16_t destination_port, const std::string& fingerprint) const;

    AlertConfig config_;
    std::uint64_t next_id_ = 1;
    std::uint64_t suppressed_events_ = 0;
    std::uint64_t emitted_alerts_ = 0;
    std::map<std::string, Alert> alerts_;
};

}  // namespace delta_nids::alert
