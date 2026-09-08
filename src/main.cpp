#include <iostream>
#include <memory>
#include <string>
#include <stdexcept>

#include "api/api_server.h"
#include "core/version.h"
#include "detection/rule.h"
#include "storage/storage.h"
#include "interface/interface_manager.h"
#include "interface/system_interface_provider.h"
#include "platform/platform.h"
#include "telemetry/telemetry.h"

namespace {

const char* state_name(delta_nids::interface::AdminState state) {
    using delta_nids::interface::AdminState;
    switch (state) {
        case AdminState::up: return "UP";
        case AdminState::down: return "DOWN";
        default: return "UNKNOWN";
    }
}

const char* backend_name(delta_nids::interface::CaptureBackend backend) {
    using delta_nids::interface::CaptureBackend;
    switch (backend) {
        case CaptureBackend::libpcap: return "libpcap";
        case CaptureBackend::npcap: return "Npcap";
        default: return "unavailable";
    }
}

void print_interfaces(const delta_nids::interface::InterfaceManager& manager) {
    for (const auto& candidate : manager.list_interfaces()) {
        const auto& info = candidate.info;
        std::cout << info.stable_id << "  " << info.name
                  << "  " << state_name(info.operational_state)
                  << "  capture=" << (info.capture_capable ? "YES" : "NO")
                  << "  score=" << candidate.score
                  << "  reason=" << candidate.reason << '\n';
    }
}

}  // namespace

int main(int argc, char** argv) {
    const auto platform = delta_nids::platform::current_platform();
    std::cout << "Delta-NIDS " << delta_nids::core::version()
              << " (" << platform.name << ")\n";

    auto manager = delta_nids::interface::InterfaceManager(
        delta_nids::interface::make_system_interface_provider());

    if (argc > 1 && std::string(argv[1]) == "--api") {
        std::string database_path = "database/nids.db";
        std::uint16_t port = 8080;
        if (argc > 2) database_path = argv[2];
        if (argc > 3) {
            try {
                const auto parsed = std::stoul(argv[3]);
                if (parsed == 0 || parsed > 65535) throw std::out_of_range("port");
                port = static_cast<std::uint16_t>(parsed);
            } catch (const std::exception&) {
                std::cerr << "[ERROR] API port must be an integer between 1 and 65535\n";
                return 2;
            }
        }
        try {
            auto storage = delta_nids::storage::make_sqlite_storage({database_path, 4096});
            delta_nids::api::ApiServer server({"127.0.0.1", port, 8192}, *storage);
            std::cout << "[INFO] Delta-NIDS API listening at http://127.0.0.1:" << port << "\n"
                      << "[INFO] Database: " << database_path << "\n"
                      << "[INFO] Press Ctrl+C to stop\n";
            server.run();
        } catch (const std::exception& error) {
            std::cerr << "[ERROR] API startup failed: " << error.what() << '\n';
            return 1;
        }
        return 0;
    }

    if (argc > 1 && std::string(argv[1]) == "--stats") {
        const auto snapshot = delta_nids::telemetry::MetricsRegistry::global().snapshot();
        for (const auto& [name, value] : snapshot.counters) std::cout << name << "=" << value << '\n';
        return 0;
    }

    if (argc > 1 && std::string(argv[1]) == "--validate-rules") {
        const auto path = argc > 2 ? argv[2] : "rules/rules.json";
        const auto loaded = delta_nids::detection::load_rules(path);
        if (!loaded.valid()) {
            for (const auto& issue : loaded.errors)
                std::cerr << "[ERROR] rule " << issue.index << " field " << issue.field << ": " << issue.message << '\n';
            return 2;
        }
        std::cout << "[INFO] Validated " << loaded.rules.size() << " passive rules from " << path << '\n';
        return 0;
    }

    if (argc > 1 && std::string(argv[1]) == "--list-interfaces") {
        delta_nids::telemetry::MetricsRegistry::global().increment("interface_listing_requests");
        print_interfaces(manager);
        return 0;
    }

    if (argc > 2 && std::string(argv[1]) == "--interface") {
        // Check for optional --capture-mode argument.
        std::string capture_mode = "normal";
        for (int i = 3; i < argc - 1; ++i) {
            if (std::string(argv[i]) == "--capture-mode") {
                capture_mode = argv[i + 1];
            }
        }
        delta_nids::telemetry::MetricsRegistry::global().increment("explicit_capture_selections");
        const auto result = manager.select_explicit(argv[2]);
        if (!result.selected) {
            std::cerr << "[ERROR] " << result.error << '\n';
            return 2;
        }
        const bool span = (capture_mode == "span");
        std::cout << "[INFO] Capture mode: " << (span ? "SPAN" : "EXPLICIT") << '\n'
                  << "[INFO] Selected interface: " << result.interface.info.name << '\n'
                  << "[INFO] Capture backend: "
                  << backend_name(result.interface.info.capture_backend) << '\n';
        if (span) {
            std::cout
                << "\n"
                << "╔══════════════════════════════════════════════════════════════╗\n"
                << "║        DELTA-NIDS  —  SPAN / PORT MIRROR MODE ACTIVE         ║\n"
                << "╚══════════════════════════════════════════════════════════════╝\n"
                << "\n"
                << "  Interface  : " << result.interface.info.name << "\n"
                << "  Promiscuous: YES\n"
                << "  BPF filter : NONE (all EtherTypes pass, including IPv6)\n"
                << "\n"
                << "  Expected topology:\n"
                << "   [Source ports] ──── Switch SPAN session ────> [Mirror port]\n"
                << "                                                      |\n"
                << "                                              [This interface]\n"
                << "\n"
                << "  If no traffic arrives within 10 seconds, verify:\n"
                << "    1. Switch SPAN source ports are configured.\n"
                << "    2. Mirror destination port matches this interface's cable.\n"
                << "    3. VLAN trunking is enabled on the mirror destination port.\n"
                << "    4. Source ports are carrying active traffic.\n"
                << "\n"
                << "  Delta-NIDS is PASSIVE: it never transmits, routes, or blocks.\n"
                << "\n";
        }
        return 0;
    }

    const auto result = manager.select_auto();
    if (!result.selected) {
        std::cerr << "[ERROR] " << result.error << '\n'
                  << "[ERROR] Use --list-interfaces to inspect available adapters.\n";
        return 2;
    }
    std::cout << "[INFO] Capture mode: AUTO\n"
              << "[INFO] Candidate interfaces: " << result.candidates.size() << '\n'
              << "[INFO] Selected interface: " << result.interface.info.name << '\n'
              << "[INFO] Capture backend: "
              << backend_name(result.interface.info.capture_backend) << '\n'
              << "[INFO] Selection reason: " << result.interface.reason << '\n';
    return 0;
}
