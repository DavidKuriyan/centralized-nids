#include "capture/span_diagnostics.h"

#include <pcap/pcap.h>

#include <sstream>
#include <string>

namespace delta_nids::capture {

SpanValidationResult validate_span_interface(const std::string& interface_name) noexcept {
    SpanValidationResult result;
    if (interface_name.empty()) {
        result.error_message = "interface name must not be empty";
        return result;
    }

    // --- Check 1: interface is present in pcap's device list ---
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t* devices = nullptr;
    if (pcap_findalldevs(&devices, errbuf) == 0 && devices) {
        for (const pcap_if_t* dev = devices; dev; dev = dev->next) {
            if (dev->name && interface_name == dev->name) {
                result.iface_found = true;
                // PCAP_IF_UP is defined in libpcap ≥ 1.6.1.
#ifdef PCAP_IF_UP
                result.iface_up = (dev->flags & PCAP_IF_UP) != 0;
#else
                result.iface_up = true;  // Cannot determine; assume UP.
#endif
                break;
            }
        }
        pcap_freealldevs(devices);
    }
    if (!result.iface_found) {
        result.error_message = "interface '" + interface_name +
            "' was not found. Run --list-interfaces to see available adapters.";
        return result;
    }
    if (!result.iface_up) {
        // Not fatal — the interface may be UP at Layer 1 even if the OS
        // reports it as administratively down (common on dedicated monitor
        // ports).  Report but allow capture to proceed.
    }

    // --- Check 2: libpcap can open the interface ---
    pcap_t* handle = pcap_create(interface_name.c_str(), errbuf);
    if (!handle) {
        result.error_message = "libpcap cannot open interface '" + interface_name + "': " + errbuf;
        return result;
    }
    result.pcap_ok = true;

    // --- Check 3: promiscuous mode can be set ---
    if (pcap_set_promisc(handle, 1) != 0) {
        result.error_message =
            "promiscuous mode cannot be set on '" + interface_name +
            "'. Check that the process has capture permissions "
            "(Linux: run as root or add CAP_NET_RAW; Windows: run as Administrator).";
        pcap_close(handle);
        return result;
    }
    pcap_set_snaplen(handle, 65535);
    pcap_set_timeout(handle, 100);

    const int activated = pcap_activate(handle);
    if (activated < 0) {
        result.error_message =
            "interface activation failed for '" + interface_name +
            "': " + pcap_statustostr(activated);
        pcap_close(handle);
        return result;
    }
    result.promisc_ok = true;
    pcap_close(handle);

    result.ok = true;
    return result;
}

std::string zero_traffic_diagnostic(const std::string& interface_name,
                                    double seconds_elapsed) noexcept {
    std::ostringstream out;
    out << "\n"
        << "╔════════════════════════════════════════════════════════════════╗\n"
        << "║         DELTA-NIDS  —  ZERO TRAFFIC WARNING                   ║\n"
        << "╚════════════════════════════════════════════════════════════════╝\n"
        << "\n"
        << "  Interface  : " << interface_name << "\n"
        << "  Elapsed    : " << static_cast<long>(seconds_elapsed) << " seconds\n"
        << "  Packets    : 0\n"
        << "\n"
        << "  No traffic has been received on the SPAN interface.\n"
        << "  This does NOT mean the sensor is broken — it means the\n"
        << "  switch SPAN configuration has not yet sent any frames\n"
        << "  to this port.  Verify the following:\n"
        << "\n"
        << "  1. Switch SPAN / RSPAN / ERSPAN is configured.\n"
        << "     ─ Source ports (the ports you want to monitor) are selected.\n"
        << "     ─ Destination port is set to the port this NIDS is connected to.\n"
        << "     ─ Direction: BOTH (ingress + egress) is recommended.\n"
        << "\n"
        << "  2. Physical connection:\n"
        << "     ─ An Ethernet cable connects the switch mirror destination\n"
        << "       port to the NIDS network interface ('" << interface_name << "').\n"
        << "     ─ The cable and SFP (if used) are seated correctly.\n"
        << "\n"
        << "  3. VLAN configuration:\n"
        << "     ─ If source ports are in specific VLANs, the SPAN session\n"
        << "       must include those VLANs.\n"
        << "     ─ The mirror destination port should be in trunk mode or\n"
        << "       configured to pass all VLANs.\n"
        << "\n"
        << "  4. Source ports are carrying traffic:\n"
        << "     ─ Generate some traffic on the source machines\n"
        << "       (e.g. ping, web browser) and check again.\n"
        << "\n"
        << "  5. Permissions:\n"
        << "     ─ Linux  : run as root or with CAP_NET_RAW.\n"
        << "     ─ Windows: run as Administrator with Npcap installed.\n"
        << "\n"
        << "  Delta-NIDS remains passive and will begin processing frames\n"
        << "  as soon as mirrored traffic arrives on this interface.\n"
        << "\n";
    return out.str();
}

std::string zero_traffic_warning_short(const std::string& interface_name) noexcept {
    return "No traffic detected on SPAN interface '" + interface_name +
           "'. Check switch SPAN source ports, mirror destination port, "
           "cable connection, VLAN configuration, and switch SPAN configuration.";
}

}  // namespace delta_nids::capture
