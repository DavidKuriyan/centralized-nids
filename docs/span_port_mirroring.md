# SPAN / Port Mirroring Deployment Guide

This guide provides engineering procedures for deploying **Centralized-NIDS** on enterprise switch port mirroring sessions (SPAN), Remote SPAN (RSPAN), Encapsulated Remote SPAN (ERSPAN), and hypervisor virtual switches.

Centralized-NIDS operates strictly as a **passive network sensor**. It does not inject traffic, modify frames, send TCP resets, or participate in Spanning Tree Protocol (STP).

---

## 1. Architectural Model & Evidence Flow

In a Switched Port Analyzer (SPAN) deployment, the physical or virtual switch copies traffic traversing designated source ports, VLANs, or aggregation trunks and directs it to a dedicated mirror destination port connected to the sensor interface.

```text
               ┌───────────────────────────────────────────────┐
               │          Core / Distribution Switch           │
               │                                               │
               │  [Port 1]      [Port 2]      [Port 3]         │
               └───┬──────────────┬──────────────┬─────────────┘
                   │              │              │
                [Client]       [Server]      [Firewall]
                   │              │              │
                   └───────┬──────┴──────────────┘
                           │ (Switch internally replicates frames)
                           ▼
               ┌──────────────────────┐
               │ SPAN Destination     │
               │ Port (e.g. Port 24)  │
               └──────────┬───────────┘
                          │ (Passive unnumbered link)
                          ▼
               ┌───────────────────────────────────────────────┐
               │         Centralized-NIDS Sensor Host          │
               │                                               │
               │  • Dedicated NIC in Promiscuous Mode          │
               │  • 802.1Q / QinQ VLAN Tag Stripping           │
               │  • IPv4 & IPv6 Dual-Stack Protocol Decoder    │
               │  • Real-time Duplicate Filter & Reassembly    │
               │  • Signature Engine & Behavioral Detectors    │
               │  • SQLite Storage & Real-Time Web Console     │
               └───────────────────────────────────────────────┘
```

---

## 2. Switch Configuration Examples

### A. Cisco IOS / Catalyst Switches
Mirrors ingress and egress traffic from source access/trunk ports (e.g., `GigabitEthernet0/1 - 4`) to the sensor destination port (`GigabitEthernet0/24`). `encapsulation replicate` preserves 802.1Q VLAN headers for inspection.

```text
enable
configure terminal

! Remove any existing monitor session
no monitor session 1

! Configure source ports for bidirectional monitoring
monitor session 1 source interface GigabitEthernet0/1 - 4 both

! Configure destination port preserving VLAN tags
monitor session 1 destination interface GigabitEthernet0/24 encapsulation replicate

end
write memory
```

To mirror entire VLANs:
```text
monitor session 1 source vlan 10,20,30 both
monitor session 1 destination interface GigabitEthernet0/24 encapsulation replicate
```

---

### B. Cisco Nexus (NX-OS)
```text
configure terminal
monitor session 1
  source interface Ethernet1/1-4 both
  destination interface Ethernet1/48
  no shut
end
copy running-config startup-config
```

---

### C. Arista EOS
```text
enable
configure terminal
monitor session SPAN_NIDS
  source Ethernet1/1-4 both
  destination Ethernet1/48
end
write memory
```

---

### D. Juniper Junos (EX / QFX Series)
```text
edit
set forwarding-options analyzer CENTRAL_SPAN input ingress interface ge-0/0/0.0
set forwarding-options analyzer CENTRAL_SPAN input egress interface ge-0/0/0.0
set forwarding-options analyzer CENTRAL_SPAN output interface ge-0/0/23.0
commit and-quit
```

---

### E. Ubiquiti UniFi Switches
1. Navigate to **UniFi Devices** in the UniFi Controller.
2. Select your switch and open **Port Manager**.
3. Select the port connected to Centralized-NIDS.
4. Set **Port Profile / Operation** to **Mirroring**.
5. Select the target **Mirrored Port** (uplink or server port).
6. Apply changes.

---

### F. MikroTik RouterOS
```text
/interface ethernet switch
set mirror-source=ether1 mirror-target=ether5
```

---

### G. Linux / Open vSwitch (OVS)
```bash
ovs-vsctl -- --id=@p1 get port eth1 \
          -- --id=@m create mirror name=span0 select-all=true output-port=@p1 \
          -- set bridge br0 mirrors=@m
```

---

### H. VMware ESXi (vSphere Distributed Switch)
1. In vSphere Client, navigate to **Networking** > Select Distributed Switch > **Configure** > **Port Mirroring**.
2. Create a new Port Mirroring Session (Type: **Distributed Port Mirroring**).
3. Set source target VMs / vNICs as **Sources**.
4. Set the Centralized-NIDS VM virtual port as the **Destination**.
5. Ensure Promiscuous Mode is set to **Accept** on the destination port group.

---

## 3. Host Network Interface Hardening

The sensor network adapter should be unnumbered and configured strictly as a listener, preventing the sensor from emitting packets onto the mirror network.

### Linux Sensor Host
```bash
# 1. Bring up interface in promiscuous mode
sudo ip link set eth1 promisc on up

# 2. Disable IPv6 auto-configuration and IPv4 ARP on the mirror NIC
sudo sysctl -w net.ipv6.conf.eth1.disable_ipv6=1
sudo sysctl -w net.ipv4.conf.eth1.arp_ignore=8
sudo sysctl -w net.ipv4.conf.eth1.arp_announce=2

# 3. Expand OS socket receive buffers for bursty line rates
sudo sysctl -w net.core.rmem_max=67108864
sudo sysctl -w net.core.rmem_default=33554432
```

### Windows Sensor Host
1. Open **Control Panel** > **Network and Internet** > **Network Connections**.
2. Right-click the network adapter connected to the SPAN port > **Properties**.
3. Uncheck **Internet Protocol Version 4 (TCP/IPv4)**.
4. Uncheck **Internet Protocol Version 6 (TCP/IPv6)**.
5. Ensure **Npcap Packet Driver (NPCAP)** is checked.
6. Click **OK**.

---

## 4. Running Centralized-NIDS in SPAN Mode

### Method 1: The Unified Production Launcher (Recommended)
Orchestrates the SPAN capture pipeline, SQLite database, C++ REST API, and web monitoring console.

#### On Windows:
```powershell
# Open PowerShell as Administrator
cd "path\to\centralized-nids"
.\.venv\Scripts\Activate.ps1

# Run on the mirror adapter in SPAN mode:
py run_project.py --interface "Ethernet 2" --capture-mode span
```

#### On Linux:
```bash
cd /path/to/centralized-nids
source .venv/bin/activate

sudo -E env HOME="$HOME" PATH="$PATH" python run_project.py --interface eth1 --capture-mode span
```

Access the dashboard at: **`http://127.0.0.1:8081`**

---

### Method 2: Standalone Engine (`main.py`)
```bash
# Capture with custom buffer (32 MB) and jumbo frame snap-length
python main.py -i eth1 --capture-mode span --snap-length 9216 --buffer-size 33554432 --persist --db database/nids.sqlite
```

---

### Method 3: Native High-Speed C++ Engine
```bash
# Build Release executable
cmake -S . -B build -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build --config Release

# Run native binary in SPAN mode
./build/Release/delta-nids.exe -i eth1 --capture-mode span
# (On Linux: ./build/delta-nids -i eth1 --capture-mode span)
```

---

## 5. Health Monitoring & Verification

### 1. Zero-Traffic Watchdog
If the switch SPAN session is disabled or a cable is disconnected, Centralized-NIDS automatically detects 0 packets received and raises an operational warning:
```text
[WARN] Zero traffic observed on SPAN interface 'eth1' within watchdog window.
Verify:
  1. Switch mirror session configuration and administrative state.
  2. Physical cable and link state on mirror destination port.
  3. 802.1Q trunking / encapsulation replicate setting.
  4. Operating system capture privileges.
```

### 2. Live Web Console Metrics
The **Capture Status** panel in the web console (`http://127.0.0.1:8081`) reports:
* **Capture Mode Badge**: Displays `SPAN MODE` in green.
* **Interface State**: Verifies link status and promiscuous capture.
* **Protocol Distribution**: Live counters for IPv4, IPv6, 802.1Q VLAN, TCP, UDP, ICMP, and ICMPv6.
* **Deduplication Counter**: Shows total duplicate mirror frames absorbed.
