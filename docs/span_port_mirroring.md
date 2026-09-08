# SPAN / Port Mirroring Deployment Guide for Delta-NIDS

This guide provides step-by-step instructions for configuring switch port mirroring (SPAN) and deploying Delta-NIDS to monitor mirrored network traffic in production.

Delta-NIDS operates strictly as a **passive network intrusion detection system**. It does not inject traffic, modify frames, send TCP resets, or participate in routing / Spanning Tree protocols.

---

## 1. Overview & Passive Architecture

In a Switched Port Analyzer (SPAN) or port mirroring setup, the network switch creates a copy of network packets passing through designated source ports, VLANs, or aggregation uplinks and directs them to a dedicated mirror destination port connected to Delta-NIDS.

```text
               ┌───────────────────────────────────────────────┐
               │         Core / Distribution Switch            │
               │                                               │
               │  [Port 1]      [Port 2]      [Port 3]         │
               └───┬──────────────┬──────────────┬─────────────┘
                   │              │              │
                [Client]       [Server]      [Firewall]
                   │              │              │
                   └───────┬──────┴──────────────┘
                           │ (Switch internally copies frames)
                           ▼
               ┌──────────────────────┐
               │ SPAN Destination     │
               │ Port (e.g. Port 24)  │
               └──────────┬───────────┘
                          │ (Passive unnumbered link)
                          ▼
               ┌───────────────────────────────────────────────┐
               │           Delta-NIDS Sensor Host              │
               │                                               │
               │  • Dedicated NIC in Promiscuous Mode          │
               │  • 802.1Q / QinQ VLAN tag stripping           │
               │  • IPv4 & IPv6 dual-stack protocol decoder    │
               │  • Real-time deduplication & reassembly       │
               │  • Rule engine & behavioral detectors         │
               │  • SQLite telemetry & Web monitoring console  │
               └───────────────────────────────────────────────┘
```

---

## 2. How to Enable Port Mirroring on Switches & Hypervisors

Choose your switch platform below to configure port mirroring to the port where the Delta-NIDS sensor NIC is connected.

### A. Cisco IOS / Catalyst Switches
Mirrors traffic from source ports (e.g., GigabitEthernet0/1 through 0/4) to the Delta-NIDS destination port (e.g., GigabitEthernet0/24):

```text
! Enter configuration mode
enable
configure terminal

! Remove any existing session 1
no monitor session 1

! Set source ports to monitor both ingress and egress (Rx and Tx)
monitor session 1 source interface GigabitEthernet0/1 - 4 both

! Set destination port where Delta-NIDS is connected
! 'encapsulation replicate' preserves 802.1Q VLAN headers for NIDS inspection
monitor session 1 destination interface GigabitEthernet0/24 encapsulation replicate

! Exit and save configuration
end
write memory
```

To monitor an entire VLAN instead of individual ports:
```text
monitor session 1 source vlan 10,20,30 both
monitor session 1 destination interface GigabitEthernet0/24 encapsulation replicate
```

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

### D. Juniper Junos (EX / QFX Series)
```text
edit
set forwarding-options analyzer DELTA_SPAN input ingress interface ge-0/0/0.0
set forwarding-options analyzer DELTA_SPAN input egress interface ge-0/0/0.0
set forwarding-options analyzer DELTA_SPAN output interface ge-0/0/23.0
commit and-quit
```

### E. Ubiquiti UniFi (Switch Controller)
1. In the **UniFi Network Controller**, go to **UniFi Devices**.
2. Select your switch and click **Port Manager**.
3. Select the destination port where Delta-NIDS is plugged in.
4. Set **Port Profile / Operation** to **Mirroring**.
5. Select the **Mirrored Port** (the source uplink or server port to monitor).
6. Click **Apply Changes**.

### F. MikroTik RouterOS
```text
# Mirror switch port ether1 to ether5 (connected to Delta-NIDS)
/interface ethernet switch
set mirror-source=ether1 mirror-target=ether5
```

### G. Linux / Open vSwitch (OVS)
Create a mirror on a Linux bridge or OVS switch:
```bash
# Open vSwitch mirror
ovs-vsctl -- --id=@p1 get port eth1 \
          -- --id=@m create mirror name=span0 select-all=true output-port=@p1 \
          -- set bridge br0 mirrors=@m
```

### H. VMware ESXi (vSphere vSwitch / Distributed Switch)
1. **Standard vSwitch**:
   - Go to **Networking** > **Virtual Switches** > Select your vSwitch > **Edit settings**.
   - Under **Security**, set **Promiscuous mode** to **Accept**.
2. **Distributed Switch (VDS)**:
   - In vSphere Client, go to **Networking** > Select VDS > **Configure** > **Port Mirroring**.
   - Add a new Port Mirroring Session (Type: **Distributed Port Mirroring**).
   - Add the target VMs / VNICs as **Sources** (Normal).
   - Add the Delta-NIDS VM virtual port as the **Destination**.

---

## 3. Host Interface Preparation (Zero-Interference)

The SPAN destination NIC should be configured purely as a listener so the sensor host never transmits traffic onto the mirror feed.

### Linux Sensor Host
```bash
# 1. Identify the mirror network interface name
ip link show

# 2. Set interface up and enable promiscuous mode
sudo ip link set eth1 promisc on up

# 3. Disable IPv6 auto-configuration and IPv4 ARP on the mirror NIC
sudo sysctl -w net.ipv6.conf.eth1.disable_ipv6=1
sudo sysctl -w net.ipv4.conf.eth1.arp_ignore=8
sudo sysctl -w net.ipv4.conf.eth1.arp_announce=2

# 4. Enlarge OS receive buffer for high-throughput microbursts
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

## 4. How to Run Delta-NIDS in SPAN Mode

Delta-NIDS provides three ways to run in SPAN mode depending on your workflow.

### Method 1: The Unified Launcher (Recommended for Full Operations)

The unified launcher starts the capture pipeline, SQLite database, native API, and web monitoring console together.

#### On Windows:
1. Open **PowerShell as Administrator**:
2. Activate your virtual environment and run:
```powershell
cd "d:\Cyber security Projects\New folder\Centralized-delta-nids\delta-ids"
.\.venv\Scripts\Activate.ps1

# List available network interfaces to find your SPAN adapter:
py -c "from scapy.all import show_interfaces; show_interfaces()"

# Run in SPAN mode on your mirror adapter (e.g. "Ethernet 2" or "eth1"):
py run_project.py --interface "Ethernet 2" --capture-mode span
```

#### On Linux:
```bash
cd /path/to/delta-ids
source .venv/bin/activate

# Run with sudo to permit promiscuous socket capture:
sudo -E env HOME="$HOME" PATH="$PATH" python run_project.py --interface eth1 --capture-mode span
```

Once running, access the web console at:
👉 **`http://127.0.0.1:8081`**

---

### Method 2: Standalone Python Capture Engine (`main.py`)

To run the continuous detection engine in terminal-only or background daemon mode:

```bash
# Basic SPAN capture
python main.py -i eth1 --capture-mode span

# SPAN capture with persistence, custom buffer (32 MB), and jumbo frame snap-length
python main.py -i eth1 --capture-mode span --snap-length 9216 --buffer-size 33554432 --persist --db database/nids.sqlite
```

---

### Method 3: Native C++ High-Performance Engine (`delta-nids`)

For maximum line-rate capture and low-latency rule evaluation:

```bash
# Build the C++ binary (if not already built)
cmake -S . -B build -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build --config Release

# Run in SPAN mode
./build/Release/delta-nids.exe -i eth1 --capture-mode span
# (On Linux: ./build/delta-nids -i eth1 --capture-mode span)
```

---

## 5. Verification & Health Monitoring

### 1. Zero-Traffic Watchdog
If the switch SPAN session is inactive, the cable is unplugged, or the wrong interface was specified, Delta-NIDS automatically detects that 0 packets have been received after 10–30 seconds and outputs an actionable warning:

```text
⚠ No traffic detected on SPAN interface 'eth1'.
Check:
  1. Switch SPAN session is configured and source ports are active.
  2. Ethernet cable connects the switch mirror port to this interface.
  3. VLAN trunking is enabled on the mirror port.
  4. Delta-NIDS process is running with Administrator / root privileges.
```

### 2. Live Dashboard Capture Status Panel
In the web dashboard (`http://127.0.0.1:8081`):
1. Navigate to the **Overview** page.
2. The **Capture status** panel displays:
   - **Capture Mode Badge**: Shows `SPAN MODE` in green.
   - **Interface State**: Confirms link status and promiscuous mode.
   - **Protocol Breakdown**: Live counters for IPv4, IPv6, 802.1Q VLAN, TCP, UDP, ICMP, and ICMPv6.
   - **Duplicates Filtered**: Displays the count of deduplicated mirror frames.

### 3. Quick Terminal Test
Generate benign test traffic on the network to verify the SPAN capture is receiving packets:
```bash
# From any host on the monitored network:
ping 8.8.8.8
curl -I https://www.google.com
```
Observe the **Packets seen** counter increase immediately in the console and web dashboard.
