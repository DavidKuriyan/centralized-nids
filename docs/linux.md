# Linux Operations Manual

This guide outlines setup, privilege management, interface discovery, systemd service configuration, and troubleshooting for Centralized-NIDS on Linux systems.

---

## 1. System Requirements & Installation

Centralized-NIDS supports modern Linux distributions including Ubuntu 20.04+, Debian 11+, and RHEL 8+.

### Package Installation
```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev libsqlite3-dev python3 python3-venv python3-pip
```

### Repository & Python Setup
```bash
git clone https://github.com/DavidKuriyan/centralized-nids.git
cd centralized-nids

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 2. Compilation & Verification

```bash
# Build native engine and tests
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build --config Release -j$(nproc)

# Run test suite
ctest --test-dir build --output-on-failure
```

---

## 3. Network Interface Discovery & Configuration

### Interface Discovery
List all physical and virtual interfaces alongside the engine's deterministic suitability ranking:

```bash
./build/delta-nids --list-interfaces
```

The auto-selection algorithm ranks adapters based on link state, loopback avoidance, and promiscuous capabilities. To specify an adapter explicitly:

```bash
./build/delta-nids --interface eth0
```

### Capture Privileges
Live packet acquisition requires access to raw sockets. Two deployment methods are supported:

#### Method A: Linux Capabilities (Recommended / Non-Root)
Grant capture capabilities to the Python or native binary:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip build/delta-nids
```

#### Method B: Elevated Execution
```bash
sudo -E env HOME="$HOME" PATH="$PATH" .venv/bin/python run_project.py --interface eth0
```

*Note: Offline PCAP replay does not require any elevated privileges.*

---

## 4. Production Service Deployment (systemd)

To run Centralized-NIDS as a continuous background daemon on Linux, create a systemd service unit:

```ini
# /etc/systemd/system/centralized-nids.service
[Unit]
Description=Centralized Network Intrusion Detection System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/centralized-nids
ExecStart=/opt/centralized-nids/.venv/bin/python run_project.py --interface eth0 --capture-mode span
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable centralized-nids
sudo systemctl start centralized-nids
sudo systemctl status centralized-nids
```

---

## 5. Troubleshooting & Diagnostics

* **libpcap failure upon initialization**: Ensure `libpcap-dev` is installed and the capture interface is in an `UP` operational state (`ip link show <interface>`).
* **Zero packets captured**: Verify that the interface is receiving frames using an independent `tcpdump -i <interface> -nn -c 10`.
* **Database lock / Permission denied**: Ensure the directory containing the SQLite database is writable by the user running the engine.
