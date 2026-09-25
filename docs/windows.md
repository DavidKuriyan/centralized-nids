# Windows Operations Manual

This guide outlines prerequisites, driver setup, interface enumeration, PowerShell commands, and service management for Centralized-NIDS on Windows systems.

---

## 1. System Requirements & Installation

* **Operating System**: Windows 10 (64-bit), Windows 11, Windows Server 2019, or Windows Server 2022.
* **Npcap Driver**: Current version installed from [npcap.com](https://npcap.com/#download).
* **Python**: Python 3.10+ installed with PATH enabled.
* **Build Tools (Optional for C++ engine)**: Visual Studio 2022 with *Desktop development with C++*.

### Critical Npcap Driver Setup
During the Npcap installation wizard:
1. ✅ **Check: "Install Npcap in WinPcap API-compatible Mode"** (Required for standard libpcap wrappers).
2. ✅ **Check: "Support raw 802.11 traffic (and monitor mode) for wireless adapters"** (Optional).
3. If Npcap was installed without WinPcap compatibility, reinstall Npcap with this option checked.

---

## 2. Environment Setup & Build

### Configure Python Environment
Open PowerShell:
```powershell
git clone https://github.com/DavidKuriyan/centralized-nids.git
cd centralized-nids

py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
```

### Build C++ Engine
Launch **Developer PowerShell for VS 2022**:
```powershell
cmake -S . -B build -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

---

## 3. Interface Enumeration & Selection

Windows network interfaces possess both friendly names (e.g., `Ethernet`, `Wi-Fi`) and device GUIDs (e.g., `\Device\NPF_{...}`).

### List Discovered Adapters
```powershell
.\build\Release\delta-nids.exe --list-interfaces
```
Or via Python:
```powershell
py -c "from scapy.all import show_interfaces; show_interfaces()"
```

### Executing Live Capture
Run PowerShell **as Administrator**:
```powershell
# Auto-detect primary active interface:
py run_project.py

# Explicit friendly name matching:
py run_project.py --interface "Ethernet"
py run_project.py --interface "Wi-Fi"

# SPAN / Port Mirroring mode on dedicated capture NIC:
py run_project.py --interface "Ethernet 2" --capture-mode span
```

Access the console in your browser: **`http://127.0.0.1:8081`**

---

## 4. Operational Troubleshooting

* **Permission Denied / Npcap Error**: Ensure PowerShell is launched with elevated administrative privileges.
* **Npcap Driver Not Found**: Verify the Npcap service is running by executing `net start npcap` in an elevated command prompt.
* **Adapter Name Discrepancies**: Windows interface names are case-insensitive in Centralized-NIDS (`"Ethernet"`, `"ethernet"`, and `"ETHERNET"` all match the same adapter).
* **Firewall / Port Conflicts**: If port `8080` (API) or `8081` (Dashboard) is in use, pass `--api-port` or `--dashboard-port` to `run_project.py`.
