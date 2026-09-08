# Security Hardening & Threat Model Specification

Centralized-NIDS operates on the security premise that all packet bytes, PCAP files, external rule definitions, and API client requests represent untrusted, potentially adversarial inputs.

---

## 1. Security Architecture & Invariants

Centralized-NIDS enforces key defensive architectural guarantees:

* **Strict Input Bounds Checking**: All packet parsing routines perform explicit byte boundary validation prior to accessing headers, lengths, offsets, or payload slices, eliminating buffer over-read and under-read vulnerabilities.
* **Resilient Error Containment**: Malformed or deliberately corrupt packets generate decode error status codes and increment telemetry failure counters without halting the capture process.
* **Passive Isolation**: The core engine contains no routines capable of injecting packets, transmitting TCP resets, modifying operating system firewalls, altering routing tables, or triggering automated active responses.
* **Parameterized Persistence**: All database interactions with SQLite use strictly parameterized SQL queries, completely eliminating SQL injection vectors.
* **Bounded Resource Allocation**: Flow records, behavioral scan caches, fragment tables, and persistence queues are hard-bounded to prevent memory exhaustion and algorithmic complexity attacks.
* **Local-First API Exposure**: The native C++ HTTP REST API and Flask dashboard bind to `127.0.0.1` (loopback) by default.

---

## 2. Threat Model Analysis

| Threat Vector | Potential Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Malformed Packet Floods** | Process crash / DoS | Defensive decoding with explicit slice bounds; exceptions caught and logged to telemetry counters. |
| **State Table Exhaustion** | Memory exhaustion / OOM | Hard-bounded flow maps with LRU eviction and sliding-window expiration timers. |
| **ReDoS (Regular Expression DoS)** | High CPU consumption | Rule compilation validates PCRE patterns for catastrophic backtracking risks. |
| **SQL Injection** | Database corruption | Exclusive use of prepared statements and parameterized bindings across all queries. |
| **Sensor Network Exposure** | Host discovery on mirror link | Unnumbered listener configuration: disabling IPv4 ARP and IPv6 auto-configuration on the capture NIC. |
| **API Abuse / Flooding** | Denial of service to console | Query limits on `/api/alerts` and `/api/traffic`; loopback binding by default. |

---

## 3. Production Deployment Hardening

### Principle of Least Privilege
* **Linux**: Rather than running the entire NIDS suite as `root`, grant only capture capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`) to the capture binary or use an unprivileged user group for capture device access.
* **Windows**: Run the capture service under a dedicated service account possessing Npcap driver access rights.

### Network Ingress Isolation
For SPAN / mirror links:
1. Strip IP addresses from the sensor NIC (unbind IPv4/IPv6 stacks).
2. Disable ARP replies and neighbor discovery on the listening interface.
3. Keep the Web Console and REST API behind an authenticated reverse proxy (e.g., NGINX with TLS and mutual authentication) if remote operations access is required.
