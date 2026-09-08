# Detection Quality Evaluation Framework

Centralized-NIDS uses a deterministic, repeatable quality evaluation framework to benchmark detection precision, recall, and false-positive resilience without relying on opaque heuristics.

---

## 1. Evaluation Methodology

Detection quality is evaluated using labeled traffic corpora comprising both positive attack cases and realistic negative baseline traffic. A labeled case defines:

* **Case Identifier**: Unique, stable name for the traffic scenario.
* **Target Truth**: Ground-truth specification of whether an alert should be raised (`Expected`).
* **Observed Outcome**: Engine output produced during pipeline processing (`Observed`).

---

## 2. Confusion Matrix & Formal Metrics

Each test evaluation assigns results into standard confusion matrix categories:

| Metric | Classification | Description |
| :--- | :--- | :--- |
| **True Positive (TP)** | Expected Alert = Yes, Observed Alert = Yes | Correct detection of malicious or anomalous traffic. |
| **False Positive (FP)** | Expected Alert = No, Observed Alert = Yes | Benign baseline traffic incorrectly flagged as an attack. |
| **True Negative (TN)** | Expected Alert = No, Observed Alert = No | Benign baseline traffic correctly allowed without alerting. |
| **False Negative (FN)** | Expected Alert = Yes, Observed Alert = No | Malicious probe pattern missed by the detection engine. |

### Mathematical Scoring Criteria

```text
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1 Score  = 2 * (Precision * Recall) / (Precision + Recall)
```

*(Where denominators evaluate to zero, metrics are reported as 0.0 to prevent undefined numerical state.)*

---

## 3. Negative Control Integrity

High precision requires evaluating realistic negative controls. Negative test corpora must exercise:
* Multi-destination HTTP/HTTPS browsing sessions to public CDNs and search engines.
* High-volume local ARP address resolution between gateways and network neighbors.
* Single-host ICMP echo diagnostics (`ping 8.8.8.8`).
* Asymmetric and out-of-order TCP teardowns (FIN/RST closures).
* Valid DNS multi-record lookups and reverse in-addr queries.

Negative cases must **never** be reduced to empty capture files.

---

## 4. Normalization and Reproducibility

Evaluations are performed against normalized alert records rather than transient system fields:
1. **Rule SIDs**: Matches exact signature or behavioral identifier (e.g., `90003`).
2. **5-Tuple Scope**: Validates source IP, destination IP, protocol, and observed ports.
3. **Evidence Contracts**: Confirms that alert evidence fields match real packet-derived facts (e.g., list of distinct destination ports or host targets).

Timestamps, local network adapter GUIDs, and file offsets are excluded from equivalence testing to guarantee cross-platform test repeatability on Linux and Windows.
