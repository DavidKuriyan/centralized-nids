# PCAP Regression Testing & Verification Framework

PCAP replay provides an isolated, deterministic, and cross-platform verification harness. By reading raw frame timestamps and payloads from standard capture files, the normalization, reassembly, rule evaluation, and behavioral detection pipelines are validated identically on both Linux and Windows.

---

## 1. Regression Framework Principles

* **Deterministic Input**: Eliminates live network jitter, link drops, and non-reproducible external traffic bursts.
* **Privilege Independence**: PCAP replay runs without requiring raw socket capabilities or administrative elevation.
* **Normalized Equivalence**: Verifies that decoded protocol semantics (IP addresses, transport ports, flags, payload slices) match expected ground truth regardless of host OS endianness or filesystem paths.

---

## 2. Running the Test Harness

### C++ Native Test Harness
```bash
# Run all unit and PCAP regression tests
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

### Python Automated Test Suite
```bash
# Run all Python test cases
python -m unittest discover -s tests -p "test_*.py"

# Run specific regression modules
python -m unittest tests/test_ipv6_pipeline.py
python -m unittest tests/test_span_capture.py
python -m unittest tests/test_vlan_capture.py
```

### Offline Local Validation Matrix
```bash
python tools/validate_local.py
python tools/validate_local.py --json
```

---

## 3. Creating New PCAP Regression Test Cases

When introducing a new detection signature or behavioral heuristic:
1. Capture or synthesize a minimal `.pcap` containing the target traffic pattern.
2. Store the file under `tests/fixtures/` or `captures/`.
3. Create an automated test asserting:
   * **Exact SID match**: Verifies the intended signature or heuristic fires.
   * **Evidence validation**: Confirms that extracted metadata fields (target ports, query names, flag values) match expected packet evidence.
   * **Negative isolation**: Verifies that no unintended alerts or false positives are generated.
