# Building & Compilation Guide

This document outlines the prerequisites, toolchain requirements, CMake build configurations, and compilation procedures for the **Centralized-NIDS** native engine and test harness.

---

## 1. Prerequisites & Toolchain Requirements

Centralized-NIDS requires a C++17 compliant compiler and CMake 3.20 or newer.

### Supported Platforms & Compilers
* **Linux**: GCC 9.0+, Clang 10.0+ (Ubuntu 20.04+, Debian 11+, RHEL 8+)
* **Windows**: Microsoft Visual C++ (MSVC) 2022 (v143 toolset) or Clang/LLVM with MSVC runtime

### Native Dependencies
* **CMake** (>= 3.20)
* **libpcap** (Linux) or **Npcap SDK** (Windows)
* **SQLite3** (Automatically resolved via system package or FetchContent build)
* **nlohmann-json** (Automatically resolved via system package or FetchContent pinned v3.11.3)

---

## 2. Linux Build Instructions

### Install Build Dependencies
```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev libsqlite3-dev
```

### Standard Release Build
```bash
# Generate build files
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DDELTA_NIDS_BUILD_TESTS=ON

# Compile the project
cmake --build build --config Release -j$(nproc)

# Run test suite
ctest --test-dir build --output-on-failure
```

### Developer Build with Strict Warnings
Maintainers can treat all compiler warnings as errors:
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DDELTA_NIDS_ENABLE_WERROR=ON -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build -j$(nproc)
```

---

## 3. Windows Build Instructions

### Developer Environment Setup
Launch the **Developer PowerShell for VS 2022** (or Developer Command Prompt) to ensure MSVC environment variables (`cl.exe`, `cmake.exe`, `ninja.exe`) are active.

Ensure **Npcap SDK** headers and libraries are installed or placed in the standard library path if compiling against native packet capture.

### Build via Visual Studio CMake Generator
```powershell
# Configure build
cmake -S . -B build -DDELTA_NIDS_BUILD_TESTS=ON

# Build Release binary
cmake --build build --config Release

# Run test suite
ctest --test-dir build --output-on-failure
```

### High-Speed Build via Ninja
```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

The output executable is located at `build/delta-nids` (Linux) or `build/Release/delta-nids.exe` (Windows).

---

## 4. CMake Options Reference

| CMake Option | Default | Description |
| :--- | :--- | :--- |
| `DELTA_NIDS_BUILD_TESTS` | `ON` | Builds GoogleTest unit and integration tests. |
| `DELTA_NIDS_ENABLE_WERROR` | `OFF` | Enables `-Werror` (GCC/Clang) or `/WX` (MSVC) treating warnings as errors. |
| `CMAKE_BUILD_TYPE` | `Release` | Selects compiler optimization level (`Debug`, `Release`, `RelWithDebInfo`). |

---

## 5. Dependency Strategy & Reproducibility

Centralized-NIDS adheres to strict dependency isolation:
1. **Zero External Runtime DLL Hell**: Core detection, decoding, and flow tracking are pure C++17 with zero third-party runtime dependencies beyond the system C/C++ runtime and libpcap/Npcap.
2. **Deterministic FetchContent**: Third-party header libraries such as `nlohmann-json` and embedded SQLite are declared via CMake's `FetchContent` with pinned immutable commit tags and download hashes.
3. **Platform Isolation**: All OS-specific networking routines (raw packet socket bindings, interface discovery, privilege checks) are encapsulated behind modular platform wrappers under `src/interface/` and `src/capture/`.

---

## 6. Binary Validation & Sanity Checks

Verify the compiled binary operational flags:

```bash
# Display discovered interfaces and selection scores
./build/delta-nids --list-interfaces

# Validate signature rules syntax
./build/delta-nids --validate-rules tests/fixtures/valid.rules.json

# Display engine metrics and telemetry
./build/delta-nids --stats
```
