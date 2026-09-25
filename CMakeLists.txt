cmake_minimum_required(VERSION 3.20)

project(DeltaNIDS VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
include(GNUInstallDirs)

option(DELTA_NIDS_BUILD_TESTS "Build Delta-NIDS tests" ON)
option(DELTA_NIDS_ENABLE_WERROR "Treat compiler warnings as errors" OFF)

find_package(PCAP QUIET)
include(FetchContent)

find_package(nlohmann_json QUIET)
find_package(SQLite3 QUIET)
if(NOT SQLite3_FOUND)
    FetchContent_Declare(
        sqlite3
        URL https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(sqlite3)
    add_library(sqlite3_lib STATIC "${sqlite3_SOURCE_DIR}/sqlite3.c")
    set_target_properties(sqlite3_lib PROPERTIES LINKER_LANGUAGE CXX)
    target_include_directories(sqlite3_lib PUBLIC "${sqlite3_SOURCE_DIR}")
    add_library(SQLite3::SQLite3 ALIAS sqlite3_lib)
    set(SQLite3_FOUND TRUE)
endif()
if(NOT nlohmann_json_FOUND)
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()
if(NOT PCAP_FOUND)
    find_path(PCAP_INCLUDE_DIRS NAMES pcap/pcap.h pcap.h
        HINTS
            "$ENV{NPCAP_SDK}/Include"
            "$ENV{ProgramFiles}/Npcap SDK/Include"
            "$ENV{ProgramFiles(x86)}/Npcap SDK/Include"
            "C:/Npcap-sdk/Include"
            "C:/Users/Admin/Downloads/npcap-sdk-1.16/Include"
        PATHS
            /usr/include
            /usr/local/include
            /opt/homebrew/include
    )
    find_library(PCAP_LIBRARIES NAMES pcap wpcap
        HINTS
            "$ENV{NPCAP_SDK}/Lib/x64"
            "$ENV{NPCAP_SDK}/Lib"
            "$ENV{ProgramFiles}/Npcap SDK/Lib/x64"
            "$ENV{ProgramFiles}/Npcap SDK/Lib"
            "$ENV{ProgramFiles(x86)}/Npcap SDK/Lib/x64"
            "$ENV{ProgramFiles(x86)}/Npcap SDK/Lib"
            "C:/Npcap-sdk/Lib/x64"
            "C:/Npcap-sdk/Lib"
            "C:/Users/Admin/Downloads/npcap-sdk-1.16/Lib/x64"
            "C:/Users/Admin/Downloads/npcap-sdk-1.16/Lib"
        PATHS
            /usr/lib
            /usr/local/lib
            /usr/lib/x86_64-linux-gnu
            /opt/homebrew/lib
    )
    if(PCAP_INCLUDE_DIRS AND PCAP_LIBRARIES)
        set(PCAP_FOUND TRUE)
    endif()
endif()
if(NOT PCAP_FOUND)
    message(FATAL_ERROR "libpcap/Npcap development files are required to build Delta-NIDS")
endif()


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive-)
    if(DELTA_NIDS_ENABLE_WERROR)
        add_compile_options(/WX)
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(DELTA_NIDS_ENABLE_WERROR)
        add_compile_options(-Werror)
    endif()
endif()

add_library(delta_nids_core STATIC
    src/core/version.cpp
    src/telemetry/telemetry.cpp
    src/evaluation/evaluation.cpp
    src/interface/interface_manager.cpp
    src/interface/interface_scorer.cpp
    src/capture/packet_capture.cpp
    src/capture/pcap_capture.cpp
    src/capture/ipv6_fragment_cache.cpp
    src/capture/span_diagnostics.cpp
    src/packet/packet.cpp
    src/packet/decoder.cpp
    src/flow/flow.cpp
    src/flow/flow_manager.cpp
    src/flow/tcp_reassembly.cpp
    src/protocol/service_identifier.cpp
    src/protocol/http_inspector.cpp
    src/protocol/dns_inspector.cpp
    src/protocol/tls_inspector.cpp
    src/protocol/simple_inspectors.cpp
    src/protocol/inspector_manager.cpp
    src/detection/detection_buffer.cpp
    src/detection/buffer_builder.cpp
    src/detection/rule_parser.cpp
    src/detection/rule_matcher.cpp
    src/detection/detection_engine.cpp
    src/behavioral/behavioral_detectors.cpp
    src/alert/alert_manager.cpp
    src/incident/incident_manager.cpp
    src/storage/sqlite_storage.cpp
    src/api/api_server.cpp
)
target_include_directories(delta_nids_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/src
)
target_compile_features(delta_nids_core PUBLIC cxx_std_17)
target_include_directories(delta_nids_core PRIVATE ${PCAP_INCLUDE_DIRS})
if(TARGET SQLite3::SQLite3)
    set(DELTA_NIDS_SQLITE_TARGET SQLite3::SQLite3)
else()
    set(DELTA_NIDS_SQLITE_TARGET SQLite::SQLite3)
endif()
target_link_libraries(delta_nids_core PRIVATE ${PCAP_LIBRARIES} nlohmann_json::nlohmann_json ${DELTA_NIDS_SQLITE_TARGET})
if(WIN32)
    target_link_libraries(delta_nids_core PRIVATE ws2_32)
endif()

add_library(delta_nids_platform STATIC
    src/interface/system_interface_provider.cpp
)
target_link_libraries(delta_nids_platform PUBLIC delta_nids_core)

target_include_directories(delta_nids_platform PUBLIC ${PROJECT_SOURCE_DIR}/src)

if(WIN32)
    target_sources(delta_nids_platform PRIVATE
        src/platform/windows/windows_platform.cpp
        src/platform/windows/windows_interface_provider.cpp
    )
    target_link_libraries(delta_nids_platform PRIVATE iphlpapi ws2_32)
else()
    target_sources(delta_nids_platform PRIVATE
        src/platform/linux/linux_platform.cpp
        src/platform/linux/linux_interface_provider.cpp
    )
endif()

add_executable(delta-nids
    src/main.cpp
)
target_link_libraries(delta-nids PRIVATE delta_nids_platform)
target_compile_features(delta-nids PRIVATE cxx_std_17)

install(TARGETS delta-nids RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(DELTA_NIDS_BUILD_TESTS)
    enable_testing()
    add_executable(delta-nids-security-test
        tests/unit/security_hardening_test.cpp
    )
    target_link_libraries(delta-nids-security-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-security-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-security-test COMMAND delta-nids-security-test)

    add_executable(delta-nids-performance-test
        tests/unit/performance_test.cpp
    )
    target_link_libraries(delta-nids-performance-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-performance-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-performance-test COMMAND delta-nids-performance-test)

    add_executable(delta-nids-evaluation-test
        tests/unit/evaluation_test.cpp
    )
    target_link_libraries(delta-nids-evaluation-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-evaluation-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-evaluation-test COMMAND delta-nids-evaluation-test)

    add_executable(delta-nids-pcap-regression-test
        tests/unit/pcap_regression_test.cpp
    )
    target_link_libraries(delta-nids-pcap-regression-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-pcap-regression-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-pcap-regression-test COMMAND delta-nids-pcap-regression-test)

    add_executable(delta-nids-windows-provider-test
        tests/unit/windows_provider_test.cpp
    )
    target_link_libraries(delta-nids-windows-provider-test PRIVATE delta_nids_platform)
    target_compile_features(delta-nids-windows-provider-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-windows-provider-test COMMAND delta-nids-windows-provider-test)

    add_executable(delta-nids-version-test
        tests/unit/version_test.cpp
    )
    target_link_libraries(delta-nids-version-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-version-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-version-test COMMAND delta-nids-version-test)

    add_executable(delta-nids-platform-test
        tests/unit/platform_test.cpp
    )
    target_link_libraries(delta-nids-platform-test PRIVATE delta_nids_platform)
    target_compile_features(delta-nids-platform-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-platform-test COMMAND delta-nids-platform-test)

    add_executable(delta-nids-interface-test
        tests/unit/interface_test.cpp
    )
    target_link_libraries(delta-nids-interface-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-interface-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-interface-test COMMAND delta-nids-interface-test)

    add_executable(delta-nids-capture-test
        tests/unit/capture_test.cpp
    )
    target_link_libraries(delta-nids-capture-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-capture-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-capture-test COMMAND delta-nids-capture-test)

    add_executable(delta-nids-packet-test
        tests/unit/packet_test.cpp
    )
    target_link_libraries(delta-nids-packet-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-packet-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-packet-test COMMAND delta-nids-packet-test)

    add_executable(delta-nids-flow-test
        tests/unit/flow_test.cpp
    )
    target_link_libraries(delta-nids-flow-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-flow-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-flow-test COMMAND delta-nids-flow-test)

    add_executable(delta-nids-reassembly-test
        tests/unit/reassembly_test.cpp
    )
    target_link_libraries(delta-nids-reassembly-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-reassembly-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-reassembly-test COMMAND delta-nids-reassembly-test)

    add_executable(delta-nids-service-test
        tests/unit/service_test.cpp
    )
    target_link_libraries(delta-nids-service-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-service-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-service-test COMMAND delta-nids-service-test)

    add_executable(delta-nids-inspector-test
        tests/unit/inspector_test.cpp
    )
    target_link_libraries(delta-nids-inspector-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-inspector-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-inspector-test COMMAND delta-nids-inspector-test)

    add_executable(delta-nids-buffer-test
        tests/unit/buffer_test.cpp
    )
    target_link_libraries(delta-nids-buffer-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-buffer-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-buffer-test COMMAND delta-nids-buffer-test)

    add_executable(delta-nids-rule-test
        tests/unit/rule_test.cpp
    )
    target_link_libraries(delta-nids-rule-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-rule-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-rule-test COMMAND delta-nids-rule-test)
    set_tests_properties(delta-nids-rule-test PROPERTIES WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

    add_executable(delta-nids-matcher-test
        tests/unit/matcher_test.cpp
    )
    target_link_libraries(delta-nids-matcher-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-matcher-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-matcher-test COMMAND delta-nids-matcher-test)

    add_executable(delta-nids-detection-test
        tests/unit/detection_test.cpp
    )
    target_link_libraries(delta-nids-detection-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-detection-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-detection-test COMMAND delta-nids-detection-test)

    add_executable(delta-nids-behavioral-test
        tests/unit/behavioral_test.cpp
    )
    target_link_libraries(delta-nids-behavioral-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-behavioral-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-behavioral-test COMMAND delta-nids-behavioral-test)

    add_executable(delta-nids-alert-test
        tests/unit/alert_test.cpp
    )
    target_link_libraries(delta-nids-alert-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-alert-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-alert-test COMMAND delta-nids-alert-test)

    add_executable(delta-nids-incident-test
        tests/unit/incident_test.cpp
    )
    target_link_libraries(delta-nids-incident-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-incident-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-incident-test COMMAND delta-nids-incident-test)

    add_executable(delta-nids-storage-test
        tests/unit/storage_test.cpp
    )
    target_link_libraries(delta-nids-storage-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-storage-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-storage-test COMMAND delta-nids-storage-test)

    add_executable(delta-nids-api-test
        tests/unit/api_test.cpp
    )
    target_link_libraries(delta-nids-api-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-api-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-api-test COMMAND delta-nids-api-test)

    add_executable(delta-nids-telemetry-test
        tests/unit/telemetry_test.cpp
    )
    target_link_libraries(delta-nids-telemetry-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-telemetry-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-telemetry-test COMMAND delta-nids-telemetry-test)

    add_executable(delta-nids-api-integration-test
        tests/unit/api_integration_test.cpp
    )
    target_link_libraries(delta-nids-api-integration-test PRIVATE delta_nids_core nlohmann_json::nlohmann_json ${DELTA_NIDS_SQLITE_TARGET})
    target_compile_features(delta-nids-api-integration-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-api-integration-test COMMAND delta-nids-api-integration-test)

    add_executable(delta-nids-span-test
        tests/unit/span_capture_test.cpp
    )
    target_link_libraries(delta-nids-span-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-span-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-span-test COMMAND delta-nids-span-test)

    add_executable(delta-nids-ipv6-test
        tests/unit/ipv6_capture_test.cpp
    )
    target_link_libraries(delta-nids-ipv6-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-ipv6-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-ipv6-test COMMAND delta-nids-ipv6-test)

    add_executable(delta-nids-vlan-test
        tests/unit/vlan_test.cpp
    )
    target_link_libraries(delta-nids-vlan-test PRIVATE delta_nids_core)
    target_compile_features(delta-nids-vlan-test PRIVATE cxx_std_17)
    add_test(NAME delta-nids-vlan-test COMMAND delta-nids-vlan-test)

    if(WIN32)
        set_tests_properties(
            delta-nids-security-test
            delta-nids-performance-test
            delta-nids-evaluation-test
            delta-nids-pcap-regression-test
            delta-nids-windows-provider-test
            delta-nids-version-test
            delta-nids-platform-test
            delta-nids-interface-test
            delta-nids-capture-test
            delta-nids-packet-test
            delta-nids-flow-test
            delta-nids-reassembly-test
            delta-nids-service-test
            delta-nids-inspector-test
            delta-nids-buffer-test
            delta-nids-rule-test
            delta-nids-matcher-test
            delta-nids-detection-test
            delta-nids-behavioral-test
            delta-nids-alert-test
            delta-nids-incident-test
            delta-nids-storage-test
            delta-nids-api-test
            delta-nids-telemetry-test
            delta-nids-api-integration-test
            delta-nids-span-test
            delta-nids-ipv6-test
            delta-nids-vlan-test
            PROPERTIES ENVIRONMENT "PATH=C:/Windows/System32/Npcap;$ENV{PATH}"
        )
    endif()
endif()

