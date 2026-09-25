#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "storage/storage.h"

namespace delta_nids::api {

struct ServerConfig {
    std::string host = "127.0.0.1";
    std::uint16_t port = 8080;
    std::size_t maximum_request_bytes = 8192;
};

class ApiServer {
public:
    ApiServer(ServerConfig config, storage::Storage& storage);
    ~ApiServer();

    ApiServer(const ApiServer&) = delete;
    ApiServer& operator=(const ApiServer&) = delete;

    void run();
    void start();
    void stop() noexcept;
    [[nodiscard]] bool running() const noexcept;
    [[nodiscard]] const ServerConfig& config() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

}  // namespace delta_nids::api
