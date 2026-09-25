#include <cassert>
#include <cstdio>

#include "api/api_server.h"
#include "storage/storage.h"

int main() {
    const char* path = "delta-nids-api-test.sqlite";
    std::remove(path);
    auto storage = delta_nids::storage::make_sqlite_storage({path, 16});
    delta_nids::api::ApiServer server({"127.0.0.1", 18080, 8192}, *storage);
    assert(server.config().host == "127.0.0.1");
    assert(server.config().port == 18080);
    storage->flush();
    std::remove(path);
    return 0;
}
