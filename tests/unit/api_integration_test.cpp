#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <future>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>
#include <sqlite3.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_type = SOCKET;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_type = int;
#endif

#include "api/api_server.h"
#include "storage/storage.h"

namespace {
using json = nlohmann::json;
void close_socket(socket_type socket) {
#ifdef _WIN32
    closesocket(socket);
#else
    close(socket);
#endif
}
std::string request(std::uint16_t port, const std::string& request_text, bool split=false) {
    const auto socket = ::socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    assert(socket != INVALID_SOCKET);
#else
    assert(socket >= 0);
#endif
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_port=htons(port); inet_pton(AF_INET,"127.0.0.1",&address.sin_addr);
    if (connect(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address))!=0) { close_socket(socket); return {}; }
    if (split) { const auto midpoint=request_text.size()/2; send(socket,request_text.data(),static_cast<int>(midpoint),0); std::this_thread::sleep_for(std::chrono::milliseconds(2)); send(socket,request_text.data()+midpoint,static_cast<int>(request_text.size()-midpoint),0); }
    else send(socket,request_text.data(),static_cast<int>(request_text.size()),0);
#ifdef _WIN32
    shutdown(socket, SD_SEND);
#else
    shutdown(socket, SHUT_WR);
#endif
    std::string response; char buffer[512]; int received=0; while((received=recv(socket,buffer,sizeof(buffer),0))>0) response.append(buffer,received); close_socket(socket); return response;
}
int status(const std::string& response) { if(response.size()<12 || response.rfind("HTTP/",0)!=0) return 0; return std::stoi(response.substr(9,3)); }
json body(const std::string& response) { return json::parse(response.substr(response.find("\r\n\r\n")+4)); }
std::string get(std::uint16_t port,const std::string& path) { return request(port,"GET "+path+" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); }
}

int main() {
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
    const char* path="delta-nids-api-integration.sqlite"; std::remove(path);
    auto storage=delta_nids::storage::make_sqlite_storage({path,128});
    delta_nids::alert::Alert alert; alert.id=7; alert.first_seen=1; alert.last_seen=1; alert.occurrence_count=1; alert.source_ip="192.0.2.1"; alert.destination_ip="198.51.100.1"; alert.severity=delta_nids::alert::Severity::high; alert.fingerprint="api-test"; storage->store_alert(alert);
    delta_nids::incident::Incident incident; incident.id=8; incident.first_seen=1; incident.last_seen=1; incident.category="signature"; incident.alert_ids.insert(7); storage->store_incident(incident); storage->flush();
    // The relation table is part of the production schema; seed it to verify expanded incident evidence.
    {
        sqlite3* raw = nullptr;
        assert(sqlite3_open(path, &raw) == SQLITE_OK);
        assert(sqlite3_exec(raw, "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (8, 7);", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    constexpr std::uint16_t port=18888;
    delta_nids::api::ApiServer server({"127.0.0.1",port,1024},*storage);
    std::thread server_thread([&server]{server.run();});
    for(int attempt=0;attempt<500 && !server.running();++attempt) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    assert(server.running());

    auto    response=get(port,"/api/status"); assert(status(response)==200); auto status_json=body(response); assert(status_json.at("name")=="Delta-NIDS"); assert(status_json.at("passive_only")==true);
    response=get(port,"/api/alerts?page=1&page_size=1&source_ip=192.0.2.1"); assert(status(response)==200); auto alerts=body(response); assert(alerts.contains("items")&&alerts.contains("total")&&alerts.at("items").size()==1);
    response=get(port,"/api/alerts/7"); assert(status(response)==200); assert(body(response).at("id")==7);
    response=get(port,"/api/incidents/8"); assert(status(response)==200); assert(body(response).at("id")==8); assert(body(response).at("alert_count")==1); assert(body(response).at("alerts").at(0).at("id")==7);
    response=get(port,"/api/alerts/999"); assert(status(response)==404);
    response=get(port,"/api/not-found"); assert(status(response)==404);
    response=request(port,"POST /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n"); assert(status(response)==405);
    response=request(port,"GET /api/status HTTP/1.1\r\nHost: localhost\r\n",false); assert(status(response)==0);
    response=request(port,"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",true); assert(status(response)==200);
    response=request(port,"GET /api/status HTTP/1.1\r\nHost: localhost\r\nX: "+std::string(1200,'x')+"\r\n\r\n"); assert(status(response)==413 || status(response)==400);

    std::vector<std::future<int>> clients;
    for(int index=0;index<8;++index) clients.push_back(std::async(std::launch::async,[port]{
#ifdef _WIN32
        WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        return status(get(port,"/api/status"));
    }));
    for(auto& client:clients) assert(client.get()==200);

    server.stop(); server_thread.join(); storage->flush(); std::remove(path); return 0;
}
