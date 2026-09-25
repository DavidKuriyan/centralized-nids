#include "api/api_server.h"
#include "telemetry/telemetry.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <cstdlib>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_type = SOCKET;
constexpr socket_type invalid_socket = INVALID_SOCKET;
#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_type = int;
constexpr socket_type invalid_socket = -1;
#endif

namespace delta_nids::api {
namespace {
using json = nlohmann::json;

void close_socket(socket_type socket) noexcept {
#ifdef _WIN32
    closesocket(socket);
#else
    close(socket);
#endif
}

json alert_json(const alert::Alert& value) {
    return {{"id",value.id},{"first_seen",value.first_seen},{"last_seen",value.last_seen},{"timestamp",value.last_seen},{"occurrence_count",value.occurrence_count},{"suppressed_count",value.suppressed_count},{"severity",alert::severity_name(value.severity)},{"confidence",value.confidence / 100.0},{"risk",value.risk},{"gid",value.gid},{"sid",value.sid},{"revision",value.revision},{"source_ip",value.source_ip},{"source_port",value.source_port},{"destination_ip",value.destination_ip},{"destination_port",value.destination_port},{"protocol",value.protocol},{"service",value.service},{"flow_id",value.flow_id},{"traffic_id",value.traffic_id},{"message",value.message},{"evidence",value.evidence},{"explanation",value.explanation}};
}
json traffic_json(const storage::TrafficRecord& value) {
    // Network endpoint identity is always IP-based. Ethernet addresses are
    // intentionally absent from the normal traffic API contract.
    return {{"id",value.id},{"timestamp",value.timestamp},{"src_ip",value.src_ip},{"src_port",value.src_port},{"dst_ip",value.dst_ip},{"dst_port",value.dst_port},{"protocol",value.protocol},{"length",value.length},{"payload_summary",value.payload_summary}};
}

bool parse_size(std::string_view text, std::size_t& output) {
    if (text.empty()) return false;
    const auto* begin=text.data(); const auto* end=begin+text.size(); std::size_t value=0;
    const auto result=std::from_chars(begin,end,value);
    if(result.ec!=std::errc{} || result.ptr!=end) return false;
    output=value; return true;
}

std::string url_decode(std::string_view value) {
    std::string decoded;
    decoded.reserve(value.size());
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (value[index] == '+') {
            decoded.push_back(' ');
            continue;
        }
        if (value[index] == '%' && index + 2 < value.size()) {
            const auto hex = [](char character) -> int {
                if (character >= '0' && character <= '9') return character - '0';
                if (character >= 'a' && character <= 'f') return character - 'a' + 10;
                if (character >= 'A' && character <= 'F') return character - 'A' + 10;
                return -1;
            };
            const int high = hex(value[index + 1]);
            const int low = hex(value[index + 2]);
            if (high >= 0 && low >= 0) {
                decoded.push_back(static_cast<char>((high << 4) | low));
                index += 2;
                continue;
            }
        }
        decoded.push_back(value[index]);
    }
    return decoded;
}

// Accepts Unix epoch seconds or a server-local "YYYY-MM-DD[ HH:MM[:SS]]" value so
// searches use the same clock the NIDS runs on (see /api/system).
bool parse_time_filter(const std::string& text, std::int64_t& output) {
    if (text.empty() || text.size() > 32) return false;
    if (text.find_first_not_of("0123456789") == std::string::npos) {
        try { output = std::stoll(text); } catch (...) { return false; }
        return output >= 0;
    }
    static const char* const formats[] = {"%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"};
    for (const char* const format : formats) {
        std::tm parts{};
        parts.tm_isdst = -1;
        std::istringstream stream(text);
        stream >> std::get_time(&parts, format);
        if (stream.fail()) continue;
        std::string remainder;
        std::getline(stream, remainder);
        if (!remainder.empty()) continue;
        const std::time_t value = std::mktime(&parts);
        if (value == static_cast<std::time_t>(-1)) continue;
        output = static_cast<std::int64_t>(value);
        return true;
    }
    return false;
}
json incident_json(const incident::Incident& value) {
    json alerts = json::array();
    for (const auto id : value.alert_ids) alerts.push_back(id);
    return {{"id",value.id},{"first_seen",value.first_seen},{"last_seen",value.last_seen},{"status",incident::status_name(value.status)},{"severity",alert::severity_name(value.severity)},{"confidence",value.confidence},{"risk",value.risk},{"category",value.category},{"event_count",value.event_count},{"explanation",value.explanation},{"alert_ids",alerts},{"source_ips",value.source_entities},{"destination_ips",value.destination_entities}};
}

struct Query { std::unordered_map<std::string,std::string> values; };
Query parse_query(std::string_view query) {
    Query result; std::size_t start=0; std::size_t fields=0;
    while(start<query.size() && fields++<64) { const auto separator=query.find('&',start); const auto token=query.substr(start,separator==std::string_view::npos?query.size()-start:separator-start); const auto equal=token.find('='); if(equal!=std::string_view::npos && equal>0) result.values.emplace(url_decode(token.substr(0,equal)),url_decode(token.substr(equal+1))); if(separator==std::string_view::npos) break; start=separator+1; }
    return result;
}

}  // namespace

class ApiServer::Impl {
public:
    Impl(ServerConfig config, storage::Storage& storage) : config_(std::move(config)), storage_(storage) {
        if(config_.port==0 || config_.maximum_request_bytes<1024) throw std::invalid_argument("invalid API server configuration");
    }
    ~Impl(){ stop(); }
    void start() {
        if (running_.load()) return;
#ifdef _WIN32
        WSADATA data{}; if(WSAStartup(MAKEWORD(2,2),&data)!=0) throw std::runtime_error("WSAStartup failed");
#endif
        listener_=socket(AF_INET,SOCK_STREAM,0); if(listener_==invalid_socket) throw std::runtime_error("unable to create API socket");
        int reuse=1; setsockopt(listener_,SOL_SOCKET,SO_REUSEADDR,reinterpret_cast<const char*>(&reuse),sizeof(reuse));
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_port=htons(config_.port); if(inet_pton(AF_INET,config_.host.c_str(),&address.sin_addr)!=1){close_listener();throw std::invalid_argument("API host must be an IPv4 address");}
        if(bind(listener_,reinterpret_cast<sockaddr*>(&address),sizeof(address))!=0 || listen(listener_,32)!=0){close_listener();throw std::runtime_error("unable to bind API server");}
        timeval timeout{}; timeout.tv_sec=0; timeout.tv_usec=100000;
        setsockopt(listener_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        running_.store(true);
    }
    void run(){
        start();
        while(running_.load()) { sockaddr_in client{};
#ifdef _WIN32
            int length=sizeof(client);
#else
            socklen_t length=sizeof(client);
#endif
            const auto connection=accept(listener_,reinterpret_cast<sockaddr*>(&client),&length); if(connection==invalid_socket){if(running_.load()) continue;break;} std::thread(&Impl::handle,this,connection).detach(); }
        close_listener();
    }
    void stop() noexcept {
        running_.store(false);        if(listener_!=invalid_socket){
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_port = htons(config_.port);
            inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
            const auto wake = ::socket(AF_INET, SOCK_STREAM, 0);
            if (wake != invalid_socket) {
                (void)::connect(wake, reinterpret_cast<sockaddr*>(&address), sizeof(address));
                close_socket(wake);
            }
            shutdown(listener_, SHUT_RDWR);
            close_socket(listener_);
            listener_ = invalid_socket;
        }
    }
    const ServerConfig& config() const noexcept { return config_; }
    bool running() const noexcept { return running_.load(); }
private:
    void handle(socket_type connection) noexcept {
        std::string request; request.reserve(config_.maximum_request_bytes); char buffer[1024];
        for(;;){
#ifdef _WIN32
            const int count=recv(connection,buffer,sizeof(buffer),0);
#else
            const auto count=recv(connection,buffer,sizeof(buffer),0);
#endif
            if(count<=0) { close_socket(connection); return; }
            if(request.size()+static_cast<std::size_t>(count)>config_.maximum_request_bytes){ send_response(connection,413,{{"error","request too large"}}); return; }
            request.append(buffer,static_cast<std::size_t>(count));
            if(request.find("\r\n\r\n")!=std::string::npos) break;
        }
        const auto line_end=request.find("\r\n"); if(line_end==std::string::npos || request.find("\r\n\r\n")==std::string::npos){send_response(connection,400,{{"error","malformed HTTP request"}});return;}
        std::istringstream line(request.substr(0,line_end)); std::string method,target,version; line>>method>>target>>version;
        if (method.empty() || target.empty() || version.empty() || target.size() > config_.maximum_request_bytes) { send_response(connection,400,{{"error","malformed HTTP request line"}}); return; }
        if((method!="GET" && method!="DELETE") || (version!="HTTP/1.1" && version!="HTTP/1.0")){send_response(connection,405,{{"error","only GET and DELETE are supported"}});return;}
        const auto query_start=target.find('?'); const auto path=target.substr(0,query_start); const auto query=query_start==std::string::npos?std::string{}:target.substr(query_start+1); const auto parsed=parse_query(query);
        int status=200; const auto body=route(method,path,parsed,status); send_response(connection,status,body);
    }
    json route(const std::string& method,const std::string& path,const Query& query,int& status) const {
        if(method=="DELETE") {
            if(path=="/api/alerts") return {{"cleared",storage_.clear_alerts()}};
            if(path=="/api/traffic") return {{"cleared",storage_.clear_traffic()}};
            if(path=="/api/reset") {
                // Clear all tables in one serialized request. Runtime reporting is
                // immediately recreated by the capture heartbeat; no capture
                // restart is required.
                return {{"alerts", storage_.clear_alerts()}, {"traffic", storage_.clear_traffic()},
                        {"incidents", storage_.clear_incidents()}, {"flows", storage_.clear_flows()},
                        {"statistics", storage_.clear_statistics()}};
            }
            status=405; return {{"error","DELETE is only supported for /api/alerts, /api/traffic, or /api/reset"}};
        }
        if(path=="/api/status") {
            json result={{"name","Delta-NIDS"},{"status","running"},{"api_status","connected"},{"detection_engine","native API/storage services running"},{"passive_only",true},{"rules_loaded",storage_.count_rows("rules")}};
            const auto runtime = storage_.query_statistics({1, 500});
            const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            for (const auto& item : runtime.items) {
                if (item.name != "capture_runtime" || item.text_value.empty()) continue;
                try {
                    const auto value = json::parse(item.text_value);
                    const auto timestamp = static_cast<std::time_t>(item.timestamp);
                    if (now - timestamp <= 30) {
                        result["capture_status"] = value.value("status", "UNKNOWN");
                        result["capture_activity"] = value.value("status", "UNKNOWN");
                        result["interface"] = value.value("interface", "");
                        result["packets_captured"] = value.value("packets_captured", 0);
                        result["packets_processed"] = value.value("packets_processed", 0);
                        result["packets_failed"] = value.value("packets_failed", 0);
                        result["last_packet_time"] = value.value("last_packet_time", 0.0);
                    } else {
                        result["capture_status"] = "STALE";
                    }
                } catch (...) {
                    result["capture_status"] = "UNKNOWN";
                }
                break;
            }
            if (!result.contains("capture_status")) result["capture_status"] = "NOT_REPORTED";
            return result;
        }
        if(path=="/api/stats") {
            json result={{"alerts",storage_.count_rows("alerts")},{"incidents",storage_.count_rows("incidents")},{"flows",storage_.count_rows("flows")},{"detection_events",storage_.count_rows("detection_events")},{"traffic",storage_.count_rows("traffic_logs")}};
            for(const auto& [name,value] : telemetry::MetricsRegistry::global().snapshot().counters) result[name]=value;
            const auto persisted = storage_.query_statistics({1, 500});
            for (const auto& item : persisted.items) {
                if (item.name == "packets_processed" || item.name == "bytes_processed") {
                    if (!result.contains(item.name) || result[item.name].get<std::int64_t>() < item.value) result[item.name] = item.value;
                }
            }
            return result;
        }
        if(path=="/api/system") {
            const auto now = std::chrono::system_clock::now();
            const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
            const std::time_t wall = std::chrono::system_clock::to_time_t(now);
            std::tm local{};
            std::int64_t offset = 0;
            std::string zone = "UTC";
#ifdef _WIN32
            if (localtime_s(&local, &wall) == 0) {
                long bias = 0; int daylight = 0;
                _get_timezone(&bias);
                _get_daylight(&daylight);
                offset = daylight && local.tm_isdst > 0 ? -bias + 3600 : -bias;
                zone = daylight && local.tm_isdst > 0 ? _tzname[1] : _tzname[0];
            }
#else
            if (localtime_r(&wall, &local) != nullptr) {
                // POSIX tzname values are abbreviations (for example EDT), not valid
                // Intl.DateTimeFormat identifiers. Use an explicitly configured IANA
                // zone; otherwise expose a self-consistent UTC contract.
                const char* configured_zone = std::getenv("DELTA_NIDS_TIMEZONE");
                if (configured_zone != nullptr && std::string(configured_zone).find('/') != std::string::npos) {
                    zone = configured_zone;
                    offset = static_cast<std::int64_t>(local.tm_gmtoff);
                }
            }
#endif
            return {{"platform","portable"},{"api_host",config_.host},{"api_port",config_.port},{"epoch_seconds",epoch},{"timezone_offset_seconds",offset},{"timezone_name",zone}};
        }
        if(path=="/api/config") return {{"api_host",config_.host},{"api_port",config_.port},{"maximum_request_bytes",config_.maximum_request_bytes}};
        if(path=="/api/alerts/export") {
            storage::AlertFilter filter;
            if (auto it = query.values.find("search"); it != query.values.end()) filter.search = it->second;
            const auto value = storage_.query_alerts({1, 500}, filter);
            json items = json::array();
            for (const auto& item : value.items) {
                items.push_back({
                    {"timestamp", item.last_seen}, {"gid", item.gid}, {"sid", item.sid},
                    {"rev", item.revision}, {"message", item.message},
                    {"priority", item.risk > 0 ? std::max(1, 5 - item.risk / 25) : 3},
                    {"severity", alert::severity_name(item.severity)}, {"protocol", item.protocol},
                    {"source", {{"ip", item.source_ip}, {"port", item.source_port}}},
                    {"destination", {{"ip", item.destination_ip}, {"port", item.destination_port}}},
                    {"confidence", item.confidence / 100.0}, {"action", "ALERT"}, {"alert_id", item.id}
                });
            }
            return items;
        }
        if(path=="/api/traffic/export") {
            storage::TrafficFilter filter;
            if (auto it = query.values.find("search"); it != query.values.end()) filter.search = it->second;
            if (auto it = query.values.find("protocol"); it != query.values.end()) filter.protocol = it->second;
            const auto value = storage_.query_traffic_export(filter);
            json items = json::array();
            for (const auto& item : value.items) items.push_back(traffic_json(item));
            return items;
        }
        if(path.rfind("/api/alerts/",0)==0){ std::size_t id=0; if(!parse_size(path.substr(12),id)){status=400;return {{"error","invalid alert id"}};} alert::Alert value; if(!storage_.get_alert(id,value)){status=404;return {{"error","alert not found"}};} return alert_json(value); }
        if(path.rfind("/api/incidents/",0)==0){ std::size_t id=0; if(!parse_size(path.substr(15),id)){status=400;return {{"error","invalid incident id"}};} incident::Incident value; if(!storage_.get_incident(id,value)){status=404;return {{"error","incident not found"}};} auto result = incident_json(value); const auto related = storage_.query_incident_alerts(id, {1, 500}); json alerts = json::array(); for (const auto& alert : related.items) alerts.push_back(alert_json(alert)); result["alerts"] = std::move(alerts); result["alert_count"] = related.total; return result; }
        if(path.rfind("/api/traffic/",0)==0){ std::size_t id=0; if(!parse_size(path.substr(13),id)){status=400;return {{"error","invalid traffic id"}};} storage::TrafficRecord value; if(!storage_.get_traffic(id,value)){status=404;return {{"error","traffic record not found"}};} return traffic_json(value); }
        storage::PageRequest page; if(auto it=query.values.find("page");it!=query.values.end()&&!parse_size(it->second,page.page)){status=400;return {{"error","invalid page"}};} if(auto it=query.values.find("page_size");it!=query.values.end()&&!parse_size(it->second,page.page_size)){status=400;return {{"error","invalid page_size"}};} if(page.page==0||page.page_size==0){status=400;return {{"error","page and page_size must be positive"}};}
        if(path=="/api/alerts"){storage::AlertFilter filter; if(auto it=query.values.find("severity");it!=query.values.end())filter.severity=it->second; if(auto it=query.values.find("source_ip");it!=query.values.end())filter.source_ip=it->second; if(auto it=query.values.find("destination_ip");it!=query.values.end())filter.destination_ip=it->second; if(auto it=query.values.find("message");it!=query.values.end())filter.message=it->second; if(auto it=query.values.find("protocol");it!=query.values.end())filter.protocol=it->second; if(auto it=query.values.find("search");it!=query.values.end())filter.search=it->second; if(auto it=query.values.find("since");it!=query.values.end()){std::int64_t since=0;if(!parse_time_filter(it->second,since)){status=400;return {{"error","invalid since timestamp"}};}filter.since=since;} if(auto it=query.values.find("until");it!=query.values.end()){std::int64_t until=0;if(!parse_time_filter(it->second,until)){status=400;return {{"error","invalid until timestamp"}};}filter.until=until;} if(auto it=query.values.find("sid");it!=query.values.end()){std::size_t sid=0;if(!parse_size(it->second,sid)){status=400;return {{"error","invalid sid"}};}filter.sid=static_cast<std::uint32_t>(sid);} const auto value=storage_.query_alerts(page,filter);json items=json::array();for(const auto& item:value.items)items.push_back(alert_json(item));return {{"items",items},{"page",page.page},{"page_size",std::min<std::size_t>(page.page_size,500)},{"total",value.total}};}
        if(path=="/api/traffic"){storage::TrafficFilter filter; if(auto it=query.values.find("search");it!=query.values.end())filter.search=it->second; if(auto it=query.values.find("src_ip");it!=query.values.end())filter.src_ip=it->second; if(auto it=query.values.find("dst_ip");it!=query.values.end())filter.dst_ip=it->second; if(auto it=query.values.find("protocol");it!=query.values.end())filter.protocol=it->second; if(auto it=query.values.find("since");it!=query.values.end()){std::int64_t since=0;if(!parse_time_filter(it->second,since)){status=400;return {{"error","invalid since timestamp"}};}filter.since=since;} if(auto it=query.values.find("until");it!=query.values.end()){std::int64_t until=0;if(!parse_time_filter(it->second,until)){status=400;return {{"error","invalid until timestamp"}};}filter.until=until;} const auto value=storage_.query_traffic(page,filter);json items=json::array();for(const auto& item:value.items)items.push_back(traffic_json(item));return {{"items",items},{"page",page.page},{"page_size",std::min<std::size_t>(page.page_size,500)},{"total",value.total}};}
        if(path=="/api/incidents"){storage::IncidentFilter filter;if(auto it=query.values.find("status");it!=query.values.end())filter.status=it->second;if(auto it=query.values.find("category");it!=query.values.end())filter.category=it->second;if(auto it=query.values.find("search");it!=query.values.end())filter.search=it->second;const auto value=storage_.query_incidents(page,filter);json items=json::array();for(const auto& item:value.items)items.push_back(incident_json(item));return {{"items",items},{"page",page.page},{"page_size",std::min<std::size_t>(page.page_size,500)},{"total",value.total}};}
        if(path=="/api/flows"){const auto value=storage_.query_flows(page);json items=json::array();for(const auto& item:value.items)items.push_back({{"id",item.id},{"start_time",item.start_time},{"last_seen",item.last_seen},{"service",item.service},{"protocol",item.protocol},{"packets",item.packets},{"bytes",item.bytes}});return {{"items",items},{"page",page.page},{"page_size",std::min<std::size_t>(page.page_size,500)},{"total",value.total}};}
        if(path=="/api/rules"){storage::RuleFilter filter;if(auto it=query.values.find("search");it!=query.values.end())filter.search=it->second;const auto value=storage_.query_rules(page,filter);json items=json::array();for(const auto& item:value.items)items.push_back({{"gid",item.gid},{"sid",item.sid},{"revision",item.revision},{"message",item.message},{"priority",item.priority},{"protocol",item.protocol},{"enabled",item.enabled},{"source_file",item.source_file}});return {{"items",items},{"page",page.page},{"page_size",std::min<std::size_t>(page.page_size,500)},{"total",value.total}};}
        if(path=="/api/detection-events"){const auto value=storage_.query_detection_events(page);json items=json::array();for(const auto& item:value.items)items.push_back({{"timestamp",item.timestamp},{"flow_id",item.flow_id},{"sid",item.sid},{"event_type",item.event_type},{"explanation",item.explanation},{"evidence",item.evidence}});return {{"items",items},{"page",page.page},{"page_size",std::min<std::size_t>(page.page_size,500)},{"total",value.total}};}
        if(path=="/api/statistics"){const auto value=storage_.query_statistics(page);json items=json::array();for(const auto& item:value.items)items.push_back({{"timestamp",item.timestamp},{"name",item.name},{"value",item.value}});return {{"items",items},{"page",page.page},{"page_size",std::min<std::size_t>(page.page_size,500)},{"total",value.total}};}
        status=404; return {{"error","not found"}};
    }
    void send_response(socket_type connection,int status,const json& body) noexcept { const auto payload=body.dump(); const std::string reason=status==200?"OK":status==400?"Bad Request":status==404?"Not Found":status==405?"Method Not Allowed":status==413?"Payload Too Large":"Error"; const auto response="HTTP/1.1 "+std::to_string(status)+" "+reason+"\r\nContent-Type: application/json\r\nContent-Length: "+std::to_string(payload.size())+"\r\nConnection: close\r\n\r\n"+payload; send(connection,response.data(),static_cast<int>(response.size()),0);
#ifdef _WIN32
    shutdown(connection, SD_SEND);
#endif
    close_socket(connection); }
    void close_listener() noexcept { if(listener_!=invalid_socket){close_socket(listener_);listener_=invalid_socket;} }
    ServerConfig config_; storage::Storage& storage_; std::atomic<bool> running_{false}; socket_type listener_=invalid_socket;
};

ApiServer::ApiServer(ServerConfig config,storage::Storage& storage):implementation_(std::make_unique<Impl>(std::move(config),storage)){}
ApiServer::~ApiServer()=default;
void ApiServer::run(){implementation_->run();}
void ApiServer::start(){implementation_->start();}
void ApiServer::stop() noexcept{implementation_->stop();}
bool ApiServer::running() const noexcept{return implementation_->running();}
const ServerConfig& ApiServer::config() const noexcept{return implementation_->config();}

}  // namespace delta_nids::api
