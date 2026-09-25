#include "capture/packet_capture.h"
#include "packet/packet.h"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

static void put16(std::vector<std::uint8_t>& b, std::size_t p, std::uint16_t v) { b[p]=static_cast<std::uint8_t>(v); b[p+1]=static_cast<std::uint8_t>(v>>8); }
static void put32(std::vector<std::uint8_t>& b, std::size_t p, std::uint32_t v) { for(int i=0;i<4;++i)b[p+i]=static_cast<std::uint8_t>(v>>(8*i)); }

int main() {
    const std::string path = "delta_nids_regression.pcap";
    std::vector<std::uint8_t> bytes(24 + 16 + 14 + 20 + 8 + 4, 0);
    put32(bytes,0,0xa1b2c3d4); put16(bytes,4,2); put16(bytes,6,4); put32(bytes,16,65535); put32(bytes,20,1);
    auto p = std::size_t{24}; put32(bytes,p,1700000000); put32(bytes,p+4,123000); put32(bytes,p+8,46); put32(bytes,p+12,46); p += 16;
    bytes[p+12]=0x08; bytes[p+13]=0x00; p += 14;
    bytes[p]=0x45; bytes[p+2]=0; bytes[p+3]=32; bytes[p+8]=64; bytes[p+9]=17; bytes[p+12]=10; bytes[p+15]=1; bytes[p+16]=10; bytes[p+19]=2; p += 20;
    bytes[p+1]=0x35; bytes[p+2]=0x04; bytes[p+3]=0xd2; bytes[p+4]=0; bytes[p+5]=12; p += 8;
    bytes[p]=1; bytes[p+1]=2; bytes[p+2]=3; bytes[p+3]=4;
    std::ofstream output(path, std::ios::binary); output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())); output.close();

    delta_nids::capture::CaptureConfig config; config.pcap_path = path;
    auto capture = delta_nids::capture::make_capture(config);
    std::size_t count = 0; std::string canonical;
    capture->run([&](delta_nids::capture::CapturedPacket packet) {
        ++count; const auto decoded = delta_nids::packet::decode(packet, "pcap"); assert(decoded.status == delta_nids::packet::DecodeStatus::valid); assert(decoded.packet);
        canonical += decoded.packet->source.to_string() + ">" + decoded.packet->destination.to_string() + ":" + std::to_string(*decoded.packet->destination_port) + ":" + std::to_string(decoded.packet->payload.size());
    });
    std::remove(path.c_str());
    assert(count == 1); assert(canonical == "10.0.0.1>10.0.0.2:1234:4");
    return 0;
}
