// L2-L4 parsing and building (Ethernet, 802.1Q, IPv4, TCP).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "irbridge/util.hpp"

namespace irbridge::net {

using Ip4 = std::uint32_t;  // host byte order

std::string ip_to_string(Ip4 ip);
bool parse_ip(const std::string& s, Ip4& out);

enum TcpFlags : std::uint8_t {
  kFin = 0x01,
  kSyn = 0x02,
  kRst = 0x04,
  kPsh = 0x08,
  kAck = 0x10,
};

struct TcpSegment {
  util::Micros ts = 0;
  Ip4 src = 0, dst = 0;
  std::uint16_t sport = 0, dport = 0;
  std::uint32_t seq = 0, ack = 0;
  std::uint8_t flags = 0;
  const std::uint8_t* payload = nullptr;
  std::size_t payload_len = 0;
};

struct ParseStats {
  std::uint64_t packets = 0;
  std::uint64_t not_ipv4 = 0;
  std::uint64_t not_tcp = 0;
  std::uint64_t ip_fragments = 0;
  std::uint64_t malformed = 0;
};

// Parses an Ethernet frame. Returns false for anything that is not a well-formed, unfragmented
// IPv4/TCP packet. The payload pointer refers into `frame`.
bool parse_ethernet(const std::uint8_t* frame, std::size_t len, util::Micros ts, TcpSegment& out, ParseStats& st);

// Builds an Ethernet/IPv4/TCP frame with valid checksums (traffic generator, tests).
std::vector<std::uint8_t> build_tcp_frame(Ip4 src, std::uint16_t sport, Ip4 dst, std::uint16_t dport,
                                          std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
                                          const std::uint8_t* payload, std::size_t len);

}  // namespace irbridge::net
