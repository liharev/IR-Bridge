#include "irbridge/net.hpp"

#include <arpa/inet.h>

#include <cstdio>
#include <cstring>

namespace irbridge::net {

std::string ip_to_string(Ip4 ip) {
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
  return buf;
}

bool parse_ip(const std::string& s, Ip4& out) {
  in_addr a{};
  if (inet_pton(AF_INET, s.c_str(), &a) != 1) return false;
  out = ntohl(a.s_addr);
  return true;
}

namespace {
std::uint16_t rd16(const std::uint8_t* p) { return static_cast<std::uint16_t>((p[0] << 8) | p[1]); }
std::uint32_t rd32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}
void wr16(std::uint8_t* p, std::uint16_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 8);
  p[1] = static_cast<std::uint8_t>(v);
}
void wr32(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 24);
  p[1] = static_cast<std::uint8_t>(v >> 16);
  p[2] = static_cast<std::uint8_t>(v >> 8);
  p[3] = static_cast<std::uint8_t>(v);
}
std::uint32_t csum_add(std::uint32_t sum, const std::uint8_t* p, std::size_t n) {
  for (std::size_t i = 0; i + 1 < n; i += 2) sum += rd16(p + i);
  if (n & 1) sum += static_cast<std::uint32_t>(p[n - 1]) << 8;
  return sum;
}
std::uint16_t csum_fold(std::uint32_t sum) {
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return static_cast<std::uint16_t>(~sum);
}
}  // namespace

bool parse_ethernet(const std::uint8_t* frame, std::size_t len, util::Micros ts, TcpSegment& out, ParseStats& st) {
  ++st.packets;
  if (len < 14) {
    ++st.malformed;
    return false;
  }
  std::size_t off = 12;
  std::uint16_t ethertype = rd16(frame + off);
  off += 2;
  // Up to two VLAN tags (802.1Q / 802.1ad).
  for (int i = 0; i < 2 && (ethertype == 0x8100 || ethertype == 0x88A8); ++i) {
    if (len < off + 4) {
      ++st.malformed;
      return false;
    }
    ethertype = rd16(frame + off + 2);
    off += 4;
  }
  if (ethertype != 0x0800) {
    ++st.not_ipv4;
    return false;
  }
  if (len < off + 20) {
    ++st.malformed;
    return false;
  }
  const std::uint8_t* ip = frame + off;
  if ((ip[0] >> 4) != 4) {
    ++st.not_ipv4;
    return false;
  }
  const std::size_t ihl = static_cast<std::size_t>(ip[0] & 0x0F) * 4;
  const std::size_t total = rd16(ip + 2);
  if (ihl < 20 || total < ihl || len < off + total) {
    ++st.malformed;
    return false;
  }
  const std::uint16_t frag = rd16(ip + 6);
  if ((frag & 0x3FFF) != 0) {  // MF flag or non-zero offset
    ++st.ip_fragments;
    return false;
  }
  if (ip[9] != 6) {
    ++st.not_tcp;
    return false;
  }
  const std::uint8_t* tcp = ip + ihl;
  const std::size_t tcp_len = total - ihl;
  if (tcp_len < 20) {
    ++st.malformed;
    return false;
  }
  const std::size_t doff = static_cast<std::size_t>(tcp[12] >> 4) * 4;
  if (doff < 20 || doff > tcp_len) {
    ++st.malformed;
    return false;
  }
  out.ts = ts;
  out.src = rd32(ip + 12);
  out.dst = rd32(ip + 16);
  out.sport = rd16(tcp);
  out.dport = rd16(tcp + 2);
  out.seq = rd32(tcp + 4);
  out.ack = rd32(tcp + 8);
  out.flags = tcp[13];
  out.payload = tcp + doff;
  out.payload_len = tcp_len - doff;
  return true;
}

std::vector<std::uint8_t> build_tcp_frame(Ip4 src, std::uint16_t sport, Ip4 dst, std::uint16_t dport,
                                          std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
                                          const std::uint8_t* payload, std::size_t len) {
  std::vector<std::uint8_t> f(14 + 20 + 20 + len, 0);
  // Ethernet: locally administered MACs derived from the IPs.
  std::uint8_t* eth = f.data();
  eth[0] = 0x02;
  wr32(eth + 2, dst);
  eth[6] = 0x02;
  wr32(eth + 8, src);
  wr16(eth + 12, 0x0800);
  std::uint8_t* ip = eth + 14;
  ip[0] = 0x45;
  wr16(ip + 2, static_cast<std::uint16_t>(20 + 20 + len));
  wr16(ip + 6, 0x4000);  // DF
  ip[8] = 64;
  ip[9] = 6;
  wr32(ip + 12, src);
  wr32(ip + 16, dst);
  wr16(ip + 10, csum_fold(csum_add(0, ip, 20)));
  std::uint8_t* tcp = ip + 20;
  wr16(tcp, sport);
  wr16(tcp + 2, dport);
  wr32(tcp + 4, seq);
  wr32(tcp + 8, ack);
  tcp[12] = 5 << 4;
  tcp[13] = flags;
  wr16(tcp + 14, 65535);
  if (len > 0) std::memcpy(tcp + 20, payload, len);
  std::uint8_t pseudo[12];
  wr32(pseudo, src);
  wr32(pseudo + 4, dst);
  pseudo[8] = 0;
  pseudo[9] = 6;
  wr16(pseudo + 10, static_cast<std::uint16_t>(20 + len));
  std::uint32_t sum = csum_add(0, pseudo, sizeof(pseudo));
  sum = csum_add(sum, tcp, 20 + len);
  wr16(tcp + 16, csum_fold(sum));
  return f;
}

}  // namespace irbridge::net
