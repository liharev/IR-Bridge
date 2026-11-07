// Ethernet/IPv4/TCP parsing and the kernel BPF filter (run in a small classic-BPF interpreter).
#include <gtest/gtest.h>
#include <linux/filter.h>

#include "irbridge/capture.hpp"
#include "irbridge/net.hpp"

using namespace irbridge;

namespace {

const net::Ip4 kCtl = 0x0A2A0001;  // 10.42.0.1
const net::Ip4 kIr = 0x0A2A000B;   // 10.42.0.11

std::vector<std::uint8_t> frame(std::uint16_t sport, std::uint16_t dport, const std::string& payload = "IR") {
  return net::build_tcp_frame(kCtl, sport, kIr, dport, 1000, 2000, net::kAck | net::kPsh,
                              reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size());
}

std::vector<std::uint8_t> add_vlan(const std::vector<std::uint8_t>& f, std::uint16_t vid) {
  std::vector<std::uint8_t> v(f.begin(), f.begin() + 12);
  v.insert(v.end(), {0x81, 0x00, static_cast<std::uint8_t>(vid >> 8), static_cast<std::uint8_t>(vid & 0xFF)});
  v.insert(v.end(), f.begin() + 12, f.end());
  return v;
}

// Minimal classic BPF interpreter covering the instructions a socket filter may use.
std::uint32_t run_bpf(const std::vector<capture::BpfInsn>& prog, const std::vector<std::uint8_t>& pkt) {
  std::uint32_t A = 0, X = 0;
  std::uint32_t mem[16] = {};
  auto load = [&](std::uint32_t off, int size, bool& ok) -> std::uint32_t {
    if (off + static_cast<std::uint32_t>(size) > pkt.size()) {
      ok = false;
      return 0;
    }
    std::uint32_t v = 0;
    for (int i = 0; i < size; ++i) v = (v << 8) | pkt[off + static_cast<std::uint32_t>(i)];
    return v;
  };
  for (std::size_t pc = 0; pc < prog.size(); ++pc) {
    const auto& in = prog[pc];
    const std::uint16_t cls = BPF_CLASS(in.code);
    bool ok = true;
    switch (cls) {
      case BPF_LD: {
        const int size = BPF_SIZE(in.code) == BPF_W ? 4 : BPF_SIZE(in.code) == BPF_H ? 2 : 1;
        if (BPF_MODE(in.code) == BPF_ABS) A = load(in.k, size, ok);
        else if (BPF_MODE(in.code) == BPF_IND) A = load(X + in.k, size, ok);
        else if (BPF_MODE(in.code) == BPF_IMM) A = in.k;
        else if (BPF_MODE(in.code) == BPF_MEM) A = mem[in.k & 15];
        else if (BPF_MODE(in.code) == BPF_LEN) A = static_cast<std::uint32_t>(pkt.size());
        if (!ok) return 0;
        break;
      }
      case BPF_LDX:
        if (BPF_MODE(in.code) == BPF_MSH) {
          X = (load(in.k, 1, ok) & 0x0F) * 4;
          if (!ok) return 0;
        } else if (BPF_MODE(in.code) == BPF_IMM) {
          X = in.k;
        } else if (BPF_MODE(in.code) == BPF_MEM) {
          X = mem[in.k & 15];
        }
        break;
      case BPF_ST: mem[in.k & 15] = A; break;
      case BPF_STX: mem[in.k & 15] = X; break;
      case BPF_ALU: {
        const std::uint32_t v = BPF_SRC(in.code) == BPF_X ? X : in.k;
        switch (BPF_OP(in.code)) {
          case BPF_ADD: A += v; break;
          case BPF_SUB: A -= v; break;
          case BPF_AND: A &= v; break;
          case BPF_OR: A |= v; break;
          case BPF_LSH: A <<= v; break;
          case BPF_RSH: A >>= v; break;
          case BPF_MUL: A *= v; break;
          default: return 0;
        }
        break;
      }
      case BPF_JMP: {
        const std::uint32_t v = BPF_SRC(in.code) == BPF_X ? X : in.k;
        bool cond = false;
        switch (BPF_OP(in.code)) {
          case BPF_JA: pc += in.k; continue;
          case BPF_JEQ: cond = A == v; break;
          case BPF_JGT: cond = A > v; break;
          case BPF_JGE: cond = A >= v; break;
          case BPF_JSET: cond = (A & v) != 0; break;
          default: return 0;
        }
        pc += cond ? in.jt : in.jf;
        break;
      }
      case BPF_RET: return BPF_RVAL(in.code) == BPF_A ? A : in.k;
      case BPF_MISC:
        if (BPF_MISCOP(in.code) == BPF_TAX) X = A;
        else A = X;
        break;
      default: return 0;
    }
  }
  return 0;
}

}  // namespace

TEST(Net, BuildParseRoundTrip) {
  const auto f = frame(50000, 42616, "hello");
  net::TcpSegment s;
  net::ParseStats st;
  ASSERT_TRUE(net::parse_ethernet(f.data(), f.size(), 7, s, st));
  EXPECT_EQ(s.src, kCtl);
  EXPECT_EQ(s.dst, kIr);
  EXPECT_EQ(s.sport, 50000);
  EXPECT_EQ(s.dport, 42616);
  EXPECT_EQ(s.seq, 1000u);
  EXPECT_EQ(s.ts, 7);
  ASSERT_EQ(s.payload_len, 5u);
  EXPECT_EQ(std::string(reinterpret_cast<const char*>(s.payload), s.payload_len), "hello");
  EXPECT_EQ(net::ip_to_string(kIr), "10.42.0.11");
  net::Ip4 ip = 0;
  EXPECT_TRUE(net::parse_ip("10.42.0.11", ip));
  EXPECT_EQ(ip, kIr);
  EXPECT_FALSE(net::parse_ip("10.42.0.256", ip));
}

TEST(Net, VlanTaggedFrames) {
  const auto f = add_vlan(add_vlan(frame(50000, 42616), 100), 200);  // QinQ-like double tag
  net::TcpSegment s;
  net::ParseStats st;
  ASSERT_TRUE(net::parse_ethernet(f.data(), f.size(), 0, s, st));
  EXPECT_EQ(s.dport, 42616);
}

TEST(Net, RejectsFragmentsAndTruncated) {
  auto f = frame(50000, 42616);
  net::TcpSegment s;
  net::ParseStats st;
  auto frag = f;
  frag[14 + 6] = 0x20;  // MF flag
  EXPECT_FALSE(net::parse_ethernet(frag.data(), frag.size(), 0, s, st));
  EXPECT_FALSE(net::parse_ethernet(f.data(), 30, 0, s, st));
  std::vector<std::uint8_t> arp(f.begin(), f.end());
  arp[12] = 0x08;
  arp[13] = 0x06;
  EXPECT_FALSE(net::parse_ethernet(arp.data(), arp.size(), 0, s, st));
}

TEST(Bpf, AcceptsIrPortsInBothDirections) {
  const auto prog = capture::build_tcp_port_filter({42616, 42800});
  ASSERT_FALSE(prog.empty());
  EXPECT_NE(run_bpf(prog, frame(50000, 42616)), 0u);
  EXPECT_NE(run_bpf(prog, frame(42616, 50000)), 0u);
  EXPECT_NE(run_bpf(prog, frame(50000, 42800)), 0u);
  EXPECT_NE(run_bpf(prog, add_vlan(frame(50000, 42616), 10)), 0u);
  EXPECT_EQ(run_bpf(prog, frame(50000, 80)), 0u);
  EXPECT_EQ(run_bpf(prog, frame(22, 50000)), 0u);
  auto udp = frame(50000, 42616);
  udp[14 + 9] = 17;
  EXPECT_EQ(run_bpf(prog, udp), 0u);
}

TEST(Pcap, WriteAndReadBack) {
  const std::string path = ::testing::TempDir() + "/irbridge-test.pcap";
  {
    capture::PcapWriter w(path);
    ASSERT_TRUE(w.ok());
    w.write(1'700'000'000'123'456, frame(50000, 42616, "a"));
    w.write(1'700'000'001'000'000, frame(42616, 50000, "bb"));
  }
  capture::PcapFileSource src(path);
  ASSERT_TRUE(src.ok()) << src.error();
  capture::Packet p;
  ASSERT_TRUE(src.next(p, 0));
  EXPECT_EQ(p.ts, 1'700'000'000'123'456);
  EXPECT_EQ(p.bytes, frame(50000, 42616, "a"));
  ASSERT_TRUE(src.next(p, 0));
  EXPECT_FALSE(src.next(p, 0));
  EXPECT_TRUE(src.eof());
  EXPECT_EQ(src.stats().packets, 2u);
}
