// TCP reassembly for mirrored traffic (prompt 4).
#include <gtest/gtest.h>

#include "irbridge/tcp.hpp"

using namespace irbridge;

namespace {

const net::Ip4 kCtl = 0x0A2A0001;
const net::Ip4 kIr = 0x0A2A000B;

struct Recorder {
  std::string to_reader, to_controller;
  int opens = 0, gaps = 0, closes = 0;
  bool encrypted = false;
  tcp::CloseReason reason = tcp::CloseReason::Shutdown;
  tcp::FlowTable::Callbacks callbacks() {
    tcp::FlowTable::Callbacks cb;
    cb.on_open = [this](const tcp::FlowKey&, bool enc, util::Micros) {
      ++opens;
      encrypted = enc;
    };
    cb.on_data = [this](const tcp::FlowKey&, tcp::Dir d, const std::uint8_t* p, std::size_t n, util::Micros) {
      (d == tcp::Dir::ToReader ? to_reader : to_controller).append(reinterpret_cast<const char*>(p), n);
    };
    cb.on_gap = [this](const tcp::FlowKey&, tcp::Dir, util::Micros) { ++gaps; };
    cb.on_close = [this](const tcp::FlowKey&, tcp::CloseReason r, util::Micros) {
      ++closes;
      reason = r;
    };
    return cb;
  }
};

// Segment from the controller (to the reader) or from the reader.
net::TcpSegment seg(bool from_ctl, std::uint32_t seq, const std::string& data, std::uint8_t flags = net::kAck,
                    util::Micros ts = 0, std::uint16_t port = 42616) {
  static std::vector<std::string> keep;  // payload storage for the duration of the test
  keep.push_back(data);
  net::TcpSegment s;
  s.ts = ts;
  s.src = from_ctl ? kCtl : kIr;
  s.dst = from_ctl ? kIr : kCtl;
  s.sport = from_ctl ? 50000 : port;
  s.dport = from_ctl ? port : 50000;
  s.seq = seq;
  s.flags = flags;
  s.payload = reinterpret_cast<const std::uint8_t*>(keep.back().data());
  s.payload_len = keep.back().size();
  return s;
}

}  // namespace

TEST(Tcp, HandshakeAndInOrderData) {
  Recorder r;
  tcp::FlowTable t({}, r.callbacks());
  t.on_segment(seg(true, 100, "", net::kSyn));
  t.on_segment(seg(false, 900, "", net::kSyn | net::kAck));
  t.on_segment(seg(true, 101, "abc"));
  t.on_segment(seg(true, 104, "def"));
  t.on_segment(seg(false, 901, "xyz"));
  EXPECT_EQ(r.opens, 1);
  EXPECT_EQ(r.to_reader, "abcdef");
  EXPECT_EQ(r.to_controller, "xyz");
}

TEST(Tcp, OutOfOrderAndRetransmit) {
  Recorder r;
  tcp::FlowTable t({}, r.callbacks());
  t.on_segment(seg(true, 100, "", net::kSyn));
  t.on_segment(seg(true, 104, "def"));  // early
  t.on_segment(seg(true, 101, "abc"));  // fills the hole
  t.on_segment(seg(true, 101, "abc"));  // retransmit
  t.on_segment(seg(true, 102, "bcdefg"));  // overlapping retransmit with new bytes
  EXPECT_EQ(r.to_reader, "abcdefg");
  EXPECT_EQ(r.gaps, 0);
}

TEST(Tcp, SequenceWrapAround) {
  Recorder r;
  tcp::FlowTable t({}, r.callbacks());
  t.on_segment(seg(false, 0xFFFFFFFDu, "", net::kSyn | net::kAck));
  t.on_segment(seg(false, 0xFFFFFFFEu, "12"));
  t.on_segment(seg(false, 0x00000000u, "34"));
  t.on_segment(seg(false, 0x00000002u, "56"));
  EXPECT_EQ(r.to_controller, "123456");
}

TEST(Tcp, HoleTimesOutIntoGap) {
  Recorder r;
  tcp::FlowTable::Options o;
  o.reassembly_timeout = 500 * util::kMicrosPerMilli;
  tcp::FlowTable t(o, r.callbacks());
  t.on_segment(seg(true, 100, "", net::kSyn, 0));
  t.on_segment(seg(true, 101, "aa", net::kAck, 1000));
  t.on_segment(seg(true, 106, "zz", net::kAck, 2000));  // 103..105 lost on the mirror port
  t.on_tick(100 * util::kMicrosPerMilli);
  EXPECT_EQ(r.gaps, 0);
  t.on_tick(util::kMicrosPerSecond);
  EXPECT_EQ(r.gaps, 1);
  EXPECT_EQ(r.to_reader, "aazz");
}

TEST(Tcp, MidStreamStart) {
  Recorder r;
  tcp::FlowTable t({}, r.callbacks());
  t.on_segment(seg(true, 5000, "hello"));
  t.on_segment(seg(true, 5005, "!"));
  EXPECT_EQ(r.opens, 1);
  EXPECT_EQ(r.to_reader, "hello!");
}

TEST(Tcp, FinClosesAndTailDoesNotReopen) {
  Recorder r;
  tcp::FlowTable t({}, r.callbacks());
  t.on_segment(seg(true, 100, "", net::kSyn));
  t.on_segment(seg(false, 900, "", net::kSyn | net::kAck));
  t.on_segment(seg(true, 101, "", net::kFin | net::kAck));
  t.on_segment(seg(false, 901, "", net::kFin | net::kAck));
  EXPECT_EQ(r.closes, 1);
  EXPECT_EQ(r.reason, tcp::CloseReason::Fin);
  t.on_segment(seg(true, 102, "", net::kAck));  // last ACK
  EXPECT_EQ(r.opens, 1);
  EXPECT_EQ(t.size(), 0u);
}

TEST(Tcp, RstAndIdle) {
  Recorder r;
  tcp::FlowTable::Options o;
  o.idle_timeout = 10 * util::kMicrosPerSecond;
  tcp::FlowTable t(o, r.callbacks());
  t.on_segment(seg(true, 100, "x", net::kAck, 0));
  t.on_segment(seg(false, 900, "", net::kRst, 1));
  EXPECT_EQ(r.reason, tcp::CloseReason::Rst);
  t.on_segment(seg(true, 200, "y", net::kAck, 0));
  t.on_tick(11 * util::kMicrosPerSecond);
  EXPECT_EQ(r.reason, tcp::CloseReason::Idle);
  EXPECT_EQ(r.closes, 2);
}

TEST(Tcp, TlsPortIsEncryptedAndNotDelivered) {
  Recorder r;
  tcp::FlowTable t({}, r.callbacks());
  t.on_segment(seg(true, 100, "\x16\x03\x01", net::kAck, 0, 42800));
  EXPECT_TRUE(r.encrypted);
  EXPECT_TRUE(r.to_reader.empty());
}

TEST(Tcp, OtherPortsIgnored) {
  Recorder r;
  tcp::FlowTable t({}, r.callbacks());
  t.on_segment(seg(true, 100, "GET /", net::kAck, 0, 80));
  EXPECT_EQ(r.opens, 0);
  EXPECT_EQ(t.stats().ignored_segments, 1u);
}

TEST(Tcp, OooBufferIsBounded) {
  Recorder r;
  tcp::FlowTable::Options o;
  o.max_ooo_bytes = 1024;
  tcp::FlowTable t(o, r.callbacks());
  t.on_segment(seg(true, 100, "", net::kSyn));
  const std::string chunk(512, 'q');
  for (std::uint32_t i = 0; i < 10; ++i) t.on_segment(seg(true, 2000 + i * 512, chunk));  // all beyond a hole
  EXPECT_GE(r.gaps, 1);  // overflow forces a gap instead of unbounded buffering
}
