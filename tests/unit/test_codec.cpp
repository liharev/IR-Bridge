#include <gtest/gtest.h>

#include <random>

#include "commands.pb.h"
#include "irbridge/codec.hpp"
#include "irbridge/util.hpp"

using namespace irbridge;

namespace {

std::vector<std::uint8_t> hex(const char* s) {
  std::vector<std::uint8_t> v;
  EXPECT_TRUE(util::from_hex(s, v));
  return v;
}

std::vector<codec::Frame> decode_all(const std::vector<std::uint8_t>& bytes, std::size_t chunk = 0) {
  codec::StreamDecoder d;
  std::vector<codec::Frame> out;
  if (chunk == 0) {
    d.feed(bytes);
  } else {
    for (std::size_t i = 0; i < bytes.size(); i += chunk) {
      d.feed(bytes.data() + i, std::min(chunk, bytes.size() - i));
      d.drain([&](codec::Frame&& f) { out.push_back(std::move(f)); });
    }
  }
  d.drain([&](codec::Frame&& f) { out.push_back(std::move(f)); });
  return out;
}

struct Vector {
  const char* hex;
  std::uint8_t msgid, module, type;
  const char* payload;
};

// Reference frames from the IntelliReader Protocol Specification v1.96 and the Getting Started Guide.
const Vector kVectors[] = {
    {"4952 0007 01 01 01 0A020801 09DF", 0x01, 0x01, 0x01, "0A020801"},
    {"4952 0003 01 01 02 B26B", 0x01, 0x01, 0x02, ""},
    {"4952 0003 02 03 04 ED9F", 0x02, 0x03, 0x04, ""},
    {"4952 0005 01 03 03 080D AA1F", 0x01, 0x03, 0x03, "080D"},
    {"4952 0003 00 00 06 F6EE", 0x00, 0x00, 0x06, ""},
    {"4952 000F 01 01 01 420A1A08616E797468696E67 5025", 0x01, 0x01, 0x01, "420A1A08616E797468696E67"},
    {"4952 000D 01 01 02 0A08616E797468696E67 0901", 0x01, 0x01, 0x02, "0A08616E797468696E67"},
};

}  // namespace

TEST(Crc16, XmodemCheckValue) {
  const char* s = "123456789";
  EXPECT_EQ(codec::crc16_xmodem(reinterpret_cast<const std::uint8_t*>(s), 9), 0x31C3);
}

TEST(Codec, ReferenceVectorsDecode) {
  for (const auto& v : kVectors) {
    const auto frames = decode_all(hex(v.hex));
    ASSERT_EQ(frames.size(), 1u) << v.hex;
    EXPECT_EQ(frames[0].msgid, v.msgid);
    EXPECT_EQ(frames[0].module, v.module);
    EXPECT_EQ(frames[0].type, v.type);
    EXPECT_EQ(util::to_hex(frames[0].payload, true), v.payload);
  }
}

TEST(Codec, ReferenceVectorsEncode) {
  for (const auto& v : kVectors) {
    codec::Frame f{v.msgid, v.module, v.type, hex(v.payload)};
    EXPECT_EQ(codec::encode(f), hex(v.hex)) << v.hex;
  }
}

TEST(Codec, ProtobufPayloadMatchesSpecExample) {
  ::Miscellaneous m;
  m.mutable_set_leds_state()->set_blue(true);
  std::string bytes;
  ASSERT_TRUE(m.SerializeToString(&bytes));
  EXPECT_EQ(util::to_hex(bytes, true), "0A020801");
}

TEST(Codec, ByteByByteAndEverySplit) {
  std::vector<std::uint8_t> all;
  for (const auto& v : kVectors) {
    const auto b = hex(v.hex);
    all.insert(all.end(), b.begin(), b.end());
  }
  EXPECT_EQ(decode_all(all, 1).size(), std::size(kVectors));
  for (std::size_t split = 1; split < all.size(); ++split) {
    codec::StreamDecoder d;
    std::size_t n = 0;
    d.feed(all.data(), split);
    d.drain([&](codec::Frame&&) { ++n; });
    d.feed(all.data() + split, all.size() - split);
    d.drain([&](codec::Frame&&) { ++n; });
    EXPECT_EQ(n, std::size(kVectors)) << "split " << split;
  }
}

TEST(Codec, GarbageAroundFrames) {
  std::vector<std::uint8_t> b = hex("00 49 49 52 FF 13 37");
  const auto f1 = hex(kVectors[0].hex);
  b.insert(b.end(), f1.begin(), f1.end());
  const auto junk = hex("49 52 00 01 49");
  b.insert(b.end(), junk.begin(), junk.end());
  const auto f2 = hex(kVectors[1].hex);
  b.insert(b.end(), f2.begin(), f2.end());
  b.push_back(0x49);
  const auto frames = decode_all(b);
  ASSERT_EQ(frames.size(), 2u);
  EXPECT_EQ(frames[0].type, 0x01);
  EXPECT_EQ(frames[1].type, 0x02);
}

TEST(Codec, CorruptCrcIsDroppedAndNextFrameFound) {
  auto bad = hex(kVectors[0].hex);
  bad.back() ^= 0xFF;
  const auto good = hex(kVectors[1].hex);
  bad.insert(bad.end(), good.begin(), good.end());
  codec::StreamDecoder d;
  d.feed(bad);
  std::vector<codec::Frame> out;
  d.drain([&](codec::Frame&& f) { out.push_back(std::move(f)); });
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].type, 0x02);
  EXPECT_GE(d.stats().crc_errors, 1u);
}

TEST(Codec, OversizeLengthIsRejected) {
  auto b = hex("4952 FFFF 01 01 01");
  const auto good = hex(kVectors[2].hex);
  b.insert(b.end(), good.begin(), good.end());
  codec::StreamDecoder d;
  d.feed(b);
  std::size_t n = 0;
  d.drain([&](codec::Frame&&) { ++n; });
  EXPECT_EQ(n, 1u);
  EXPECT_GE(d.stats().bad_length, 1u);
}

TEST(Codec, GapInsideFrameResynchronises) {
  const auto f = hex(kVectors[5].hex);
  codec::StreamDecoder d;
  d.feed(f.data(), 8);
  d.mark_gap();
  d.feed(f.data() + 12, f.size() - 12);
  const auto g = hex(kVectors[6].hex);
  d.feed(g);
  std::vector<codec::Frame> out;
  d.drain([&](codec::Frame&& fr) { out.push_back(std::move(fr)); });
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].type, 0x02);
  EXPECT_EQ(d.stats().gaps, 1u);
}

TEST(Codec, LargestFrameRoundTrip) {
  codec::Frame f{7, 0x0A, 0x01, std::vector<std::uint8_t>(codec::kMaxLength - 3, 0xAB)};
  const auto bytes = codec::encode(f);
  EXPECT_EQ(bytes.size(), codec::kMaxFrame);
  const auto frames = decode_all(bytes, 333);
  ASSERT_EQ(frames.size(), 1u);
  EXPECT_EQ(frames[0].payload.size(), codec::kMaxLength - 3);
}

TEST(Codec, RandomInputIsBounded) {
  std::mt19937 gen(42);
  codec::StreamDecoder d;
  std::vector<std::uint8_t> chunk(4096);
  for (int i = 0; i < 2560; ++i) {  // 10 MiB
    for (auto& c : chunk) c = static_cast<std::uint8_t>(gen() & 0x7F) | ((gen() & 1) ? 0x40 : 0);
    d.feed(chunk);
    d.drain([](codec::Frame&&) {});
    ASSERT_LE(d.buffered(), 2 * codec::kMaxFrame + chunk.size());
  }
}
