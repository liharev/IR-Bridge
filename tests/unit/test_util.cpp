#include <gtest/gtest.h>

#include <set>

#include "irbridge/util.hpp"

using namespace irbridge::util;

TEST(Util, Rfc3339RoundTrip) {
  const Micros t = 1'762'491'600'123'000;  // 2025-11-07T05:00:00.123Z
  EXPECT_EQ(format_rfc3339(t, 0), "2025-11-07T05:00:00.123+00:00");
  EXPECT_EQ(format_rfc3339(t, 180), "2025-11-07T08:00:00.123+03:00");
  Micros back = 0;
  ASSERT_TRUE(parse_rfc3339("2025-11-07T08:00:00.123+03:00", back));
  EXPECT_EQ(back, t);
  ASSERT_TRUE(parse_rfc3339("2025-11-07T05:00:00Z", back));
  EXPECT_EQ(back, t - 123'000);
  EXPECT_FALSE(parse_rfc3339("2025-11-07 05:00", back));
  EXPECT_FALSE(parse_rfc3339("", back));
}

TEST(Util, UuidV7) {
  std::set<std::string> ids;
  for (int i = 0; i < 1000; ++i) {
    const std::string u = uuid_v7(1'762'491'600'000'000);
    ASSERT_EQ(u.size(), 36u);
    EXPECT_EQ(u[14], '7');  // version
    EXPECT_TRUE(u[19] == '8' || u[19] == '9' || u[19] == 'a' || u[19] == 'b');  // variant
    ids.insert(u);
  }
  EXPECT_EQ(ids.size(), 1000u);
  EXPECT_LT(uuid_v7(1'000'000'000'000'000), uuid_v7(2'000'000'000'000'000));  // time-ordered
}

TEST(Util, HexAndLower) {
  const std::vector<std::uint8_t> b{0x00, 0xAB, 0x7F};
  EXPECT_EQ(to_hex(b), "00ab7f");
  std::vector<std::uint8_t> back;
  ASSERT_TRUE(from_hex("00AB7f", back));
  EXPECT_EQ(back, b);
  EXPECT_FALSE(from_hex("abc", back));
  EXPECT_EQ(utf8_to_lower("ОПЛАЧЕНО x3 Ёж"), "оплачено x3 ёж");
}

TEST(Util, SecureZero) {
  std::string s = "secret";
  secure_zero(s);
  EXPECT_TRUE(s.empty() || s.find_first_not_of('\0') == std::string::npos);
}
