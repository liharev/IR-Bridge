#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>

#include "irbridge/privacy.hpp"

using namespace irbridge::privacy;
namespace fs = std::filesystem;

namespace {
fs::path temp_dir() {
  fs::path p = fs::temp_directory_path() / ("irbridge-priv-" + std::to_string(::getpid()));
  fs::create_directories(p);
  return p;
}
}  // namespace

TEST(Privacy, HashIsDeterministicAndKeyed) {
  CarrierHasher a(std::vector<std::uint8_t>(kSecretSize, 1));
  CarrierHasher b(std::vector<std::uint8_t>(kSecretSize, 2));
  const std::string h1 = a.hash("uid:", "0E264417");
  EXPECT_EQ(h1.size(), 32u);  // 16 bytes hex
  EXPECT_EQ(h1, a.hash("uid:", "0E264417"));
  EXPECT_NE(h1, b.hash("uid:", "0E264417"));       // different device key
  EXPECT_NE(h1, a.hash("pan:", "0E264417"));       // domain separation
  EXPECT_NE(h1, a.hash("uid:", "0E264418"));
  EXPECT_EQ(h1.find_first_not_of("0123456789abcdef"), std::string::npos);
}

TEST(Privacy, HashMatchesHmacReference) {
  // HMAC-SHA256(key = 32 x 0x0b, "uid:" "abc"), first 16 bytes (computed with Python hmac).
  CarrierHasher h(std::vector<std::uint8_t>(kSecretSize, 0x0b));
  EXPECT_EQ(h.hash("uid:", "abc"), "050ed603737e5f742079ec4f945991f2");
  EXPECT_EQ(sha256_hex(reinterpret_cast<const std::uint8_t*>("abc"), 3),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Privacy, Luhn) {
  EXPECT_TRUE(luhn_valid("4111111111111111"));
  EXPECT_TRUE(luhn_valid("2200000000000004"));
  EXPECT_FALSE(luhn_valid("2200000000000001"));  // the synthetic test number
  EXPECT_FALSE(luhn_valid(""));
  EXPECT_FALSE(luhn_valid("41111111111111a1"));
}

TEST(Privacy, FindPanCandidates) {
  const auto c = find_pan_candidates("x 4111111111111111 y 2200000000000001 z 0000000000000000 12345");
  ASSERT_EQ(c.size(), 1u);
  EXPECT_EQ(c[0], "4111111111111111");
  EXPECT_TRUE(find_pan_candidates("{\"carrier_hash\":\"e04818a9e4906e93\"}").empty());
}

TEST(Privacy, PaymentSystemByAid) {
  EXPECT_EQ(payment_system_from_aid({0xA0, 0x00, 0x00, 0x06, 0x58, 0x10, 0x10}), "MIR");
  EXPECT_EQ(payment_system_from_aid({0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10}), "VISA");
  EXPECT_EQ(payment_system_from_aid({0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10}), "MASTERCARD");
  EXPECT_EQ(payment_system_from_aid({0xA0, 0x00, 0x00, 0x03, 0x33, 0x01, 0x01}), "UNIONPAY");
  EXPECT_EQ(payment_system_from_aid({0xA0, 0x00, 0x00, 0x09, 0x99}), "OTHER");
  EXPECT_EQ(payment_system_from_aid({}), "");
}

TEST(Privacy, SecretCreatedWithMode0600AndReused) {
  const fs::path dir = temp_dir();
  const std::string path = (dir / "secret.key").string();
  fs::remove(path);
  std::vector<std::uint8_t> s1, s2;
  std::string err;
  ASSERT_TRUE(load_or_create_secret(path, s1, err)) << err;
  EXPECT_EQ(s1.size(), kSecretSize);
  struct stat st {};
  ASSERT_EQ(::stat(path.c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0600u);
  ASSERT_TRUE(load_or_create_secret(path, s2, err)) << err;
  EXPECT_EQ(s1, s2);
  fs::remove_all(dir);
}

TEST(Privacy, SecretWithLooseModeIsRefused) {
  const fs::path dir = temp_dir();
  const std::string path = (dir / "loose.key").string();
  {
    std::ofstream f(path, std::ios::binary);
    f << std::string(kSecretSize, 'k');
  }
  ::chmod(path.c_str(), 0644);
  std::vector<std::uint8_t> s;
  std::string err;
  EXPECT_FALSE(load_or_create_secret(path, s, err));
  EXPECT_FALSE(err.empty());
  fs::remove_all(dir);
}
