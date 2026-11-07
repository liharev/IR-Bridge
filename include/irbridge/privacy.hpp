// Cardholder data protection (TZ FR-5.1..5.4).
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace irbridge::privacy {

constexpr std::size_t kSecretSize = 32;

// Loads the per-device secret or creates it (getrandom, mode 0600). Refuses a secret file that is
// readable or writable by group/others. Returns false and sets `error` on failure.
bool load_or_create_secret(const std::string& path, std::vector<std::uint8_t>& secret, std::string& error);

// carrier_hash = hex(HMAC-SHA256(secret, domain || material)[0..16]).
class CarrierHasher {
 public:
  CarrierHasher() = default;
  explicit CarrierHasher(std::vector<std::uint8_t> secret);
  ~CarrierHasher();
  CarrierHasher(const CarrierHasher&) = default;
  CarrierHasher& operator=(const CarrierHasher&) = default;

  bool ready() const { return secret_.size() == kSecretSize; }
  std::string hash(std::string_view domain, const std::uint8_t* material, std::size_t n) const;
  std::string hash(std::string_view domain, std::string_view material) const {
    return hash(domain, reinterpret_cast<const std::uint8_t*>(material.data()), material.size());
  }

 private:
  std::vector<std::uint8_t> secret_;
};

std::string sha256_hex(const std::uint8_t* data, std::size_t n);

// MIR / VISA / MASTERCARD / UNIONPAY / OTHER by the AID prefix (RID). Empty AID -> "".
std::string payment_system_from_aid(const std::vector<std::uint8_t>& aid);

// Luhn check over an ASCII digit string.
bool luhn_valid(std::string_view digits);

// Finds 13..19 digit runs in `text` that pass the Luhn check (PAN candidates).
std::vector<std::string> find_pan_candidates(std::string_view text);

}  // namespace irbridge::privacy
