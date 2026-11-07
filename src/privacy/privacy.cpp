#include "irbridge/privacy.hpp"

#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "irbridge/util.hpp"

namespace irbridge::privacy {

bool load_or_create_secret(const std::string& path, std::vector<std::uint8_t>& secret, std::string& error) {
  secret.clear();
  struct stat st {};
  if (::stat(path.c_str(), &st) == 0) {
    if ((st.st_mode & 077) != 0) {
      error = "secret file " + path + " must not be accessible by group or others (expected mode 0600)";
      return false;
    }
    if (st.st_uid != ::geteuid()) {
      error = "secret file " + path + " is not owned by the service user";
      return false;
    }
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      error = "cannot open secret file " + path + ": " + std::strerror(errno);
      return false;
    }
    secret.resize(kSecretSize);
    const ssize_t n = ::read(fd, secret.data(), secret.size());
    ::close(fd);
    if (n != static_cast<ssize_t>(kSecretSize)) {
      util::secure_zero(secret);
      error = "secret file " + path + " must contain exactly 32 bytes";
      return false;
    }
    return true;
  }
  if (errno != ENOENT) {
    error = "cannot stat secret file " + path + ": " + std::strerror(errno);
    return false;
  }
  secret.resize(kSecretSize);
  if (getrandom(secret.data(), secret.size(), 0) != static_cast<ssize_t>(kSecretSize)) {
    util::secure_zero(secret);
    error = "getrandom failed";
    return false;
  }
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) {
    util::secure_zero(secret);
    error = "cannot create secret file " + path + ": " + std::strerror(errno);
    return false;
  }
  const ssize_t w = ::write(fd, secret.data(), secret.size());
  const int sync_rc = ::fsync(fd);
  ::close(fd);
  if (w != static_cast<ssize_t>(kSecretSize) || sync_rc != 0) {
    util::secure_zero(secret);
    ::unlink(path.c_str());
    error = "cannot write secret file " + path;
    return false;
  }
  return true;
}

CarrierHasher::CarrierHasher(std::vector<std::uint8_t> secret) : secret_(std::move(secret)) {}

CarrierHasher::~CarrierHasher() { util::secure_zero(secret_); }

std::string CarrierHasher::hash(std::string_view domain, const std::uint8_t* material, std::size_t n) const {
  if (!ready()) return {};
  unsigned char out[EVP_MAX_MD_SIZE];
  unsigned int out_len = 0;
  // One-shot HMAC over domain || material without concatenating into a heap buffer.
  EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  EVP_MAC_CTX* mctx = mac ? EVP_MAC_CTX_new(mac) : nullptr;
  std::string result;
  if (mctx != nullptr) {
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("digest", digest, 0), OSSL_PARAM_construct_end()};
    std::size_t len = 0;
    if (EVP_MAC_init(mctx, secret_.data(), secret_.size(), params) == 1 &&
        EVP_MAC_update(mctx, reinterpret_cast<const unsigned char*>(domain.data()), domain.size()) == 1 &&
        EVP_MAC_update(mctx, material, n) == 1 && EVP_MAC_final(mctx, out, &len, sizeof(out)) == 1) {
      out_len = static_cast<unsigned int>(len);
    }
  }
  EVP_MAC_CTX_free(mctx);
  EVP_MAC_free(mac);
  if (out_len >= 16) result = util::to_hex(out, 16);
  util::secure_zero(out, sizeof(out));
  return result;
}

std::string sha256_hex(const std::uint8_t* data, std::size_t n) {
  unsigned char out[SHA256_DIGEST_LENGTH];
  SHA256(data, n, out);
  return util::to_hex(out, sizeof(out));
}

std::string payment_system_from_aid(const std::vector<std::uint8_t>& aid) {
  if (aid.empty()) return {};
  const std::string h = util::to_hex(aid, true);
  auto starts = [&](const char* rid) { return h.rfind(rid, 0) == 0; };
  if (starts("A000000658")) return "MIR";
  if (starts("A000000003")) return "VISA";
  if (starts("A000000004")) return "MASTERCARD";
  if (starts("A000000333")) return "UNIONPAY";
  return "OTHER";
}

bool luhn_valid(std::string_view digits) {
  if (digits.empty()) return false;
  int sum = 0;
  bool dbl = false;
  for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
    if (*it < '0' || *it > '9') return false;
    int d = *it - '0';
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 == 0;
}

std::vector<std::string> find_pan_candidates(std::string_view text) {
  std::vector<std::string> out;
  std::size_t i = 0;
  while (i < text.size()) {
    if (text[i] < '0' || text[i] > '9') {
      ++i;
      continue;
    }
    std::size_t j = i;
    while (j < text.size() && text[j] >= '0' && text[j] <= '9') ++j;
    const std::size_t len = j - i;
    if (len >= 13 && len <= 19) {
      const std::string_view run = text.substr(i, len);
      // A run of identical digits (e.g. zero padding) is not a PAN.
      const bool uniform = run.find_first_not_of(run[0]) == std::string_view::npos;
      if (!uniform && luhn_valid(run)) out.emplace_back(run);
    }
    i = j;
  }
  return out;
}

}  // namespace irbridge::privacy
