#include "irbridge/util.hpp"

#include <sys/random.h>
#include <sys/timex.h>

#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <random>

namespace irbridge::util {

Micros now_micros() {
  using namespace std::chrono;
  return duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
}

Micros monotonic_micros() {
  using namespace std::chrono;
  return duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
}

int local_utc_offset_minutes(Micros ts) {
  const std::time_t secs = static_cast<std::time_t>(ts / kMicrosPerSecond);
  std::tm local{};
  localtime_r(&secs, &local);
  return static_cast<int>(local.tm_gmtoff / 60);
}

std::string format_rfc3339(Micros ts, int utc_offset_minutes) {
  Micros secs = ts / kMicrosPerSecond;
  Micros rem = ts % kMicrosPerSecond;
  if (rem < 0) {
    rem += kMicrosPerSecond;
    secs -= 1;
  }
  const std::time_t shifted = static_cast<std::time_t>(secs + static_cast<Micros>(utc_offset_minutes) * 60);
  std::tm t{};
  gmtime_r(&shifted, &t);
  const int ms = static_cast<int>(rem / kMicrosPerMilli);
  char buf[64];
  const char sign = utc_offset_minutes < 0 ? '-' : '+';
  const int off = utc_offset_minutes < 0 ? -utc_offset_minutes : utc_offset_minutes;
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03d%c%02d:%02d", t.tm_year + 1900,
                t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, ms, sign, off / 60, off % 60);
  return buf;
}

std::string format_rfc3339_local(Micros ts) { return format_rfc3339(ts, local_utc_offset_minutes(ts)); }

namespace {
bool parse_int(std::string_view s, std::size_t pos, std::size_t len, int& out) {
  if (pos + len > s.size()) return false;
  int v = 0;
  for (std::size_t i = pos; i < pos + len; ++i) {
    if (s[i] < '0' || s[i] > '9') return false;
    v = v * 10 + (s[i] - '0');
  }
  out = v;
  return true;
}

// Days from civil date (Howard Hinnant's algorithm), avoids timegm/locale dependencies.
std::int64_t days_from_civil(int y, unsigned m, unsigned d) {
  y -= m <= 2;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}
}  // namespace

bool parse_rfc3339(std::string_view s, Micros& out) {
  int y, mo, d, h, mi, sec;
  if (s.size() < 20) return false;
  if (!parse_int(s, 0, 4, y) || s[4] != '-' || !parse_int(s, 5, 2, mo) || s[7] != '-' ||
      !parse_int(s, 8, 2, d) || (s[10] != 'T' && s[10] != 't' && s[10] != ' ') || !parse_int(s, 11, 2, h) ||
      s[13] != ':' || !parse_int(s, 14, 2, mi) || s[16] != ':' || !parse_int(s, 17, 2, sec)) {
    return false;
  }
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || sec > 60) return false;
  std::size_t pos = 19;
  Micros frac = 0;
  if (pos < s.size() && s[pos] == '.') {
    ++pos;
    Micros scale = 100000;
    std::size_t digits = 0;
    while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') {
      if (digits < 6) {
        frac += (s[pos] - '0') * scale;
        scale /= 10;
      }
      ++digits;
      ++pos;
    }
    if (digits == 0) return false;
  }
  int offset_min = 0;
  if (pos >= s.size()) return false;
  if (s[pos] == 'Z' || s[pos] == 'z') {
    ++pos;
  } else if (s[pos] == '+' || s[pos] == '-') {
    int oh, om;
    if (!parse_int(s, pos + 1, 2, oh) || pos + 3 >= s.size() || s[pos + 3] != ':' || !parse_int(s, pos + 4, 2, om)) {
      return false;
    }
    offset_min = oh * 60 + om;
    if (s[pos] == '-') offset_min = -offset_min;
    pos += 6;
  } else {
    return false;
  }
  if (pos != s.size()) return false;
  const std::int64_t days = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d));
  const std::int64_t secs = days * 86400 + h * 3600 + mi * 60 + sec - static_cast<std::int64_t>(offset_min) * 60;
  out = secs * kMicrosPerSecond + frac;
  return true;
}

std::string uuid_v7(Micros ts) {
  std::array<std::uint8_t, 16> b{};
  const std::uint64_t ms = static_cast<std::uint64_t>(ts / kMicrosPerMilli);
  for (int i = 0; i < 6; ++i) b[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(ms >> (40 - 8 * i));
  std::array<std::uint8_t, 10> rnd{};
  if (getrandom(rnd.data(), rnd.size(), 0) != static_cast<ssize_t>(rnd.size())) {
    static thread_local std::mt19937_64 gen{std::random_device{}()};
    for (auto& x : rnd) x = static_cast<std::uint8_t>(gen());
  }
  for (std::size_t i = 0; i < rnd.size(); ++i) b[6 + i] = rnd[i];
  b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x70);  // version 7
  b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80);  // RFC 4122 variant
  const std::string h = to_hex(b.data(), b.size());
  return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" + h.substr(16, 4) + "-" + h.substr(20);
}

std::string to_hex(const std::uint8_t* data, std::size_t n, bool upper) {
  static const char* lo = "0123456789abcdef";
  static const char* up = "0123456789ABCDEF";
  const char* digits = upper ? up : lo;
  std::string out;
  out.resize(n * 2);
  for (std::size_t i = 0; i < n; ++i) {
    out[2 * i] = digits[data[i] >> 4];
    out[2 * i + 1] = digits[data[i] & 0x0F];
  }
  return out;
}

std::string to_hex(const std::vector<std::uint8_t>& data, bool upper) { return to_hex(data.data(), data.size(), upper); }

std::string to_hex(std::string_view data, bool upper) {
  return to_hex(reinterpret_cast<const std::uint8_t*>(data.data()), data.size(), upper);
}

bool from_hex(std::string_view hex, std::vector<std::uint8_t>& out) {
  out.clear();
  int hi = -1;
  for (char c : hex) {
    if (c == ' ' || c == '\t' || c == '\n') continue;
    int v;
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else return false;
    if (hi < 0) {
      hi = v;
    } else {
      out.push_back(static_cast<std::uint8_t>((hi << 4) | v));
      hi = -1;
    }
  }
  return hi < 0;
}

void secure_zero(void* data, std::size_t n) {
  if (data != nullptr && n > 0) explicit_bzero(data, n);
}
void secure_zero(std::string& s) {
  secure_zero(s.data(), s.size());
  s.clear();
}
void secure_zero(std::vector<std::uint8_t>& v) {
  secure_zero(v.data(), v.size());
  v.clear();
}

std::string utf8_to_lower(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    const auto c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) {
      out.push_back(static_cast<char>(std::tolower(c)));
      continue;
    }
    // Two-byte Cyrillic: U+0400..U+04FF -> 0xD0/0xD1 lead bytes.
    if ((c == 0xD0 || c == 0xD1) && i + 1 < s.size()) {
      const auto c2 = static_cast<unsigned char>(s[i + 1]);
      unsigned cp = ((c & 0x1Fu) << 6) | (c2 & 0x3Fu);
      if (cp >= 0x0410 && cp <= 0x042F) cp += 0x20;        // А..Я -> а..я
      else if (cp >= 0x0400 && cp <= 0x040F) cp += 0x50;   // Ѐ..Џ (incl. Ё) -> ѐ..џ
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
      ++i;
      continue;
    }
    out.push_back(static_cast<char>(c));
  }
  return out;
}

bool clock_synchronized() {
  struct timex tx {};
  const int state = adjtimex(&tx);
  if (state == -1) return false;
  return (tx.status & STA_UNSYNC) == 0 && state != TIME_ERROR;
}

}  // namespace irbridge::util
