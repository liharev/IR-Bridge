// Common helpers: time, identifiers, hex, secure memory wiping.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace irbridge::util {

// Microseconds since the Unix epoch (UTC). All timestamps in the pipeline use this type so the
// logic can run on packet time (pcap replay) or on a virtual clock in tests.
using Micros = std::int64_t;

constexpr Micros kMicrosPerMilli = 1000;
constexpr Micros kMicrosPerSecond = 1000 * 1000;

// Wall clock in microseconds.
Micros now_micros();

// Monotonic clock in microseconds (for timeouts that must not jump with NTP).
Micros monotonic_micros();

// RFC 3339 with milliseconds and the local UTC offset, e.g. 2026-11-07T08:15:02.318+03:00.
// `utc_offset_minutes` overrides the local offset (used by tests and replay for determinism).
std::string format_rfc3339(Micros ts, int utc_offset_minutes);
std::string format_rfc3339_local(Micros ts);
int local_utc_offset_minutes(Micros ts);

// Parses the subset of RFC 3339 produced by format_rfc3339 (and "Z"). Returns false on error.
bool parse_rfc3339(std::string_view text, Micros& out);

// UUIDv7 (RFC 9562): 48-bit Unix milliseconds + random bits.
std::string uuid_v7(Micros ts);

std::string to_hex(const std::uint8_t* data, std::size_t n, bool upper = false);
std::string to_hex(const std::vector<std::uint8_t>& data, bool upper = false);
std::string to_hex(std::string_view data, bool upper = false);
// Accepts upper/lower case and ignores spaces. Returns false on odd length or invalid characters.
bool from_hex(std::string_view hex, std::vector<std::uint8_t>& out);

// Overwrites memory so the compiler cannot elide it (explicit_bzero).
void secure_zero(void* data, std::size_t n);
void secure_zero(std::string& s);
void secure_zero(std::vector<std::uint8_t>& v);

// Lower-cases ASCII and Cyrillic letters of a UTF-8 string.
std::string utf8_to_lower(std::string_view s);

// True if the system clock is synchronised (adjtimex reports no STA_UNSYNC).
bool clock_synchronized();

}  // namespace irbridge::util
