#include "irbridge/codec.hpp"

#include <algorithm>
#include <cstring>

#include "irbridge/util.hpp"

namespace irbridge::codec {

bool is_known_type(std::uint8_t type) { return type >= 0x01 && type <= 0x06; }

std::uint16_t crc16_xmodem(const std::uint8_t* data, std::size_t n, std::uint16_t init) {
  std::uint16_t crc = init;
  for (std::size_t i = 0; i < n; ++i) {
    crc = static_cast<std::uint16_t>(crc ^ (static_cast<std::uint16_t>(data[i]) << 8));
    for (int b = 0; b < 8; ++b) {
      crc = (crc & 0x8000) ? static_cast<std::uint16_t>((crc << 1) ^ 0x1021) : static_cast<std::uint16_t>(crc << 1);
    }
  }
  return crc;
}

std::vector<std::uint8_t> encode(const Frame& f) {
  const std::size_t len = 3 + f.payload.size();
  std::vector<std::uint8_t> out;
  out.reserve(len + 6);
  out.push_back(kHeader0);
  out.push_back(kHeader1);
  out.push_back(static_cast<std::uint8_t>(len >> 8));
  out.push_back(static_cast<std::uint8_t>(len & 0xFF));
  out.push_back(f.msgid);
  out.push_back(f.module);
  out.push_back(f.type);
  out.insert(out.end(), f.payload.begin(), f.payload.end());
  const std::uint16_t crc = crc16_xmodem(out.data(), out.size());
  out.push_back(static_cast<std::uint8_t>(crc >> 8));
  out.push_back(static_cast<std::uint8_t>(crc & 0xFF));
  return out;
}

void StreamDecoder::feed(const std::uint8_t* data, std::size_t n) {
  if (n == 0) return;
  compact();
  buf_.insert(buf_.end(), data, data + n);
  // Bound memory: a valid frame never needs more than kMaxFrame bytes, so anything older than
  // 2 * kMaxFrame bytes before the end cannot start a frame we could still complete... except the
  // current candidate. Dropping the head keeps the buffer bounded under any input.
  const std::size_t limit = 2 * kMaxFrame;
  if (buffered() > limit) {
    const std::size_t drop = buffered() - limit;
    skip(drop);
    ++stats_.resyncs;
    compact();
  }
}

void StreamDecoder::mark_gap() {
  ++stats_.gaps;
  if (buffered() > 0) {
    stats_.bytes_skipped += buffered();
    ++stats_.resyncs;
  }
  // Secure wipe: the buffer may hold card data.
  util::secure_zero(buf_);
  pos_ = 0;
}

void StreamDecoder::skip(std::size_t n) {
  n = std::min(n, buffered());
  util::secure_zero(buf_.data() + pos_, n);
  pos_ += n;
  stats_.bytes_skipped += n;
}

void StreamDecoder::compact() {
  if (pos_ == 0) return;
  if (pos_ >= buf_.size()) {
    buf_.clear();
  } else {
    buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(pos_));
  }
  pos_ = 0;
}

bool StreamDecoder::next(Frame& out) {
  while (true) {
    const std::size_t avail = buffered();
    if (avail < 2) return false;
    const std::uint8_t* p = buf_.data() + pos_;

    // 1. Find the header.
    if (!(p[0] == kHeader0 && p[1] == kHeader1)) {
      const auto* start = p + 1;
      const auto* end = p + avail;
      const auto* hit = std::find(start, end, kHeader0);
      const std::size_t n = static_cast<std::size_t>(hit - p);
      skip(n);
      if (hit == end) {
        // Keep nothing: no 'I' in buffer.
        return false;
      }
      ++stats_.resyncs;
      continue;
    }
    if (avail < 4) return false;

    // 2. Validate the length.
    const std::size_t len = (static_cast<std::size_t>(p[2]) << 8) | p[3];
    if (len < kMinLength || len > kMaxLength) {
      ++stats_.bad_length;
      ++stats_.resyncs;
      skip(1);
      continue;
    }
    const std::size_t total = 4 + len + 2;
    if (avail < total) return false;

    // 3. Check the CRC and type.
    const std::uint16_t got = static_cast<std::uint16_t>((p[4 + len] << 8) | p[5 + len]);
    const std::uint16_t want = crc16_xmodem(p, 4 + len);
    if (got != want) {
      ++stats_.crc_errors;
      ++stats_.resyncs;
      skip(1);
      continue;
    }
    if (!is_known_type(p[6])) {
      ++stats_.bad_type;
      ++stats_.resyncs;
      skip(1);
      continue;
    }

    out.msgid = p[4];
    out.module = p[5];
    out.type = p[6];
    out.payload.assign(p + 7, p + 4 + len);
    util::secure_zero(buf_.data() + pos_, total);
    pos_ += total;
    ++stats_.frames;
    if (pos_ == buf_.size()) {
      buf_.clear();
      pos_ = 0;
    }
    return true;
  }
}

}  // namespace irbridge::codec
