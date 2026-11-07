// IntelliReader transport layer: framing and CRC-16/XMODEM.
//
//   | 'I' 'R' | LENGTH (BE16) | MSGID | MODULE | TYPE | PAYLOAD | CRC (BE16) |
//
// LENGTH covers MSGID + MODULE + TYPE + PAYLOAD. The CRC is computed over HEADER..PAYLOAD.
// A whole frame is 9..4128 bytes (spec v1.96, section 2.2), so LENGTH is 3..4122.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace irbridge::codec {

constexpr std::uint8_t kHeader0 = 0x49;  // 'I'
constexpr std::uint8_t kHeader1 = 0x52;  // 'R'
constexpr std::size_t kMinFrame = 9;
constexpr std::size_t kMaxFrame = 4128;
constexpr std::size_t kMinLength = 3;
constexpr std::size_t kMaxLength = kMaxFrame - 6;  // 4122

enum class FrameType : std::uint8_t {
  Command = 0x01,
  Success = 0x02,
  Failure = 0x03,
  Pending = 0x04,
  Notification = 0x05,
  Control = 0x06,
};

bool is_known_type(std::uint8_t type);

std::uint16_t crc16_xmodem(const std::uint8_t* data, std::size_t n, std::uint16_t init = 0);

struct Frame {
  std::uint8_t msgid = 0;
  std::uint8_t module = 0;
  std::uint8_t type = 0;
  std::vector<std::uint8_t> payload;

  FrameType frame_type() const { return static_cast<FrameType>(type); }
};

// Serialises a frame (used by the traffic generator and tests).
std::vector<std::uint8_t> encode(const Frame& f);

struct DecoderStats {
  std::uint64_t frames = 0;
  std::uint64_t crc_errors = 0;
  std::uint64_t bad_length = 0;
  std::uint64_t bad_type = 0;
  std::uint64_t resyncs = 0;
  std::uint64_t bytes_skipped = 0;
  std::uint64_t gaps = 0;
};

// Streaming decoder for one direction of a TCP stream. Accepts arbitrary chunks, tolerates garbage,
// truncation and corruption, and never buffers more than 2 * kMaxFrame bytes.
class StreamDecoder {
 public:
  void feed(const std::uint8_t* data, std::size_t n);
  void feed(const std::vector<std::uint8_t>& data) { feed(data.data(), data.size()); }

  // Data was lost before the next byte fed: drop the partial frame and resynchronise.
  void mark_gap();

  // Calls on_frame(Frame&&) for every complete frame found so far.
  template <class F>
  void drain(F&& on_frame) {
    Frame f;
    while (next(f)) on_frame(std::move(f));
  }

  bool next(Frame& out);
  const DecoderStats& stats() const { return stats_; }
  std::size_t buffered() const { return buf_.size() - pos_; }

 private:
  void compact();
  void skip(std::size_t n);

  std::vector<std::uint8_t> buf_;
  std::size_t pos_ = 0;
  DecoderStats stats_;
};

}  // namespace irbridge::codec
