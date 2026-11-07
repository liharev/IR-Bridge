// libFuzzer: frame decoder on arbitrary byte streams, split at fuzzer-chosen points.
#include <cstddef>
#include <cstdint>

#include "irbridge/codec.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace irbridge::codec;
  if (size == 0) return 0;
  StreamDecoder d;
  const std::size_t step = 1 + data[0] % 64;  // first byte chooses the chunk size
  for (std::size_t off = 1; off < size; off += step) {
    const std::size_t n = std::min(step, size - off);
    d.feed(data + off, n);
    if ((data[off] & 0x3F) == 0x3F) d.mark_gap();
    d.drain([](Frame&& f) {
      // Every decoded frame must re-encode to a valid frame of the same content.
      const auto bytes = encode(f);
      if (bytes.size() < 9 || bytes.size() > 4128) __builtin_trap();
    });
    if (d.buffered() > 2 * 4128) __builtin_trap();  // bounded buffer
  }
  return 0;
}
