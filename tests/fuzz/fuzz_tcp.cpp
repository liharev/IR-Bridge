// libFuzzer: TCP reassembly with arbitrary segments (seq, flags, payload, timing).
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "irbridge/tcp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace irbridge;
  tcp::FlowTable::Options o;
  o.max_ooo_bytes = 4096;
  o.max_flows = 8;
  std::size_t delivered = 0;
  tcp::FlowTable::Callbacks cb;
  cb.on_data = [&](const tcp::FlowKey&, tcp::Dir, const std::uint8_t*, std::size_t n, util::Micros) { delivered += n; };
  tcp::FlowTable t(o, cb);
  util::Micros now = 0;
  std::size_t off = 0;
  // Record: [dir/port selector 1][flags 1][seq 4][dt 1][len 1][payload len]
  while (off + 8 <= size) {
    const std::uint8_t sel = data[off];
    net::TcpSegment s;
    const bool to_reader = sel & 1;
    const std::uint16_t eph = static_cast<std::uint16_t>(50000 + ((sel >> 1) & 3));
    const std::uint16_t irp = (sel & 8) ? 42800 : 42616;
    s.src = to_reader ? 0x0A2A0001 : 0x0A2A000B;
    s.dst = to_reader ? 0x0A2A000B : 0x0A2A0001;
    s.sport = to_reader ? eph : irp;
    s.dport = to_reader ? irp : eph;
    s.flags = data[off + 1];
    std::memcpy(&s.seq, data + off + 2, 4);
    now += data[off + 6] * 10000;
    s.ts = now;
    const std::size_t len = std::min<std::size_t>(data[off + 7], size - off - 8);
    s.payload = data + off + 8;
    s.payload_len = len;
    t.on_segment(s);
    if (sel & 0x80) t.on_tick(now);
    off += 8 + len;
  }
  t.close_all(now);
  if (delivered > size * 2) __builtin_trap();  // never more bytes than were offered (plus overlaps)
  return 0;
}
