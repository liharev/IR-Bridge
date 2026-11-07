// libFuzzer: protobuf decoding of commands, responses, failures and notifications for every module,
// then the presentment extraction (must never crash and must wipe what it read).
#include <cstddef>
#include <cstdint>

#include "irbridge/detect.hpp"
#include "irbridge/proto.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace irbridge;
  if (size < 2) return 0;
  codec::Frame f;
  f.msgid = 1;
  f.module = data[0] % 0x14;
  f.type = static_cast<std::uint8_t>(1 + data[1] % 6);
  f.payload.assign(data + 2, data + size);
  static const privacy::CarrierHasher hasher(std::vector<std::uint8_t>(privacy::kSecretSize, 7));
  if (auto c = proto::decode_command(f)) {
    // Try the response decoders with this command's key.
    codec::Frame r = f;
    r.type = 0x02;
    if (auto resp = proto::decode_success(c->key, r)) detect::extract_presentment(*resp, hasher, 0);
  }
  if (auto resp = proto::decode_success_inferred(f)) detect::extract_presentment(*resp, hasher, 0);
  proto::decode_failure(f);
  proto::decode_notification(f);
  return 0;
}
