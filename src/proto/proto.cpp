#include "irbridge/proto.hpp"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>
#include <google/protobuf/reflection.h>

#include "commands.pb.h"
#include "common/failure.pb.h"
#include "common/notification.pb.h"
#include "complex/poll_for_event.pb.h"
#include "contactless/token.pb.h"
#include "contactless/transaction.pb.h"
#include "irbridge/util.hpp"
#include "misc/device.pb.h"
#include "misc/stats.pb.h"
#include "qrcode/qrcode_event.pb.h"
#include "troika/av3/read_ticket.pb.h"

namespace irbridge::proto {

namespace {
// ParseFromArray logs an ERROR for every message with missing required fields; corrupted or
// foreign traffic would flood the journal. Parse partially and check initialization silently.
// Decoded messages may hold card data (EMV tags, Mifare blocks, QR payloads): their string fields
// are zeroed when the last reference goes away (TZ FR-5.2).
template <typename T>
std::shared_ptr<T> wiping() {
  return std::shared_ptr<T>(new T, [](T* p) {
    wipe(*p);
    delete p;
  });
}

bool parse_quiet(google::protobuf::Message& m, const codec::Frame& f) {
  return m.ParsePartialFromArray(f.payload.data(), static_cast<int>(f.payload.size())) && m.IsInitialized();
}
}  // namespace

namespace gp = google::protobuf;

const char* module_name(std::uint8_t module) {
  switch (module) {
    case 0x00: return "notify";
    case 0x01: return "misc";
    case 0x02: return "contact_l1";
    case 0x03: return "contactless_l1";
    case 0x04: return "contactless_l2";
    case 0x05: return "mifare";
    case 0x06: return "pinpad";
    case 0x07: return "service";
    case 0x08: return "stm";
    case 0x09: return "ntag";
    case 0x0A: return "gui";
    case 0x0B: return "touchscreen";
    case 0x0C: return "complex";
    case 0x0D: return "qrcode";
    case 0x0E: return "cipurse";
    case 0x10: return "turnstile";
    case 0x11: return "mifare_ext";
    case 0x12: return "troika";
    case 0x13: return "speaker";
    default: return "unknown";
  }
}

const char* type_name(std::uint8_t type) {
  switch (type) {
    case 0x01: return "command";
    case 0x02: return "success";
    case 0x03: return "failure";
    case 0x04: return "pending";
    case 0x05: return "notification";
    case 0x06: return "control";
    default: return "unknown";
  }
}

const char* response_kind_name(ResponseKind k) {
  switch (k) {
    case ResponseKind::Empty: return "empty";
    case ResponseKind::TransactionResult: return "transaction_result";
    case ResponseKind::Token: return "token";
    case ResponseKind::Event: return "event";
    case ResponseKind::QrCodeEvent: return "qrcode_event";
    case ResponseKind::TroikaTicket: return "troika_ticket";
    case ResponseKind::DeviceInfo: return "device_info";
    case ResponseKind::DeviceStatistic: return "device_statistic";
  }
  return "unknown";
}

namespace {

// Module wrapper messages from commands.proto (no package -> global namespace).
std::shared_ptr<gp::Message> new_wrapper(std::uint8_t module) {
  switch (static_cast<ModuleId>(module)) {
    case ModuleId::Misc: return wiping<::Miscellaneous>();
    case ModuleId::ContactlessL1: return wiping<::ContactlessLevel1>();
    case ModuleId::ContactlessL2: return wiping<::ContactlessLevel2>();
    case ModuleId::Mifare: return wiping<::Mifare>();
    case ModuleId::Gui: return wiping<::Gui>();
    case ModuleId::Complex: return wiping<::Complex>();
    case ModuleId::QrCode: return wiping<::QrCode>();
    case ModuleId::Cipurse: return wiping<::Cipurse>();
    case ModuleId::Turnstile: return wiping<::Turnstile>();
    case ModuleId::MifareExt: return wiping<::MifareExtended>();
    case ModuleId::Troika: return wiping<::TroikaCard>();
    default: return nullptr;
  }
}

template <class T>
std::shared_ptr<gp::Message> parse_as(const codec::Frame& f) {
  auto m = wiping<T>();
  if (!parse_quiet(*m, f)) return nullptr;
  if (!m->IsInitialized()) return nullptr;
  return m;
}

std::optional<DecodedResponse> make(ResponseKind kind, std::shared_ptr<gp::Message> m, bool inferred) {
  if (!m) return std::nullopt;
  DecodedResponse r;
  r.kind = kind;
  r.msg = std::move(m);
  r.inferred = inferred;
  return r;
}

}  // namespace

std::optional<DecodedCommand> decode_command(const codec::Frame& f) {
  DecodedCommand out;
  out.key.module = f.module;
  auto w = new_wrapper(f.module);
  if (!w) return out;  // module not decoded: key with module only
  if (!parse_quiet(*w, f)) return std::nullopt;
  const gp::Descriptor* d = w->GetDescriptor();
  const gp::Reflection* r = w->GetReflection();
  if (d->oneof_decl_count() < 1) return std::nullopt;
  const gp::FieldDescriptor* fd = r->GetOneofFieldDescriptor(*w, d->oneof_decl(0));
  if (fd == nullptr) return std::nullopt;  // empty wrapper: not a valid command
  out.key.field = fd->number();
  out.key.name = fd->name();
  out.wrapper = std::move(w);
  return out;
}

std::optional<DecodedResponse> decode_success(const CommandKey& cmd, const codec::Frame& f) {
  const auto m = static_cast<ModuleId>(cmd.module);
  const std::string& n = cmd.name;
  if (m == ModuleId::ContactlessL2 && n == "perform_transaction")
    return make(ResponseKind::TransactionResult, parse_as<contactless::transaction::TransactionResult>(f), false);
  if (m == ModuleId::ContactlessL1 && n == "poll_for_token")
    return make(ResponseKind::Token, parse_as<contactless::token::Token>(f), false);
  if (m == ModuleId::Complex && n == "poll_for_event")
    return make(ResponseKind::Event, parse_as<complex::poll::Event>(f), false);
  if (m == ModuleId::QrCode && n == "poll_for_qrcode")
    return make(ResponseKind::QrCodeEvent, parse_as<qrcode::event::QrCodeEvent>(f), false);
  if (m == ModuleId::Troika && n == "troika_av3_read_ticket")
    return make(ResponseKind::TroikaTicket, parse_as<troika::av3::read_ticket::Ticket>(f), false);
  if (m == ModuleId::Misc && n == "read_device_info")
    return make(ResponseKind::DeviceInfo, parse_as<misc::device::DeviceInfo>(f), false);
  if (m == ModuleId::Misc && n == "get_device_statistic")
    return make(ResponseKind::DeviceStatistic, parse_as<misc::stats::DeviceStatistic>(f), false);
  DecodedResponse r;
  r.kind = ResponseKind::Empty;
  return r;
}

std::optional<DecodedResponse> decode_success_inferred(const codec::Frame& f) {
  if (f.payload.empty()) return std::nullopt;
  switch (static_cast<ModuleId>(f.module)) {
    case ModuleId::ContactlessL2:
      return make(ResponseKind::TransactionResult, parse_as<contactless::transaction::TransactionResult>(f), true);
    case ModuleId::Complex:
      return make(ResponseKind::Event, parse_as<complex::poll::Event>(f), true);
    case ModuleId::QrCode:
      return make(ResponseKind::QrCodeEvent, parse_as<qrcode::event::QrCodeEvent>(f), true);
    default:
      return std::nullopt;
  }
}

std::shared_ptr<common::failure::FailureResponse> decode_failure(const codec::Frame& f) {
  auto m = wiping<common::failure::FailureResponse>();
  if (!parse_quiet(*m, f)) return nullptr;
  return m;
}

std::shared_ptr<common::notification::Notification> decode_notification(const codec::Frame& f) {
  auto m = wiping<common::notification::Notification>();
  if (!parse_quiet(*m, f)) return nullptr;
  return m;
}

void wipe(gp::Message& msg) {
  const gp::Reflection* r = msg.GetReflection();
  std::vector<const gp::FieldDescriptor*> fields;
  r->ListFields(msg, &fields);
  for (const gp::FieldDescriptor* fd : fields) {
    if (fd->cpp_type() == gp::FieldDescriptor::CPPTYPE_STRING) {
      if (fd->is_repeated()) {
        for (int i = 0; i < r->FieldSize(msg, fd); ++i) {
          std::string scratch;
          const std::string& ref = r->GetRepeatedStringReference(msg, fd, i, &scratch);
          util::secure_zero(const_cast<char*>(ref.data()), ref.size());
        }
      } else {
        std::string scratch;
        const std::string& ref = r->GetStringReference(msg, fd, &scratch);
        util::secure_zero(const_cast<char*>(ref.data()), ref.size());
      }
    } else if (fd->cpp_type() == gp::FieldDescriptor::CPPTYPE_MESSAGE) {
      if (fd->is_repeated()) {
        for (int i = 0; i < r->FieldSize(msg, fd); ++i) wipe(*r->MutableRepeatedMessage(&msg, fd, i));
      } else {
        wipe(*r->MutableMessage(&msg, fd));
      }
    }
  }
  msg.Clear();
}

}  // namespace irbridge::proto
