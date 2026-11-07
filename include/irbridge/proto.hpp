// Application layer of the IntelliReader protocol: typed decoding of frame payloads.
//
// Command PAYLOAD = the module wrapper from intellireader/commands.proto (a message with one oneof).
// Successful response PAYLOAD = the result message itself, without a wrapper; its type depends on the
// command with the same MSGID and MODULE (spec v1.96, sections 2.8 and 3.1.2).
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "irbridge/codec.hpp"

namespace google::protobuf {
class Message;
}
namespace common::failure {
class FailureResponse;
}
namespace common::notification {
class Notification;
}

namespace irbridge::proto {

enum class ModuleId : std::uint8_t {
  Notify = 0x00,
  Misc = 0x01,
  ContactL1 = 0x02,
  ContactlessL1 = 0x03,
  ContactlessL2 = 0x04,
  Mifare = 0x05,
  PinPad = 0x06,
  Service = 0x07,
  Stm = 0x08,
  Ntag = 0x09,
  Gui = 0x0A,
  Touch = 0x0B,
  Complex = 0x0C,
  QrCode = 0x0D,
  Cipurse = 0x0E,
  Turnstile = 0x10,
  MifareExt = 0x11,
  Troika = 0x12,
  Speaker = 0x13,
};

const char* module_name(std::uint8_t module);
const char* type_name(std::uint8_t type);

// Identifies a command: module + the oneof field of the module wrapper (number and name),
// e.g. {0x04, 1, "perform_transaction"}. name is empty when the payload was not decoded.
struct CommandKey {
  std::uint8_t module = 0;
  int field = 0;
  std::string name;
};

struct DecodedCommand {
  CommandKey key;
  // The module wrapper message (e.g. ::Gui), or null for modules we do not decode.
  std::shared_ptr<google::protobuf::Message> wrapper;
};

// Modules whose wrapper we decode: Misc, ContactlessL1/L2, Mifare, Gui, Complex, QrCode, Cipurse,
// Turnstile, MifareExt, Troika. Others yield a CommandKey with only `module` set.
std::optional<DecodedCommand> decode_command(const codec::Frame& f);

enum class ResponseKind {
  Empty,              // success without payload of interest (indication, writes, echo...)
  TransactionResult,  // contactless::transaction::TransactionResult
  Token,              // contactless::token::Token
  Event,              // complex::poll::Event
  QrCodeEvent,        // qrcode::event::QrCodeEvent
  TroikaTicket,       // troika::av3::read_ticket::Ticket
  DeviceInfo,         // misc::device::DeviceInfo
  DeviceStatistic,    // misc::stats::DeviceStatistic
};

const char* response_kind_name(ResponseKind k);

struct DecodedResponse {
  ResponseKind kind = ResponseKind::Empty;
  std::shared_ptr<google::protobuf::Message> msg;  // null for Empty
  bool inferred = false;                            // decoded without the matching command
};

// Decodes a TYPE 0x02 payload using the command it answers. Returns nullopt if the payload does not
// parse as the expected message.
std::optional<DecodedResponse> decode_success(const CommandKey& cmd, const codec::Frame& f);

// TZ FR-4.3: the command was not seen (capture started mid-session or a packet was lost).
// Module 0x04 -> TransactionResult, 0x0C -> Event, 0x0D -> QrCodeEvent; otherwise nullopt.
std::optional<DecodedResponse> decode_success_inferred(const codec::Frame& f);

std::shared_ptr<common::failure::FailureResponse> decode_failure(const codec::Frame& f);
std::shared_ptr<common::notification::Notification> decode_notification(const codec::Frame& f);

// Overwrites every bytes/string field of a message tree (cardholder data) and clears it.
void wipe(google::protobuf::Message& msg);

}  // namespace irbridge::proto
