#include <google/protobuf/message.h>

#include "complex/poll_for_event.pb.h"
#include "contactless/token.pb.h"
#include "contactless/token_carrier_type.pb.h"
#include "contactless/token_type.pb.h"
#include "contactless/transaction.pb.h"
#include "irbridge/detect.hpp"
#include "qrcode/qrcode_event.pb.h"
#include "troika/av3/read_ticket.pb.h"

namespace irbridge::detect {

const char* carrier_class_name(CarrierClass c) {
  switch (c) {
    case CarrierClass::BankCard: return "bank_card";
    case CarrierClass::MobileWallet: return "mobile_wallet";
    case CarrierClass::TransportCard: return "transport_card";
    case CarrierClass::Troika: return "troika";
    case CarrierClass::Qr: return "qr";
    case CarrierClass::Unknown: return "unknown";
  }
  return "unknown";
}

namespace {

using contactless::token_type::TokenType;
using contactless::token_carrier_type::TokenCarrierType;

bool is_transport_token(TokenType t) {
  switch (t) {
    case contactless::token_type::MIFARE_CLASSIC_1K:
    case contactless::token_type::MIFARE_CLASSIC_2K:
    case contactless::token_type::MIFARE_CLASSIC_4K:
    case contactless::token_type::MIFARE_CLASSIC_MINI:
    case contactless::token_type::MIFARE_PLUS_X_SL2_2K:
    case contactless::token_type::MIFARE_PLUS_X_SL2_4K:
    case contactless::token_type::MIFARE_UL_OR_ULC:
    case contactless::token_type::SMART_MX_WITH_MIFARE_1K:
    case contactless::token_type::SMART_MX_WITH_MIFARE_4K:
    case contactless::token_type::STM_SRI512:
    case contactless::token_type::GENERIC_ISO15693:
    case contactless::token_type::ICODE_SLI:
    case contactless::token_type::ICODE_SLIX:
    case contactless::token_type::ICODE_SLIX2:
    case contactless::token_type::ASK_CTS512B:
    case contactless::token_type::FELICA:
    case contactless::token_type::TAG_N_PLAY:
      return true;
    default:
      return false;
  }
}

bool is_mobile(TokenCarrierType c) {
  return c != contactless::token_carrier_type::UNKNOWN && c != contactless::token_carrier_type::PLASTIC_CARD;
}

void from_token(const contactless::token::Token& tok, const privacy::CarrierHasher& hasher, Presentment& p) {
  p.token_type = contactless::token_type::TokenType_Name(tok.type());
  if (!tok.id().empty()) p.carrier_hash = hasher.hash("uid:", tok.id());
  p.carrier_class = is_transport_token(tok.type()) ? CarrierClass::TransportCard : CarrierClass::Unknown;
}

void from_txn(const contactless::transaction::TransactionResult& r, const privacy::CarrierHasher& hasher,
              Presentment& p) {
  using contactless::transaction::TransactionStatus;
  from_token(r.token(), hasher, p);
  p.emv_status = contactless::transaction::TransactionStatus_Name(r.status());
  p.emv_approved = r.status() == contactless::transaction::ONLINE_AUTHORIZATION_REQUIRED ||
                   r.status() == contactless::transaction::OFFLINE_APPROVED;
  if (r.has_token_carrier_type()) {
    p.token_carrier_type = contactless::token_carrier_type::TokenCarrierType_Name(r.token_carrier_type());
  }
  std::vector<std::uint8_t> aid;
  for (const auto& tag : r.emv_tags()) {
    if (tag.number() == 0x84 || (tag.number() == 0x9F06 && aid.empty())) {
      aid.assign(tag.value().begin(), tag.value().end());
    } else if (tag.number() == 0xDFF001) {
      p.ir_version = tag.value();
    }
  }
  p.payment_system = privacy::payment_system_from_aid(aid);
  util::secure_zero(aid);

  if (r.status() == contactless::transaction::NON_EMV_CARD) {
    p.carrier_class = CarrierClass::TransportCard;
    p.payment_system.clear();
    return;  // carrier hash already derived from the UID
  }
  // Bank card: identify by the reader's PAN hash when configured, else by the token id (UID or
  // random UID of a wallet). The PAN itself is never used.
  if (r.has_pan_hash() && !r.pan_hash().empty()) p.carrier_hash = hasher.hash("pan:", r.pan_hash());
  if (r.has_token_carrier_type() && is_mobile(r.token_carrier_type())) {
    p.carrier_class = CarrierClass::MobileWallet;
  } else {
    p.carrier_class = CarrierClass::BankCard;
  }
}

void from_qr(const qrcode::event::QrCodeEvent& e, Presentment& p) {
  p.carrier_class = CarrierClass::Qr;
  if (e.has_raw_data()) {
    const std::string& d = e.raw_data().data();
    p.carrier_hash = privacy::sha256_hex(reinterpret_cast<const std::uint8_t*>(d.data()), d.size()).substr(0, 32);
  } else if (e.has_validation_result()) {
    const auto& v = e.validation_result();
    p.emv_status = qrcode::emv_qr_code::ValidationStatus_Name(v.status());
    p.emv_approved = v.status() == qrcode::emv_qr_code::ONLINE_AUTHORIZATION_REQUIRED;
    if (v.has_raw_qr_code_data()) {
      const std::string& d = v.raw_qr_code_data();
      p.carrier_hash = privacy::sha256_hex(reinterpret_cast<const std::uint8_t*>(d.data()), d.size()).substr(0, 32);
    }
  }
}

}  // namespace

std::optional<Presentment> extract_presentment(proto::DecodedResponse& response, const privacy::CarrierHasher& hasher,
                                               util::Micros ts) {
  if (!response.msg) return std::nullopt;
  Presentment p;
  p.ts = ts;
  p.inferred = response.inferred;
  bool found = true;
  switch (response.kind) {
    case proto::ResponseKind::TransactionResult:
      from_txn(static_cast<const contactless::transaction::TransactionResult&>(*response.msg), hasher, p);
      break;
    case proto::ResponseKind::Token:
      from_token(static_cast<const contactless::token::Token&>(*response.msg), hasher, p);
      break;
    case proto::ResponseKind::QrCodeEvent:
      from_qr(static_cast<const qrcode::event::QrCodeEvent&>(*response.msg), p);
      if (!p.carrier_hash.empty()) p.carrier_hash = hasher.hash("qr:", p.carrier_hash);
      break;
    case proto::ResponseKind::TroikaTicket: {
      const auto& t = static_cast<const troika::av3::read_ticket::Ticket&>(*response.msg);
      p.carrier_class = CarrierClass::Troika;
      // The ticket content changes after each trip, so it is not hashed. The carrier is identified
      // by the UID from the preceding token in the same validation (see merge logic).
      (void)t;
      break;
    }
    case proto::ResponseKind::Event: {
      const auto& e = static_cast<const complex::poll::Event&>(*response.msg);
      if (e.has_contactless_txn_result()) {
        from_txn(e.contactless_txn_result(), hasher, p);
      } else if (e.has_contactless_token()) {
        from_token(e.contactless_token(), hasher, p);
      } else if (e.has_qrcode()) {
        from_qr(e.qrcode(), p);
        if (!p.carrier_hash.empty()) p.carrier_hash = hasher.hash("qr:", p.carrier_hash);
      } else if (e.has_troika_ticket()) {
        p.carrier_class = CarrierClass::Troika;
      } else {
        found = false;  // touchscreen event
      }
      break;
    }
    default:
      found = false;
      break;
  }
  proto::wipe(*response.msg);
  if (!found) return std::nullopt;
  return p;
}

}  // namespace irbridge::detect
