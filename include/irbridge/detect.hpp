// Validation detector: turns correlated protocol events into validation records (TZ FR-4.4..4.8, 5.x).
#pragma once

#include <functional>
#include <optional>
#include <regex>
#include <string>
#include <vector>

#include "irbridge/corr.hpp"
#include "irbridge/privacy.hpp"
#include "irbridge/util.hpp"

namespace irbridge::detect {

// ---------------------------------------------------------------------------------------------
// Presentment: a carrier read by the reader.
// ---------------------------------------------------------------------------------------------
enum class CarrierClass { BankCard, MobileWallet, TransportCard, Troika, Qr, Unknown };
const char* carrier_class_name(CarrierClass c);

struct Presentment {
  util::Micros ts = 0;
  CarrierClass carrier_class = CarrierClass::Unknown;
  std::string carrier_hash;        // 32 hex chars, or empty when no identifying material
  std::string payment_system;      // MIR/VISA/MASTERCARD/UNIONPAY/OTHER or empty
  std::string token_type;          // TokenType enum name or empty
  std::string token_carrier_type;  // TokenCarrierType enum name or empty
  std::optional<std::string> emv_status;
  bool emv_approved = false;       // status ONLINE_AUTHORIZATION_REQUIRED or OFFLINE_APPROVED
  std::string ir_version;          // EMV tag DFF001 if present
  bool inferred = false;
};

// Extracts presentment data from a successful response and wipes the response message afterwards.
// Returns nullopt for responses that are not presentments.
std::optional<Presentment> extract_presentment(proto::DecodedResponse& response, const privacy::CarrierHasher& hasher,
                                               util::Micros ts);

// ---------------------------------------------------------------------------------------------
// Indication rules.
// ---------------------------------------------------------------------------------------------
enum class Indication { None, Approve, Reject };

struct Rule {
  enum class Type { GuiPicture, GuiText, GuiCustomerPicture, Leds, RgbColor, TurnstilePass };
  Type type = Type::GuiPicture;
  std::vector<int> picture_ids;            // GuiPicture: gui::picture_id::PictureId values
  std::string regex_source;                // GuiText
  bool icase = false;                      // GuiText
  std::vector<std::string> names;          // GuiCustomerPicture
  std::optional<bool> green;               // Leds
  std::optional<bool> red;                 // Leds
  std::uint32_t color = 0;                 // RgbColor 0xRRGGBB
  std::uint32_t tolerance = 0;             // RgbColor: max per-channel difference
  std::string label() const;               // e.g. "gui_picture:APPROVED"

  // Compiled form of regex_source (call compile() after setting fields).
  void compile();
  std::optional<std::regex> regex;
};

struct RuleMatch {
  Indication indication = Indication::None;
  std::string rule;   // label of the matched rule
  int passengers = 1;
};

class RuleSet {
 public:
  std::vector<Rule> approve;
  std::vector<Rule> reject;

  static RuleSet defaults();
  // Evaluates the indication carried by a controller command. Rejection rules win over approval.
  RuleMatch evaluate(const proto::DecodedCommand& cmd) const;
  // Evaluates the UI action IntelliReader performs on its own when a Complex poll event fires.
  RuleMatch evaluate_complex_event_ui(const proto::DecodedCommand& cmd) const;
};

// True for commands that change a transport card (writes, counters, ticket writes).
bool is_card_write(const proto::DecodedCommand& cmd);

// ---------------------------------------------------------------------------------------------
// Detector.
// ---------------------------------------------------------------------------------------------
enum class Outcome { Approved, Rejected, NoDecision, Aborted };
const char* outcome_name(Outcome o);

enum class SuccessPolicy { Indication, IndicationOrWrite, EmvStatus };
const char* policy_name(SuccessPolicy p);
bool parse_policy(const std::string& s, SuccessPolicy& out);

struct DetectorConfig {
  SuccessPolicy policy = SuccessPolicy::Indication;
  util::Micros decision_window = 3000 * util::kMicrosPerMilli;
  util::Micros same_carrier_merge = 1500 * util::kMicrosPerMilli;
  bool require_ack = false;
  RuleSet rules = RuleSet::defaults();
};

struct ValidationRecord {
  util::Micros ts_presented = 0;
  util::Micros ts_decided = 0;
  Outcome outcome = Outcome::NoDecision;
  std::string decision_rule;
  int passengers = 1;
  Presentment presentment;
  std::optional<std::uint64_t> amount_minor;
  std::optional<std::string> indication_mode;
  std::optional<std::string> terminal_identification;
  bool card_write_confirmed = false;
};

struct DetectorStats {
  std::uint64_t presentments = 0;
  std::uint64_t merged = 0;
  std::uint64_t approved = 0;
  std::uint64_t rejected = 0;
  std::uint64_t no_decision = 0;
  std::uint64_t aborted = 0;
  std::uint64_t orphan_indications = 0;
};

class ValidationDetector {
 public:
  using Sink = std::function<void(ValidationRecord&&)>;

  ValidationDetector(const DetectorConfig& cfg, const privacy::CarrierHasher& hasher, Sink sink);

  void on_event(corr::CorrelatedEvent& ev);
  void on_tick(util::Micros now);
  void on_session_closed(util::Micros now);

  bool presented() const { return current_.has_value(); }
  const DetectorStats& stats() const { return stats_; }

 private:
  void start(Presentment&& p);
  void handle_indication(const RuleMatch& m, util::Micros ts);
  void finish(Outcome o, util::Micros ts, const std::string& rule, int passengers = 1);
  void expire(util::Micros now);

  const DetectorConfig& cfg_;
  const privacy::CarrierHasher& hasher_;
  Sink sink_;
  std::optional<ValidationRecord> current_;
  // Parameters of the most recent PerformTransaction / PollForEvent command in the session.
  std::optional<std::uint64_t> last_amount_;
  std::optional<std::string> last_indication_mode_;
  std::optional<std::string> last_terminal_id_;
  DetectorStats stats_;
};

}  // namespace irbridge::detect
