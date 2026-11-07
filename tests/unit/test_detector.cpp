// Validation detector on synthetic sessions (prompt 6 scenarios, all success policies).
#include "helpers.hpp"

using namespace irbridge;
using irbridge::testing::make_config;
using irbridge::testing::run;
using irbridge::testing::scenario;
using detect::Outcome;

namespace {

const char* kOpen = "  - { action: open, validator: 10.42.0.11 }\n";
const char* kClose = "  - { action: wait, ms: 4000 }\n  - { action: close, validator: 10.42.0.11 }\n";

std::string with(const std::string& body) { return scenario(std::string(kOpen) + body + kClose); }

}  // namespace

TEST(Detector, BankCardApproved) {
  const auto r = run(make_config(), with("  - { action: bank_card, validator: 10.42.0.11, amount: 6600 }\n"
                                         "  - { action: indicate, validator: 10.42.0.11, kind: approve }\n"));
  ASSERT_EQ(r.events.size(), 1u);
  const auto& e = r.events[0];
  EXPECT_EQ(e.rec.outcome, Outcome::Approved);
  EXPECT_EQ(e.rec.passengers, 1);
  EXPECT_EQ(e.validator_id, "V1");
  EXPECT_EQ(e.door_id, "D1");
  EXPECT_EQ(e.rec.presentment.carrier_class, detect::CarrierClass::BankCard);
  EXPECT_EQ(e.rec.presentment.payment_system, "MIR");
  EXPECT_EQ(e.rec.presentment.carrier_hash.size(), 32u);
  ASSERT_TRUE(e.rec.amount_minor.has_value());
  EXPECT_EQ(*e.rec.amount_minor, 6600u);
  EXPECT_EQ(e.rec.indication_mode.value_or(""), "PROCESSING_ONLY");
  EXPECT_GT(e.rec.ts_decided, e.rec.ts_presented);
}

TEST(Detector, BankCardRejected) {
  const auto r = run(make_config(), with("  - { action: bank_card, validator: 10.42.0.11 }\n"
                                         "  - { action: indicate, validator: 10.42.0.11, kind: reject }\n"));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::Rejected);
  EXPECT_EQ(r.events[0].rec.passengers, 0);
}

TEST(Detector, TransportCardApprovedWithWrite) {
  const auto r = run(make_config(), with("  - { action: transport_card, validator: 10.42.0.11 }\n"
                                         "  - { action: indicate, validator: 10.42.0.11, kind: approve }\n"));
  ASSERT_EQ(r.events.size(), 1u);  // NON_EMV_CARD + Mifare read/write merged into one validation
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::Approved);
  EXPECT_EQ(r.events[0].rec.presentment.carrier_class, detect::CarrierClass::TransportCard);
  EXPECT_TRUE(r.events[0].rec.card_write_confirmed);
}

TEST(Detector, QrApprovedByGreenLed) {
  const auto r = run(make_config(), with("  - { action: qr, validator: 10.42.0.11, data: \"T-1\" }\n"
                                         "  - { action: indicate, validator: 10.42.0.11, kind: approve, via: leds }\n"));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::Approved);
  EXPECT_EQ(r.events[0].rec.presentment.carrier_class, detect::CarrierClass::Qr);
  EXPECT_EQ(r.events[0].rec.decision_rule, "leds:green");
}

TEST(Detector, NoDecisionOnTimeout) {
  const auto r = run(make_config(), with("  - { action: bank_card, validator: 10.42.0.11 }\n"));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::NoDecision);
  EXPECT_EQ(r.events[0].rec.decision_rule, "timeout");
}

TEST(Detector, SecondCardClosesFirstAsNoDecision) {
  const auto r = run(make_config(), with("  - { action: bank_card, validator: 10.42.0.11, uid: \"0E264417\" }\n"
                                         "  - { action: bank_card, validator: 10.42.0.11, uid: \"5F6E7D8C\" }\n"
                                         "  - { action: indicate, validator: 10.42.0.11, kind: approve }\n"));
  ASSERT_EQ(r.events.size(), 2u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::NoDecision);
  EXPECT_EQ(r.events[1].rec.outcome, Outcome::Approved);
  EXPECT_NE(r.events[0].rec.presentment.carrier_hash, r.events[1].rec.presentment.carrier_hash);
}

TEST(Detector, SameCardWithinMergeWindowIsOneValidation) {
  const auto r = run(make_config(), with("  - { action: bank_card, validator: 10.42.0.11, uid: \"0E264417\" }\n"
                                         "  - { action: bank_card, validator: 10.42.0.11, uid: \"0E264417\" }\n"
                                         "  - { action: indicate, validator: 10.42.0.11, kind: approve }\n"));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::Approved);
}

TEST(Detector, TextGivesPassengerCount) {
  const auto cfg = make_config(R"(
detector:
  approve:
    - { type: gui_text, regex: "оплачено(?: x([0-9]+))?", icase: true }
)");
  const auto r = run(cfg, with("  - { action: bank_card, validator: 10.42.0.11 }\n"
                               "  - { action: indicate, validator: 10.42.0.11, kind: approve, via: text, "
                               "text: \"ОПЛАЧЕНО x3\" }\n"));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::Approved);
  EXPECT_EQ(r.events[0].rec.passengers, 3);
}

TEST(Detector, RequireAckIgnoresFailedIndication) {
  const auto r = run(make_config("detector: { require_ack: true }\n"), with("  - { action: bank_card, validator: 10.42.0.11 }\n"
                                         "  - { action: indicate, validator: 10.42.0.11, kind: approve, fail: true }\n"));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::NoDecision);
}

TEST(Detector, WithoutRequireAckCommandIsEnough) {
  const auto cfg = make_config("detector: { require_ack: false }\n");
  const auto r = run(cfg, with("  - { action: bank_card, validator: 10.42.0.11 }\n"
                               "  - { action: indicate, validator: 10.42.0.11, kind: approve, fail: true }\n"));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::Approved);
}

TEST(Detector, PolicyIndicationOrWrite) {
  const std::string sc = with("  - { action: transport_card, validator: 10.42.0.11, write: true }\n");
  EXPECT_EQ(run(make_config(), sc).events.at(0).rec.outcome, Outcome::NoDecision);
  const auto r = run(make_config("detector: { success_policy: indication_or_write }\n"), sc);
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::Approved);
  EXPECT_EQ(r.events[0].rec.decision_rule, "card_write");
  // A failed write is not a confirmation.
  const auto f = run(make_config("detector: { success_policy: indication_or_write }\n"),
                     with("  - { action: transport_card, validator: 10.42.0.11, write: true, write_fails: true }\n"));
  ASSERT_EQ(f.events.size(), 1u);
  EXPECT_EQ(f.events[0].rec.outcome, Outcome::NoDecision);
}

TEST(Detector, PolicyEmvStatus) {
  const auto cfg = make_config("detector: { success_policy: emv_status }\n");
  const auto ok = run(cfg, with("  - { action: bank_card, validator: 10.42.0.11, status: OFFLINE_APPROVED, "
                                "indication: FULL }\n"));
  ASSERT_EQ(ok.events.size(), 1u);
  EXPECT_EQ(ok.events[0].rec.outcome, Outcome::Approved);
  EXPECT_EQ(ok.events[0].rec.decision_rule, "emv_status:OFFLINE_APPROVED");
  const auto declined = run(cfg, with("  - { action: bank_card, validator: 10.42.0.11, status: OFFLINE_DECLINED }\n"));
  ASSERT_EQ(declined.events.size(), 1u);
  EXPECT_EQ(declined.events[0].rec.outcome, Outcome::NoDecision);
  // Explicit reject wins over an approving status.
  const auto rej = run(cfg, with("  - { action: bank_card, validator: 10.42.0.11, status: OFFLINE_APPROVED }\n"
                                 "  - { action: indicate, validator: 10.42.0.11, kind: reject }\n"));
  ASSERT_EQ(rej.events.size(), 1u);
  EXPECT_EQ(rej.events[0].rec.outcome, Outcome::Rejected);
}

TEST(Detector, ComplexPollForEventAndTurnstile) {
  const auto r = run(make_config(), with("  - { action: bank_card, validator: 10.42.0.11, via_complex: true }\n"
                                         "  - { action: indicate, validator: 10.42.0.11, kind: approve, via: turnstile }\n"));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::Approved);
  EXPECT_EQ(r.events[0].rec.decision_rule, "turnstile_pass");
}

TEST(Detector, SessionResetAborts) {
  const auto r = run(make_config(), scenario(std::string(kOpen) +
                                             "  - { action: bank_card, validator: 10.42.0.11 }\n"
                                             "  - { action: reset, validator: 10.42.0.11 }\n"));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::Aborted);
}

TEST(Detector, MidSessionStart) {
  const std::string sc = "start: \"2026-11-07T08:00:00.000+03:00\"\ncapture_from_ms: 500\nsteps:\n" +
                         std::string(kOpen) +
                         "  - { action: idle_poll, validator: 10.42.0.11, count: 3 }\n"
                         "  - { action: wait, ms: 600 }\n"
                         "  - { action: bank_card, validator: 10.42.0.11 }\n"
                         "  - { action: indicate, validator: 10.42.0.11, kind: approve }\n" + kClose;
  const auto r = run(make_config(), sc);
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].rec.outcome, Outcome::Approved);
}

TEST(Detector, IdleTrafficProducesNothing) {
  const auto r = run(make_config(), with("  - { action: device_info, validator: 10.42.0.11 }\n"
                                         "  - { action: idle_poll, validator: 10.42.0.11, count: 20 }\n"
                                         "  - { action: echo, validator: 10.42.0.11 }\n"
                                         "  - { action: indicate, validator: 10.42.0.11, kind: neutral }\n"));
  EXPECT_TRUE(r.events.empty());
  EXPECT_GT(r.frames, 40u);
  EXPECT_EQ(r.totals.to_reader.crc_errors + r.totals.to_controller.crc_errors, 0u);
}

TEST(Detector, VersionFromDeviceInfo) {
  const auto r = run(make_config(), with("  - { action: device_info, validator: 10.42.0.11, version: \"1.56.9000\" }\n"
                                         "  - { action: qr, validator: 10.42.0.11 }\n"
                                         "  - { action: indicate, validator: 10.42.0.11, kind: approve }\n"));
  ASSERT_EQ(r.events.size(), 1u);
  EXPECT_EQ(r.events[0].ir_version, "1.56.9000");  // from DeviceInfo when the result carries no version
}

TEST(Detector, TlsSessionIsEncrypted) {
  const auto r = run(make_config(), scenario("  - { action: open, validator: 10.42.0.12, port: 42800 }\n"
                                             "  - { action: wait, ms: 500 }\n"
                                             "  - { action: close, validator: 10.42.0.12 }\n"));
  EXPECT_TRUE(r.events.empty());
  bool encrypted = false;
  for (const auto& t : r.transitions) encrypted = encrypted || (t.validator_id == "V2" && t.status == health::Status::Encrypted);
  EXPECT_TRUE(encrypted);
}
