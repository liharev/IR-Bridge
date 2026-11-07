#include <gtest/gtest.h>

#include "irbridge/json.hpp"
#include "irbridge/privacy.hpp"

using namespace irbridge;

TEST(Json, ValidationSchema) {
  pipeline::ValidationEvent v;
  v.event_id = "0190d4f0-0000-7000-8000-000000000001";
  v.vehicle_id = "BUS-1";
  v.validator_id = "V1";
  v.door_id = "D1";
  v.validator_ip = "10.42.0.11";
  v.rec.ts_presented = 1'762'491'600'000'000;  // 2025-11-07T05:00:00Z
  v.rec.ts_decided = v.rec.ts_presented + 450'000;
  v.rec.outcome = detect::Outcome::Approved;
  v.rec.decision_rule = "gui_picture:APPROVED";
  v.rec.passengers = 2;
  v.rec.presentment.carrier_class = detect::CarrierClass::BankCard;
  v.rec.presentment.carrier_hash = "e04818a9e4906e93fcb056ec710c5689";
  v.rec.presentment.payment_system = "MIR";
  v.rec.amount_minor = 6600;
  json::TimeFormat tf{true, 180};
  const auto j = json::validation(v, tf);
  EXPECT_EQ(j["schema"], "irbridge.validation/1");
  EXPECT_EQ(j["ts_presented"], "2025-11-07T08:00:00.000+03:00");
  EXPECT_EQ(j["ts_decided"], "2025-11-07T08:00:00.450+03:00");
  EXPECT_EQ(j["outcome"], "APPROVED");
  EXPECT_EQ(j["passengers"], 2);
  EXPECT_EQ(j["carrier_class"], "bank_card");
  EXPECT_EQ(j["amount_minor"], 6600);
  EXPECT_TRUE(j["emv_status"].is_null());
  // No field may carry card data.
  for (const char* forbidden : {"pan", "track2", "uid", "masked_pan", "token_id"}) EXPECT_FALSE(j.contains(forbidden));
  EXPECT_TRUE(privacy::find_pan_candidates(j.dump()).empty());
}

TEST(Json, IntervalAndStatus) {
  agg::FareInterval f;
  f.interval_id = "i-1";
  f.vehicle_id = "BUS-1";
  f.scope = "vehicle";
  f.boarded = 5;
  f.passengers_paid = 3;
  f.unpaid_estimate = 2;
  f.reliable = false;
  f.unreliable_reasons = {"validator_unobserved"};
  const auto j = json::interval(f, json::TimeFormat{true, 0});
  EXPECT_EQ(j["schema"], "irbridge.fare_interval/1");
  EXPECT_EQ(j["unpaid_estimate"], 2);
  EXPECT_EQ(j["unreliable_reasons"][0], "validator_unobserved");
  EXPECT_TRUE(j["door_id"].is_null());

  health::ValidatorStatus s;
  s.validator_id = "V1";
  s.ip = "10.42.0.11";
  s.status = health::Status::Encrypted;
  const auto js = json::validator_status(s, json::TimeFormat{true, 0});
  EXPECT_EQ(js["status"], "encrypted");
  EXPECT_TRUE(js["last_frame_ts"].is_null());
}

TEST(Json, ParsePax) {
  agg::PaxCount p;
  ASSERT_TRUE(json::parse_pax(R"({"door_id":"D1","ts":"2026-11-07T08:00:00.000+03:00","in":3,"out":1})", p));
  EXPECT_EQ(p.door_id, "D1");
  EXPECT_EQ(p.in, 3);
  EXPECT_EQ(p.out, 1);
  ASSERT_TRUE(json::parse_pax(R"({"door_id":"D1","ts":1762491600000,"in":1})", p));
  EXPECT_EQ(p.ts, 1'762'491'600'000'000);
  EXPECT_FALSE(json::parse_pax(R"({"door_id":"D1","in":1})", p));               // no ts
  EXPECT_FALSE(json::parse_pax(R"({"ts":1,"in":-1})", p));                      // negative
  EXPECT_FALSE(json::parse_pax(R"({"ts":1,"in":"three"})", p));                 // wrong type
  EXPECT_FALSE(json::parse_pax("not json", p));
  EXPECT_FALSE(json::parse_pax("[1,2]", p));
}

TEST(Json, ParseDoorAndFault) {
  agg::DoorEvent d;
  ASSERT_TRUE(json::parse_door(R"({"door_id":"D2","ts":1,"state":"open","stop_id":"S7"})", d));
  EXPECT_TRUE(d.open);
  EXPECT_EQ(d.stop_id, "S7");
  ASSERT_TRUE(json::parse_door(R"({"door_id":"D2","ts":1,"state":"closed"})", d));
  EXPECT_FALSE(d.open);
  EXPECT_FALSE(json::parse_door(R"({"door_id":"D2","ts":1,"state":"ajar"})", d));
  EXPECT_FALSE(json::parse_door(R"({"door_id":5,"ts":1,"state":"open"})", d));
  agg::CounterFault f;
  ASSERT_TRUE(json::parse_fault(R"({"ts":1,"fault":true})", f));
  EXPECT_TRUE(f.fault);
  EXPECT_FALSE(json::parse_fault(R"({"ts":1})", f));
}
