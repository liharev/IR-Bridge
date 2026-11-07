// Fare intervals (prompt 10).
#include <gtest/gtest.h>

#include "helpers.hpp"
#include "irbridge/agg.hpp"

using namespace irbridge;
using irbridge::testing::make_config;

namespace {

constexpr util::Micros S = util::kMicrosPerSecond;
const util::Micros T0 = 1'800'000'000LL * S;  // fixed virtual epoch

struct Fixture {
  config::Config cfg;
  std::unique_ptr<health::ValidatorRegistry> registry;
  std::unique_ptr<agg::Aggregator> agg;
  std::vector<agg::FareInterval> out;
  explicit Fixture(const std::string& extra = {}) : cfg(make_config(extra)) {
    registry = std::make_unique<health::ValidatorRegistry>(cfg, nullptr);
    agg = std::make_unique<agg::Aggregator>(cfg, *registry, [this](agg::FareInterval&& f) { out.push_back(std::move(f)); });
  }
  // Both validators send frames every second in [from, to].
  void observe(util::Micros from, util::Micros to, bool v2 = true) {
    for (util::Micros t = from; t <= to; t += S) {
      registry->on_frames(0x0A2A000B, 2, t);
      if (v2) registry->on_frames(0x0A2A000C, 2, t);
      registry->evaluate(t);
    }
  }
  void door(const std::string& d, util::Micros ts, bool open, const std::string& stop = {}) {
    agg->on_door(agg::DoorEvent{d, ts, open, stop});
  }
  void pax(const std::string& d, util::Micros ts, int in, int out_ = 0) { agg->on_pax(agg::PaxCount{d, ts, in, out_}); }
  void validation(const std::string& door, util::Micros ts, detect::Outcome o, int passengers = 1) {
    pipeline::ValidationEvent v;
    v.door_id = door;
    v.validator_id = door == "D1" ? "V1" : "V2";
    v.rec.ts_presented = ts;
    v.rec.outcome = o;
    v.rec.passengers = o == detect::Outcome::Approved ? passengers : 0;
    agg->on_validation(v);
  }
};

}  // namespace

TEST(Agg, FiveBoardedThreePaidGivesTwoUnpaid) {
  Fixture f;
  f.observe(T0 - 5 * S, T0 + 300 * S);
  f.door("D1", T0, true, "STOP-7");
  f.pax("D1", T0 + 5 * S, 5, 2);
  f.validation("D1", T0 + 6 * S, detect::Outcome::Approved);
  f.validation("D1", T0 + 8 * S, detect::Outcome::Approved);
  f.validation("D1", T0 + 9 * S, detect::Outcome::Approved);
  f.validation("D1", T0 + 10 * S, detect::Outcome::Rejected);
  f.validation("D1", T0 + 11 * S, detect::Outcome::NoDecision);
  f.door("D1", T0 + 20 * S, false);
  f.agg->on_tick(T0 + 100 * S);
  EXPECT_TRUE(f.out.empty());  // still in the tail
  f.agg->on_tick(T0 + 141 * S);
  ASSERT_EQ(f.out.size(), 1u);
  const auto& i = f.out[0];
  EXPECT_EQ(i.boarded, 5);
  EXPECT_EQ(i.alighted, 2);
  EXPECT_EQ(i.validations_approved, 3);
  EXPECT_EQ(i.passengers_paid, 3);
  EXPECT_EQ(i.validations_rejected, 1);
  EXPECT_EQ(i.no_decision, 1);
  EXPECT_EQ(i.unpaid_estimate, 2);
  EXPECT_EQ(i.stop_id, "STOP-7");
  EXPECT_EQ(i.ts_start, T0);
  EXPECT_EQ(i.ts_end, T0 + 140 * S);
  EXPECT_TRUE(i.reliable) << (i.unreliable_reasons.empty() ? "" : i.unreliable_reasons[0]);
}

TEST(Agg, ValidationInTailBelongsToInterval) {
  Fixture f;
  f.observe(T0 - 5 * S, T0 + 300 * S);
  f.door("D1", T0, true);
  f.pax("D1", T0 + 2 * S, 2);
  f.door("D1", T0 + 10 * S, false);
  f.validation("D1", T0 + 60 * S, detect::Outcome::Approved, 2);  // paid after the doors closed
  f.agg->on_tick(T0 + 200 * S);
  ASSERT_EQ(f.out.size(), 1u);
  EXPECT_EQ(f.out[0].passengers_paid, 2);
  EXPECT_EQ(f.out[0].unpaid_estimate, 0);
}

TEST(Agg, MorePaidThanBoardedIsZeroNotNegative) {
  Fixture f;
  f.observe(T0 - 5 * S, T0 + 300 * S);
  f.door("D1", T0, true);
  f.pax("D1", T0 + 1 * S, 1);
  f.validation("D1", T0 + 2 * S, detect::Outcome::Approved, 3);
  f.door("D1", T0 + 3 * S, false);
  f.agg->on_tick(T0 + 200 * S);
  ASSERT_EQ(f.out.size(), 1u);
  EXPECT_EQ(f.out[0].unpaid_estimate, 0);
}

TEST(Agg, TwoConsecutiveStopsDoNotOverlap) {
  Fixture f;
  f.observe(T0 - 5 * S, T0 + 900 * S);
  f.door("D1", T0, true);
  f.pax("D1", T0 + 1 * S, 3);
  f.door("D1", T0 + 10 * S, false);
  f.agg->on_tick(T0 + 200 * S);
  f.door("D1", T0 + 400 * S, true);
  f.pax("D1", T0 + 401 * S, 4);
  f.validation("D1", T0 + 402 * S, detect::Outcome::Approved);
  f.door("D1", T0 + 410 * S, false);
  f.agg->on_tick(T0 + 600 * S);
  ASSERT_EQ(f.out.size(), 2u);
  EXPECT_LE(f.out[0].ts_end, f.out[1].ts_start);
  EXPECT_EQ(f.out[0].boarded, 3);
  EXPECT_EQ(f.out[0].unpaid_estimate, 3);
  EXPECT_EQ(f.out[1].boarded, 4);
  EXPECT_EQ(f.out[1].unpaid_estimate, 3);
  EXPECT_NE(f.out[0].interval_id, f.out[1].interval_id);
}

TEST(Agg, DoorScope) {
  Fixture f("aggregation: { match_scope: door }\n");
  f.observe(T0 - 5 * S, T0 + 300 * S);
  f.door("D1", T0, true);
  f.door("D2", T0, true);
  f.pax("D1", T0 + 1 * S, 2);
  f.pax("D2", T0 + 1 * S, 3);
  f.validation("D1", T0 + 2 * S, detect::Outcome::Approved);
  f.validation("D2", T0 + 2 * S, detect::Outcome::Approved);
  f.validation("D2", T0 + 3 * S, detect::Outcome::Approved);
  f.door("D1", T0 + 10 * S, false);
  f.door("D2", T0 + 12 * S, false);
  f.agg->on_tick(T0 + 200 * S);
  ASSERT_EQ(f.out.size(), 2u);
  std::map<std::string, agg::FareInterval> by;
  for (auto& i : f.out) by[i.door_id] = i;
  EXPECT_EQ(by["D1"].unpaid_estimate, 1);
  EXPECT_EQ(by["D2"].unpaid_estimate, 1);
  EXPECT_EQ(by["D2"].scope, "door");
}

TEST(Agg, SilentValidatorMakesIntervalUnreliable) {
  Fixture f;
  f.observe(T0 - 5 * S, T0 + 300 * S, /*v2=*/false);  // V2 never seen
  f.door("D1", T0, true);
  f.pax("D1", T0 + 1 * S, 2);
  f.door("D1", T0 + 10 * S, false);
  f.agg->on_tick(T0 + 200 * S);
  ASSERT_EQ(f.out.size(), 1u);
  EXPECT_FALSE(f.out[0].reliable);
  ASSERT_FALSE(f.out[0].unreliable_reasons.empty());
  EXPECT_EQ(f.out[0].unreliable_reasons[0], "validator_unobserved");
}

TEST(Agg, CounterFaultAndClock) {
  Fixture f;
  f.observe(T0 - 5 * S, T0 + 300 * S);
  f.agg->set_clock_synced(false);
  f.door("D1", T0, true);
  f.agg->on_fault(agg::CounterFault{"", T0 + 1 * S, true});
  f.pax("D1", T0 + 2 * S, 2);
  f.door("D1", T0 + 10 * S, false);
  f.agg->on_tick(T0 + 200 * S);
  ASSERT_EQ(f.out.size(), 1u);
  EXPECT_FALSE(f.out[0].reliable);
  const auto& r = f.out[0].unreliable_reasons;
  EXPECT_NE(std::find(r.begin(), r.end(), "counter_fault"), r.end());
  EXPECT_NE(std::find(r.begin(), r.end(), "clock_unsynced"), r.end());
}

TEST(Agg, FallbackWindowsWithoutDoorSignals) {
  Fixture f("aggregation: { fallback_window_s: 60 }\n");
  f.observe(T0 - 5 * S, T0 + 300 * S);
  f.pax("D1", T0 + 1 * S, 2);
  f.validation("D1", T0 + 2 * S, detect::Outcome::Approved);
  f.pax("D1", T0 + 70 * S, 1);  // next window
  f.agg->on_tick(T0 + 130 * S);
  ASSERT_EQ(f.out.size(), 2u);
  EXPECT_EQ(f.out[0].ts_end - f.out[0].ts_start, 60 * S);
  EXPECT_EQ(f.out[0].unpaid_estimate, 1);
  EXPECT_EQ(f.out[1].unpaid_estimate, 1);
}

TEST(Agg, ValidationBetweenStopsIsOrphan) {
  Fixture f;
  f.observe(T0 - 5 * S, T0 + 600 * S);
  f.door("D1", T0, true);
  f.door("D1", T0 + 10 * S, false);
  f.agg->on_tick(T0 + 200 * S);
  f.validation("D1", T0 + 300 * S, detect::Outcome::Approved);
  EXPECT_EQ(f.agg->orphan_validations(), 1u);
}
