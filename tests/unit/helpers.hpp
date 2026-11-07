// Shared test helpers: run synthetic scenarios through the full pipeline on a virtual clock.
#pragma once

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "irbridge/config.hpp"
#include "irbridge/health.hpp"
#include "irbridge/pipeline.hpp"
#include "irbridge/privacy.hpp"
#include "irbridge/synth.hpp"

namespace irbridge::testing {

inline const char* kBaseConfig = R"(
vehicle_id: "T1"
capture: { mode: mirror, interface: eth1 }
validators:
  - { ip: 10.42.0.11, validator_id: "V1", door_id: "D1" }
  - { ip: 10.42.0.12, validator_id: "V2", door_id: "D2" }
mqtt: { enabled: false }
)";

inline config::Config make_config(const std::string& extra = {}) {
  config::Config cfg;
  std::string err;
  const bool ok = config::parse_config(std::string(kBaseConfig) + extra, cfg, err);
  EXPECT_TRUE(ok) << err;
  return cfg;
}

struct RunResult {
  std::vector<pipeline::ValidationEvent> events;
  std::vector<health::ValidatorStatus> transitions;
  pipeline::Pipeline::SessionCounters totals;
  std::uint64_t frames = 0;
};

// Generates the scenario's packets and replays them with ticks every 50 ms of virtual time.
inline RunResult run(const config::Config& cfg, const std::string& scenario_yaml) {
  RunResult res;
  std::vector<capture::Packet> packets;
  std::string err;
  EXPECT_TRUE(synth::run_scenario(scenario_yaml, [&](capture::Packet&& p) { packets.push_back(std::move(p)); }, err))
      << err;
  privacy::CarrierHasher hasher(std::vector<std::uint8_t>(privacy::kSecretSize, 0x42));
  health::Metrics metrics;
  health::ValidatorRegistry registry(cfg, [&](const health::ValidatorStatus& s) { res.transitions.push_back(s); });
  pipeline::Pipeline pipe(cfg, hasher, registry, metrics,
                          [&](pipeline::ValidationEvent&& v) { res.events.push_back(std::move(v)); });
  util::Micros last_tick = 0, last = 0;
  for (const auto& p : packets) {
    pipe.on_packet(p);
    last = p.ts;
    if (p.ts - last_tick >= 50 * util::kMicrosPerMilli) {
      pipe.on_tick(p.ts);
      last_tick = p.ts;
    }
  }
  const util::Micros end = last + cfg.detector.decision_window + util::kMicrosPerSecond;
  pipe.on_tick(end);
  pipe.shutdown(end);
  res.totals = pipe.totals();
  res.frames = metrics.frames.load();
  return res;
}

inline std::string scenario(const std::string& steps) {
  return "start: \"2026-11-07T08:00:00.000+03:00\"\nsteps:\n" + steps;
}

}  // namespace irbridge::testing
