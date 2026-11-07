// JSON representation of the module's output (TZ section 5).
#pragma once

#include <nlohmann/json.hpp>

#include "irbridge/agg.hpp"
#include "irbridge/health.hpp"
#include "irbridge/pipeline.hpp"

namespace irbridge::json {

// Timestamps use the local UTC offset unless a fixed offset is given (deterministic replays).
struct TimeFormat {
  bool fixed = false;
  int offset_minutes = 0;
  std::string operator()(util::Micros ts) const;
};

nlohmann::json validation(const pipeline::ValidationEvent& v, const TimeFormat& tf);
nlohmann::json interval(const agg::FareInterval& f, const TimeFormat& tf);
nlohmann::json validator_status(const health::ValidatorStatus& s, const TimeFormat& tf);

// Parsers for the CAMAI bus input (pax counter and doors). Return false on malformed input.
bool parse_pax(const std::string& payload, agg::PaxCount& out);
bool parse_door(const std::string& payload, agg::DoorEvent& out);
bool parse_fault(const std::string& payload, agg::CounterFault& out);

}  // namespace irbridge::json
