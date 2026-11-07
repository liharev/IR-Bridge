#include "irbridge/json.hpp"

namespace irbridge::json {

using nlohmann::json;

std::string TimeFormat::operator()(util::Micros ts) const {
  if (ts == 0) return {};
  return fixed ? util::format_rfc3339(ts, offset_minutes) : util::format_rfc3339_local(ts);
}

namespace {
json opt_str(const std::optional<std::string>& s) { return s ? json(*s) : json(nullptr); }
json str_or_null(const std::string& s) { return s.empty() ? json(nullptr) : json(s); }
}  // namespace

nlohmann::json validation(const pipeline::ValidationEvent& v, const TimeFormat& tf) {
  const auto& r = v.rec;
  const auto& p = r.presentment;
  json j;
  j["event_id"] = v.event_id;
  j["schema"] = "irbridge.validation/1";
  j["vehicle_id"] = v.vehicle_id;
  j["validator_id"] = v.validator_id;
  j["door_id"] = str_or_null(v.door_id);
  j["validator_ip"] = v.validator_ip;
  j["ts_presented"] = tf(r.ts_presented);
  j["ts_decided"] = tf(r.ts_decided);
  j["outcome"] = detect::outcome_name(r.outcome);
  j["decision_rule"] = r.decision_rule;
  j["passengers"] = r.passengers;
  j["carrier_class"] = detect::carrier_class_name(p.carrier_class);
  j["carrier_hash"] = str_or_null(p.carrier_hash);
  j["payment_system"] = str_or_null(p.payment_system);
  j["token_type"] = str_or_null(p.token_type);
  j["token_carrier_type"] = str_or_null(p.token_carrier_type);
  j["emv_status"] = opt_str(p.emv_status);
  j["amount_minor"] = r.amount_minor ? json(*r.amount_minor) : json(nullptr);
  j["indication_mode"] = opt_str(r.indication_mode);
  j["card_write_confirmed"] = r.card_write_confirmed;
  j["inferred"] = p.inferred;
  j["clock_synced"] = v.clock_synced;
  j["ir_version"] = str_or_null(v.ir_version);
  return j;
}

nlohmann::json interval(const agg::FareInterval& f, const TimeFormat& tf) {
  json j;
  j["interval_id"] = f.interval_id;
  j["schema"] = "irbridge.fare_interval/1";
  j["vehicle_id"] = f.vehicle_id;
  j["scope"] = f.scope;
  j["door_id"] = str_or_null(f.door_id);
  j["stop_id"] = str_or_null(f.stop_id);
  j["ts_start"] = tf(f.ts_start);
  j["ts_end"] = tf(f.ts_end);
  j["boarded"] = f.boarded;
  j["alighted"] = f.alighted;
  j["validations_approved"] = f.validations_approved;
  j["passengers_paid"] = f.passengers_paid;
  j["validations_rejected"] = f.validations_rejected;
  j["no_decision"] = f.no_decision;
  j["unpaid_estimate"] = f.unpaid_estimate;
  j["reliable"] = f.reliable;
  j["unreliable_reasons"] = f.unreliable_reasons;
  return j;
}

nlohmann::json validator_status(const health::ValidatorStatus& s, const TimeFormat& tf) {
  json j;
  j["schema"] = "irbridge.validator_status/1";
  j["validator_id"] = s.validator_id;
  j["door_id"] = str_or_null(s.door_id);
  j["ip"] = s.ip;
  j["status"] = health::status_name(s.status);
  j["since"] = s.since ? json(tf(s.since)) : json(nullptr);
  j["last_frame_ts"] = s.last_frame_ts ? json(tf(s.last_frame_ts)) : json(nullptr);
  j["frames"] = s.frames;
  j["crc_errors"] = s.crc_errors;
  j["failures"] = s.failures;
  j["ir_version"] = str_or_null(s.ir_version);
  return j;
}

namespace {
bool parse_ts(const json& j, util::Micros& out) {
  if (!j.contains("ts")) return false;
  const auto& t = j["ts"];
  if (t.is_string()) return util::parse_rfc3339(t.get<std::string>(), out);
  if (t.is_number_integer()) {  // milliseconds since epoch
    out = t.get<std::int64_t>() * util::kMicrosPerMilli;
    return true;
  }
  return false;
}
}  // namespace

namespace {
bool parse_pax_impl(const std::string& payload, agg::PaxCount& out) {
  const json j = json::parse(payload, nullptr, false);
  if (j.is_discarded() || !j.is_object()) return false;
  if (!parse_ts(j, out.ts)) return false;
  out.door_id = j.value("door_id", std::string());
  out.in = j.value("in", 0);
  out.out = j.value("out", 0);
  return out.in >= 0 && out.out >= 0 && out.in < 1000 && out.out < 1000;
}
}  // namespace

bool parse_pax(const std::string& payload, agg::PaxCount& out) {
  try {
    return parse_pax_impl(payload, out);
  } catch (const json::exception&) {
    return false;  // wrong field types
  }
}

namespace {
bool parse_door_impl(const std::string& payload, agg::DoorEvent& out) {
  const json j = json::parse(payload, nullptr, false);
  if (j.is_discarded() || !j.is_object() || !parse_ts(j, out.ts)) return false;
  out.door_id = j.value("door_id", std::string());
  const std::string state = j.value("state", std::string());
  if (state != "open" && state != "closed") return false;
  out.open = state == "open";
  out.stop_id = j.value("stop_id", std::string());
  return true;
}
}  // namespace

bool parse_door(const std::string& payload, agg::DoorEvent& out) {
  try {
    return parse_door_impl(payload, out);
  } catch (const json::exception&) {
    return false;  // wrong field types
  }
}

namespace {
bool parse_fault_impl(const std::string& payload, agg::CounterFault& out) {
  const json j = json::parse(payload, nullptr, false);
  if (j.is_discarded() || !j.is_object() || !j.contains("fault") || !parse_ts(j, out.ts)) return false;
  out.door_id = j.value("door_id", std::string());
  out.fault = j.value("fault", false);
  return true;
}
}  // namespace

bool parse_fault(const std::string& payload, agg::CounterFault& out) {
  try {
    return parse_fault_impl(payload, out);
  } catch (const json::exception&) {
    return false;  // wrong field types
  }
}

}  // namespace irbridge::json
