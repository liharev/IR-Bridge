#include "irbridge/health.hpp"

#include <sstream>

namespace irbridge::health {

const char* status_name(Status s) {
  switch (s) {
    case Status::Observed: return "observed";
    case Status::Silent: return "silent";
    case Status::Encrypted: return "encrypted";
    case Status::Faulty: return "faulty";
    case Status::Unmapped: return "unmapped";
  }
  return "unknown";
}

namespace {
constexpr util::Micros kWindow = 60 * util::kMicrosPerSecond;
constexpr std::size_t kMaxOutages = 4096;
}  // namespace

ValidatorRegistry::ValidatorRegistry(const config::Config& cfg, Sink on_change) : cfg_(cfg), sink_(std::move(on_change)) {
  for (const auto& v : cfg.validators) {
    Entry e;
    e.mapped = true;
    e.st.validator_id = v.validator_id;
    e.st.door_id = v.door_id;
    e.st.ip = v.ip;
    e.st.status = Status::Silent;
    e.outages.push_back({0, 0});  // open outage from the start
    entries_.emplace(v.ip4, std::move(e));
  }
}

ValidatorRegistry::Entry& ValidatorRegistry::entry(net::Ip4 ip) {
  auto it = entries_.find(ip);
  if (it != entries_.end()) return it->second;
  Entry e;
  e.mapped = false;
  e.st.ip = net::ip_to_string(ip);
  e.st.validator_id = "ip-" + e.st.ip;
  e.st.status = Status::Unmapped;
  return entries_.emplace(ip, std::move(e)).first->second;
}

void ValidatorRegistry::identity(net::Ip4 ip, std::string& validator_id, std::string& door_id) const {
  if (const auto* v = cfg_.find_validator(ip)) {
    validator_id = v->validator_id;
    door_id = v->door_id;
    return;
  }
  validator_id = "ip-" + net::ip_to_string(ip);
  door_id.clear();
}

void ValidatorRegistry::on_frames(net::Ip4 ip, std::uint64_t frames, util::Micros ts) {
  std::lock_guard<std::mutex> lk(mu_);
  Entry& e = entry(ip);
  e.st.frames += frames;
  e.window_frames += frames;
  if (ts > e.st.last_frame_ts) e.st.last_frame_ts = ts;
}

void ValidatorRegistry::on_crc_errors(net::Ip4 ip, std::uint64_t n) {
  std::lock_guard<std::mutex> lk(mu_);
  Entry& e = entry(ip);
  e.st.crc_errors += n;
  e.window_crc += n;
}

void ValidatorRegistry::on_hardware_failure(net::Ip4 ip) {
  std::lock_guard<std::mutex> lk(mu_);
  Entry& e = entry(ip);
  ++e.st.failures;
  ++e.window_hw_failures;
}

void ValidatorRegistry::on_encrypted(net::Ip4 ip, util::Micros ts) {
  std::lock_guard<std::mutex> lk(mu_);
  entry(ip).last_encrypted = ts;
}

void ValidatorRegistry::on_version(net::Ip4 ip, const std::string& version) {
  std::lock_guard<std::mutex> lk(mu_);
  entry(ip).st.ir_version = version;
}

void ValidatorRegistry::evaluate(util::Micros now) {
  std::vector<ValidatorStatus> changes;
  {
    std::lock_guard<std::mutex> lk(mu_);
    const util::Micros silence = static_cast<util::Micros>(cfg_.session.silence_timeout_s) * util::kMicrosPerSecond;
    for (auto& [ip, e] : entries_) {
      if (now - e.window_start >= kWindow) {
        // Faulty: many CRC errors (>= 10 and > 5 % of frames) or repeated hardware failures in a window.
        e.faulty = (e.window_crc >= 10 && e.window_crc * 20 > e.window_frames) || e.window_hw_failures >= 5;
        e.window_start = now;
        e.window_frames = e.window_crc = e.window_hw_failures = 0;
      }
      const bool recent_plain = e.st.last_frame_ts > 0 && now - e.st.last_frame_ts <= silence;
      const bool recent_tls = e.last_encrypted > 0 && now - e.last_encrypted <= silence;
      Status s;
      if (recent_plain) {
        s = e.faulty ? Status::Faulty : Status::Observed;
      } else if (recent_tls) {
        s = Status::Encrypted;
      } else {
        s = Status::Silent;
      }
      if (!e.mapped && s == Status::Observed) s = Status::Unmapped;
      // Outage bookkeeping (unmapped counts as observed traffic).
      const bool observed = s == Status::Observed || s == Status::Unmapped;
      const bool in_outage = !e.outages.empty() && e.outages.back().second == 0;
      if (!observed && !in_outage) {
        // The validator has not been seen since its last frame: the outage starts there.
        e.outages.push_back({e.st.last_frame_ts > 0 ? e.st.last_frame_ts : now, 0});
        if (e.outages.size() > kMaxOutages) e.outages.erase(e.outages.begin());
      } else if (observed && in_outage) {
        e.outages.back().second = now;
      }
      if (s != e.st.status || e.st.since == 0) {
        e.st.status = s;
        e.st.since = now;
        changes.push_back(e.st);
      }
    }
  }
  if (sink_) {
    for (const auto& c : changes) sink_(c);
  }
}

std::vector<ValidatorStatus> ValidatorRegistry::snapshot() const {
  std::lock_guard<std::mutex> lk(mu_);
  std::vector<ValidatorStatus> out;
  for (const auto& [ip, e] : entries_) out.push_back(e.st);
  return out;
}

bool ValidatorRegistry::unobserved_during(const std::string& validator_id, util::Micros from, util::Micros to) const {
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [ip, e] : entries_) {
    if (e.st.validator_id != validator_id) continue;
    for (const auto& [a, b] : e.outages) {
      const util::Micros end = b == 0 ? INT64_MAX : b;
      if (a < to && end > from) return true;
    }
  }
  return false;
}

bool ValidatorRegistry::any_unobserved_during(util::Micros from, util::Micros to, const std::string& door_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  for (const auto& [ip, e] : entries_) {
    if (!e.mapped) continue;
    if (!door_id.empty() && e.st.door_id != door_id) continue;
    for (const auto& [a, b] : e.outages) {
      const util::Micros end = b == 0 ? INT64_MAX : b;
      if (a < to && end > from) return true;
    }
  }
  return false;
}

std::string Metrics::render_prometheus(const std::vector<ValidatorStatus>& validators) const {
  std::ostringstream o;
  auto counter = [&](const char* name, const char* help, std::uint64_t v) {
    o << "# HELP irbridge_" << name << " " << help << "\n# TYPE irbridge_" << name << " counter\nirbridge_" << name
      << " " << v << "\n";
  };
  auto gauge = [&](const char* name, const char* help, std::uint64_t v) {
    o << "# HELP irbridge_" << name << " " << help << "\n# TYPE irbridge_" << name << " gauge\nirbridge_" << name
      << " " << v << "\n";
  };
  counter("packets_total", "Captured packets", packets.load());
  counter("kernel_drops_total", "Packets dropped by the kernel capture ring", kernel_drops.load());
  counter("frames_total", "IntelliReader frames decoded", frames.load());
  counter("crc_errors_total", "IntelliReader frames with a bad CRC", crc_errors.load());
  counter("tcp_gaps_total", "Lost TCP data detected during reassembly", tcp_gaps.load());
  counter("sessions_opened_total", "Controller-reader TCP sessions opened", sessions_opened.load());
  counter("sessions_closed_total", "Controller-reader TCP sessions closed", sessions_closed.load());
  o << "# HELP irbridge_validations_total Validation records by outcome\n# TYPE irbridge_validations_total counter\n";
  o << "irbridge_validations_total{outcome=\"APPROVED\"} " << validations_approved.load() << "\n";
  o << "irbridge_validations_total{outcome=\"REJECTED\"} " << validations_rejected.load() << "\n";
  o << "irbridge_validations_total{outcome=\"NO_DECISION\"} " << validations_no_decision.load() << "\n";
  o << "irbridge_validations_total{outcome=\"ABORTED\"} " << validations_aborted.load() << "\n";
  counter("intervals_total", "Fare intervals closed", intervals.load());
  counter("mqtt_published_total", "Messages acknowledged by the MQTT broker", mqtt_published.load());
  gauge("mqtt_queue", "Records waiting for publication", mqtt_queue.load());
  counter("store_dropped_total", "Records dropped because the store queue overflowed", store_dropped.load());
  counter("proxy_bytes_total", "Bytes relayed in proxy mode", proxy_bytes.load());
  counter("proxy_parse_dropped_total", "Proxy chunks not parsed because the parser queue was full",
          proxy_parse_dropped.load());
  o << "# HELP irbridge_validator_up 1 if the validator is observed\n# TYPE irbridge_validator_up gauge\n";
  for (const auto& v : validators) {
    o << "irbridge_validator_up{validator_id=\"" << v.validator_id << "\",status=\"" << status_name(v.status)
      << "\"} " << ((v.status == Status::Observed || v.status == Status::Unmapped) ? 1 : 0) << "\n";
  }
  o << "# HELP irbridge_validator_crc_errors_total CRC errors per validator\n"
       "# TYPE irbridge_validator_crc_errors_total counter\n";
  for (const auto& v : validators) {
    o << "irbridge_validator_crc_errors_total{validator_id=\"" << v.validator_id << "\"} " << v.crc_errors << "\n";
  }
  return o.str();
}

}  // namespace irbridge::health
