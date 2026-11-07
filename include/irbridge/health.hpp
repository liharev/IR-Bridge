// Validator observability status and service metrics (TZ FR-6.1..6.3).
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "irbridge/config.hpp"
#include "irbridge/util.hpp"

namespace irbridge::health {

enum class Status { Observed, Silent, Encrypted, Faulty, Unmapped };
const char* status_name(Status s);

struct ValidatorStatus {
  std::string validator_id;
  std::string door_id;
  std::string ip;
  Status status = Status::Silent;
  util::Micros since = 0;
  util::Micros last_frame_ts = 0;
  std::uint64_t frames = 0;
  std::uint64_t crc_errors = 0;
  std::uint64_t failures = 0;
  std::string ir_version;
};

// Tracks every validator seen on the wire or listed in the configuration.
class ValidatorRegistry {
 public:
  using Sink = std::function<void(const ValidatorStatus&)>;

  ValidatorRegistry(const config::Config& cfg, Sink on_change);

  void on_frames(net::Ip4 ip, std::uint64_t frames, util::Micros ts);
  void on_crc_errors(net::Ip4 ip, std::uint64_t n);
  void on_hardware_failure(net::Ip4 ip);
  void on_encrypted(net::Ip4 ip, util::Micros ts);
  void on_version(net::Ip4 ip, const std::string& version);

  // Recomputes statuses; emits a change for every transition.
  void evaluate(util::Micros now);

  // Thread-safe snapshot for the HTTP API.
  std::vector<ValidatorStatus> snapshot() const;
  // True if the validator was not "observed" at any moment in [from, to]: used for reliability.
  bool unobserved_during(const std::string& validator_id, util::Micros from, util::Micros to) const;
  bool any_unobserved_during(util::Micros from, util::Micros to, const std::string& door_id = {}) const;

  // Identity for an IP (validator_id, door_id); unknown IPs get "ip-<a.b.c.d>".
  void identity(net::Ip4 ip, std::string& validator_id, std::string& door_id) const;

 private:
  struct Entry {
    ValidatorStatus st;
    bool mapped = false;
    util::Micros last_encrypted = 0;
    // Window counters for the faulty heuristic (reset every 60 s).
    util::Micros window_start = 0;
    std::uint64_t window_frames = 0;
    std::uint64_t window_crc = 0;
    std::uint64_t window_hw_failures = 0;
    bool faulty = false;
    // History of [start, end) intervals when the validator was NOT observed (bounded).
    std::vector<std::pair<util::Micros, util::Micros>> outages;
  };
  Entry& entry(net::Ip4 ip);

  const config::Config& cfg_;
  Sink sink_;
  mutable std::mutex mu_;
  std::map<net::Ip4, Entry> entries_;
};

// Process-wide counters exported at /metrics.
struct Metrics {
  std::atomic<std::uint64_t> packets{0};
  std::atomic<std::uint64_t> kernel_drops{0};
  std::atomic<std::uint64_t> frames{0};
  std::atomic<std::uint64_t> crc_errors{0};
  std::atomic<std::uint64_t> tcp_gaps{0};
  std::atomic<std::uint64_t> sessions_opened{0};
  std::atomic<std::uint64_t> sessions_closed{0};
  std::atomic<std::uint64_t> validations_approved{0};
  std::atomic<std::uint64_t> validations_rejected{0};
  std::atomic<std::uint64_t> validations_no_decision{0};
  std::atomic<std::uint64_t> validations_aborted{0};
  std::atomic<std::uint64_t> intervals{0};
  std::atomic<std::uint64_t> mqtt_published{0};
  std::atomic<std::uint64_t> mqtt_queue{0};
  std::atomic<std::uint64_t> store_dropped{0};
  std::atomic<std::uint64_t> proxy_bytes{0};
  std::atomic<std::uint64_t> proxy_parse_dropped{0};

  std::string render_prometheus(const std::vector<ValidatorStatus>& validators) const;
};

}  // namespace irbridge::health
