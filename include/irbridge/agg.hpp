// Fare intervals: boarded passengers vs paid validations (TZ section 2, FR-7.1..7.4).
#pragma once

#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "irbridge/config.hpp"
#include "irbridge/health.hpp"
#include "irbridge/pipeline.hpp"

namespace irbridge::agg {

// Input from the CAMAI passenger counter.
struct PaxCount {
  std::string door_id;
  util::Micros ts = 0;
  int in = 0;
  int out = 0;
};

struct DoorEvent {
  std::string door_id;
  util::Micros ts = 0;
  bool open = false;
  std::string stop_id;  // optional, if the CAMAI bus knows the stop
};

struct CounterFault {
  std::string door_id;  // empty: whole vehicle
  util::Micros ts = 0;
  bool fault = true;
};

struct FareInterval {
  std::string interval_id;
  std::string vehicle_id;
  std::string scope;  // vehicle | door
  std::string door_id;
  std::string stop_id;
  util::Micros ts_start = 0;
  util::Micros ts_end = 0;
  int boarded = 0;
  int alighted = 0;
  int validations_approved = 0;
  int passengers_paid = 0;
  int validations_rejected = 0;
  int no_decision = 0;
  int unpaid_estimate = 0;
  bool reliable = true;
  std::vector<std::string> unreliable_reasons;
};

class Aggregator {
 public:
  using Sink = std::function<void(FareInterval&&)>;

  Aggregator(const config::Config& cfg, const health::ValidatorRegistry& registry, Sink sink);

  void on_door(const DoorEvent& e);
  void on_pax(const PaxCount& p);
  void on_fault(const CounterFault& f);
  void on_validation(const pipeline::ValidationEvent& v);
  void on_tick(util::Micros now);
  // Closes the open interval (service shutdown).
  void flush(util::Micros now);

  void set_id_generator(std::function<std::string(util::Micros)> gen) { id_gen_ = std::move(gen); }
  void set_clock_synced(bool v) { clock_synced_ = v; }
  bool active() const { return active_.has_value(); }
  std::uint64_t orphan_validations() const { return orphan_validations_; }

 private:
  struct DoorCounts {
    int boarded = 0;
    int alighted = 0;
    int approved = 0;
    int paid = 0;
    int rejected = 0;
    int no_decision = 0;
    bool counter_fault = false;
    bool clock_unsynced = false;
  };
  struct Active {
    util::Micros start = 0;
    std::optional<util::Micros> deadline;  // set when every door is closed
    util::Micros fallback_end = 0;         // fallback mode window end
    std::string stop_id;
    std::map<std::string, DoorCounts> doors;  // by door_id ("" = unknown door)
  };

  void start(util::Micros ts);
  void close(util::Micros end);
  void ensure_active(util::Micros ts);
  // Fixed-window mode: closes the window an event no longer belongs to.
  void roll(util::Micros ts);

  const config::Config& cfg_;
  const health::ValidatorRegistry& registry_;
  Sink sink_;
  std::function<std::string(util::Micros)> id_gen_;
  std::optional<Active> active_;
  std::set<std::string> open_doors_;
  bool door_mode_ = false;  // true once a door event has been seen
  bool counter_fault_ = false;
  bool clock_synced_ = true;
  std::uint64_t orphan_validations_ = 0;
};

}  // namespace irbridge::agg
