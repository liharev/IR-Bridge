#include "irbridge/agg.hpp"

#include <algorithm>

namespace irbridge::agg {

Aggregator::Aggregator(const config::Config& cfg, const health::ValidatorRegistry& registry, Sink sink)
    : cfg_(cfg), registry_(registry), sink_(std::move(sink)) {
  id_gen_ = [](util::Micros ts) { return util::uuid_v7(ts); };
}

void Aggregator::start(util::Micros ts) {
  Active a;
  a.start = ts;
  if (!door_mode_) {
    const util::Micros w = static_cast<util::Micros>(cfg_.aggregation.fallback_window_s) * util::kMicrosPerSecond;
    a.start = ts - (ts % w);
    a.fallback_end = a.start + w;
  }
  active_ = std::move(a);
}

void Aggregator::ensure_active(util::Micros ts) {
  roll(ts);
  if (!active_) start(ts);
}

void Aggregator::roll(util::Micros ts) {
  if (!door_mode_ && active_ && active_->fallback_end > 0 && ts >= active_->fallback_end) close(active_->fallback_end);
}

void Aggregator::on_door(const DoorEvent& e) {
  if (!door_mode_) {
    // Switching from fixed windows to door-driven intervals: close the current window.
    if (active_) close(e.ts);
    door_mode_ = true;
  }
  if (e.open) {
    if (!active_) start(e.ts);
    active_->deadline.reset();
    open_doors_.insert(e.door_id);
    if (!e.stop_id.empty()) active_->stop_id = e.stop_id;
  } else {
    open_doors_.erase(e.door_id);
    if (active_ && open_doors_.empty()) {
      active_->deadline = e.ts + static_cast<util::Micros>(cfg_.aggregation.post_close_tail_s) * util::kMicrosPerSecond;
    }
  }
}

void Aggregator::on_pax(const PaxCount& p) {
  if (door_mode_ && !active_) {
    // Counts outside a stop (no door signal): open a short interval so they are not lost.
    start(p.ts);
    active_->deadline = p.ts + static_cast<util::Micros>(cfg_.aggregation.post_close_tail_s) * util::kMicrosPerSecond;
  }
  ensure_active(p.ts);
  DoorCounts& d = active_->doors[p.door_id];
  d.boarded += std::max(0, p.in);
  d.alighted += std::max(0, p.out);
  if (counter_fault_) d.counter_fault = true;
}

void Aggregator::on_fault(const CounterFault& f) {
  counter_fault_ = f.fault;
  if (active_ && f.fault) {
    if (f.door_id.empty()) {
      for (auto& [id, d] : active_->doors) d.counter_fault = true;
      active_->doors[""].counter_fault = true;
    } else {
      active_->doors[f.door_id].counter_fault = true;
    }
  }
}

void Aggregator::on_validation(const pipeline::ValidationEvent& v) {
  if (!active_ && door_mode_) {
    ++orphan_validations_;  // between stops after the tail: cannot be matched to boardings
    return;
  }
  ensure_active(v.rec.ts_presented);
  DoorCounts& d = active_->doors[v.door_id];
  switch (v.rec.outcome) {
    case detect::Outcome::Approved:
      ++d.approved;
      d.paid += v.rec.passengers;
      break;
    case detect::Outcome::Rejected: ++d.rejected; break;
    case detect::Outcome::NoDecision: ++d.no_decision; break;
    case detect::Outcome::Aborted: break;
  }
  if (!v.clock_synced) d.clock_unsynced = true;
}

void Aggregator::close(util::Micros end) {
  if (!active_) return;
  Active a = std::move(*active_);
  active_.reset();

  auto build = [&](const std::string& door, const std::vector<const DoorCounts*>& parts) {
    FareInterval fi;
    fi.interval_id = id_gen_(a.start);
    fi.vehicle_id = cfg_.vehicle_id;
    fi.scope = cfg_.aggregation.match_scope;
    fi.door_id = door;
    fi.stop_id = a.stop_id;
    fi.ts_start = a.start;
    fi.ts_end = end;
    bool fault = false, unsynced = false;
    for (const auto* p : parts) {
      fi.boarded += p->boarded;
      fi.alighted += p->alighted;
      fi.validations_approved += p->approved;
      fi.passengers_paid += p->paid;
      fi.validations_rejected += p->rejected;
      fi.no_decision += p->no_decision;
      fault = fault || p->counter_fault;
      unsynced = unsynced || p->clock_unsynced;
    }
    fi.unpaid_estimate = std::max(0, fi.boarded - fi.passengers_paid);
    const bool unobserved = registry_.any_unobserved_during(a.start, end, fi.scope == "door" ? door : std::string());
    if (unobserved) fi.unreliable_reasons.push_back("validator_unobserved");
    if (fault) fi.unreliable_reasons.push_back("counter_fault");
    if (unsynced || !clock_synced_) fi.unreliable_reasons.push_back("clock_unsynced");
    fi.reliable = fi.unreliable_reasons.empty();
    sink_(std::move(fi));
  };

  if (cfg_.aggregation.match_scope == "door") {
    for (const auto& [door, counts] : a.doors) build(door, {&counts});
    if (a.doors.empty()) build("", {});
  } else {
    std::vector<const DoorCounts*> all;
    for (const auto& [door, counts] : a.doors) all.push_back(&counts);
    build("", all);
  }
}

void Aggregator::on_tick(util::Micros now) {
  if (!active_) return;
  if (active_->deadline && now >= *active_->deadline) {
    close(*active_->deadline);
  } else if (!door_mode_ && active_->fallback_end > 0 && now >= active_->fallback_end) {
    close(active_->fallback_end);
  }
}

void Aggregator::flush(util::Micros now) { close(now); }

}  // namespace irbridge::agg
