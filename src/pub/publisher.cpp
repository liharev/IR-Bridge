#include <spdlog/spdlog.h>

#include "irbridge/pub.hpp"

namespace irbridge::pub {

namespace {
constexpr util::Micros kAckTimeout = 30 * util::kMicrosPerSecond;
constexpr std::size_t kMaxInFlight = 100;
}  // namespace

Topics Topics::for_config(const config::Config& cfg) {
  const std::string base = cfg.mqtt.topic_prefix + "/" + cfg.vehicle_id;
  Topics t;
  t.validation = base + "/fare/validation";
  t.interval = base + "/fare/interval";
  t.validator_prefix = base + "/fare/validator";
  t.pax_count = base + "/pax/count";
  t.doors = base + "/doors";
  t.pax_fault = base + "/pax/fault";
  return t;
}

Publisher::Publisher(const config::Config& cfg, store::Store& store, IMqttClient& client, health::Metrics& metrics)
    : store_(store), client_(client), metrics_(metrics), topics_(Topics::for_config(cfg)) {
  client_.on_published = [this](int mid) { on_published(mid); };
}

void Publisher::on_published(int mid) {
  Flight f;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = flights_.find(mid);
    if (it == flights_.end()) return;
    f = it->second;
    flights_.erase(it);
    sent_ids_.erase(f.id);
  }
  store_.mark_published(f.kind, f.id);
  metrics_.mqtt_published.fetch_add(1, std::memory_order_relaxed);
}

std::size_t Publisher::in_flight() const {
  std::lock_guard<std::mutex> lk(mu_);
  return flights_.size();
}

void Publisher::pump(util::Micros now) {
  metrics_.mqtt_queue.store(store_.unpublished_count(), std::memory_order_relaxed);
  const bool connected = client_.connected();
  if (connected && !was_connected_) {
    // After a reconnect everything unacknowledged is sent again.
    std::lock_guard<std::mutex> lk(mu_);
    flights_.clear();
    sent_ids_.clear();
  }
  was_connected_ = connected;
  if (!connected) return;
  {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = flights_.begin(); it != flights_.end();) {
      if (now - it->second.sent > kAckTimeout) {
        sent_ids_.erase(it->second.id);
        it = flights_.erase(it);
      } else {
        ++it;
      }
    }
    if (flights_.size() >= kMaxInFlight) return;
  }
  for (const auto& r : store_.unpublished(kMaxInFlight)) {
    {
      std::lock_guard<std::mutex> lk(mu_);
      if (flights_.size() >= kMaxInFlight) break;
      if (sent_ids_.count(r.id) != 0) continue;  // waiting for PUBACK
    }
    const std::string& topic = r.kind == store::Kind::Validation ? topics_.validation : topics_.interval;
    const int mid = client_.publish(topic, r.json, 1, false);
    if (mid < 0) break;
    std::lock_guard<std::mutex> lk(mu_);
    flights_[mid] = Flight{r.kind, r.id, now};
    sent_ids_[r.id] = now;
  }
}

void Publisher::publish_status(const std::string& validator_id, const std::string& json) {
  if (!client_.connected()) return;  // retained statuses are re-sent after reconnect by the daemon
  client_.publish(topics_.validator_prefix + "/" + validator_id, json, 1, true);
}

}  // namespace irbridge::pub
