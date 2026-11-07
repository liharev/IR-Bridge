// Publication to the CAMAI bus (MQTT, QoS 1) and the local HTTP API (TZ section 5.4, FR-8.2, 8.3).
#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "irbridge/config.hpp"
#include "irbridge/health.hpp"
#include "irbridge/store.hpp"

namespace irbridge::pub {

class IMqttClient {
 public:
  virtual ~IMqttClient() = default;
  virtual bool connected() const = 0;
  // Returns the message id, or -1 when the message could not be queued.
  virtual int publish(const std::string& topic, const std::string& payload, int qos, bool retain) = 0;
  virtual bool subscribe(const std::string& topic, int qos) = 0;

  std::function<void(int mid)> on_published;
  std::function<void(const std::string& topic, const std::string& payload)> on_message;
  std::function<void(bool connected)> on_connection;
};

#ifdef IRBRIDGE_WITH_MQTT
// libmosquitto implementation with its own network thread and automatic reconnects (1..60 s).
std::unique_ptr<IMqttClient> make_mosquitto_client(const config::Config& cfg, std::string& error);
#endif

struct Topics {
  std::string validation;
  std::string interval;
  std::string validator_prefix;  // + "/<validator_id>"
  std::string pax_count;
  std::string doors;
  std::string pax_fault;
  static Topics for_config(const config::Config& cfg);
};

// Moves records from the store to MQTT with at-least-once delivery: a record is marked published
// only after PUBACK; unacknowledged records are sent again after a timeout (same event_id).
class Publisher {
 public:
  Publisher(const config::Config& cfg, store::Store& store, IMqttClient& client, health::Metrics& metrics);

  // Publishes the next batch of unpublished records. Call periodically (e.g. every 200 ms).
  void pump(util::Micros now);
  void publish_status(const std::string& validator_id, const std::string& json);
  std::size_t in_flight() const;

 private:
  struct Flight {
    store::Kind kind;
    std::string id;
    util::Micros sent = 0;
  };
  void on_published(int mid);

  store::Store& store_;
  IMqttClient& client_;
  health::Metrics& metrics_;
  Topics topics_;
  mutable std::mutex mu_;
  std::map<int, Flight> flights_;                 // by MQTT message id
  std::map<std::string, util::Micros> sent_ids_;  // id -> last send time
  bool was_connected_ = false;
};

// Local HTTP API on the configured addresses (cpp-httplib, one thread per listener).
class HttpApi {
 public:
  struct Sources {
    store::Store* store = nullptr;
    health::ValidatorRegistry* registry = nullptr;
    health::Metrics* metrics = nullptr;
    std::function<std::string()> health_json;
  };
  explicit HttpApi(Sources src);
  ~HttpApi();
  HttpApi(const HttpApi&) = delete;
  HttpApi& operator=(const HttpApi&) = delete;

  bool start(const std::vector<std::string>& listen, std::string& error);
  void stop();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace irbridge::pub
