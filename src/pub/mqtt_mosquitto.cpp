#include <mosquitto.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cstring>
#include <mutex>

#include "irbridge/pub.hpp"

namespace irbridge::pub {

namespace {

std::once_flag g_lib_init;

class MosquittoClient final : public IMqttClient {
 public:
  ~MosquittoClient() override {
    if (m_ != nullptr) {
      mosquitto_disconnect(m_);
      mosquitto_loop_stop(m_, true);
      mosquitto_destroy(m_);
    }
  }

  bool init(const config::Config& cfg, std::string& error) {
    std::call_once(g_lib_init, [] { mosquitto_lib_init(); });
    const auto& q = cfg.mqtt;
    std::string url = q.url;
    bool tls = q.tls.enabled;
    for (const char* scheme : {"tcp://", "mqtt://", "ssl://", "mqtts://"}) {
      if (url.rfind(scheme, 0) == 0) {
        if (std::string(scheme) == "ssl://" || std::string(scheme) == "mqtts://") tls = true;
        url = url.substr(std::strlen(scheme));
      }
    }
    std::string host;
    std::uint16_t port = tls ? 8883 : 1883;
    if (!config::parse_host_port(url, host, port)) host = url;
    m_ = mosquitto_new(q.client_id.c_str(), false /* persistent session for QoS 1 */, this);
    if (m_ == nullptr) {
      error = "mosquitto_new failed";
      return false;
    }
    mosquitto_int_option(m_, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V311);
    mosquitto_max_inflight_messages_set(m_, 100);
    mosquitto_reconnect_delay_set(m_, 1, 60, true);
    if (!q.username.empty()) mosquitto_username_pw_set(m_, q.username.c_str(), q.password.c_str());
    if (tls) {
      const char* ca = q.tls.ca.empty() ? nullptr : q.tls.ca.c_str();
      const char* capath = ca ? nullptr : "/etc/ssl/certs";
      const int rc = mosquitto_tls_set(m_, ca, capath, q.tls.cert.empty() ? nullptr : q.tls.cert.c_str(),
                                       q.tls.key.empty() ? nullptr : q.tls.key.c_str(), nullptr);
      if (rc != MOSQ_ERR_SUCCESS) {
        error = std::string("mqtt tls: ") + mosquitto_strerror(rc);
        return false;
      }
    }
    mosquitto_connect_callback_set(m_, [](mosquitto*, void* self, int rc) {
      auto* c = static_cast<MosquittoClient*>(self);
      c->connected_ = rc == 0;
      if (rc == 0) {
        spdlog::info("MQTT connected");
      } else {
        spdlog::warn("MQTT connect refused: {}", mosquitto_connack_string(rc));
      }
      if (c->on_connection) c->on_connection(rc == 0);
    });
    mosquitto_disconnect_callback_set(m_, [](mosquitto*, void* self, int rc) {
      auto* c = static_cast<MosquittoClient*>(self);
      c->connected_ = false;
      if (rc != 0) spdlog::warn("MQTT disconnected: {}", mosquitto_strerror(rc));
      if (c->on_connection) c->on_connection(false);
    });
    mosquitto_publish_callback_set(m_, [](mosquitto*, void* self, int mid) {
      auto* c = static_cast<MosquittoClient*>(self);
      if (c->on_published) c->on_published(mid);
    });
    mosquitto_message_callback_set(m_, [](mosquitto*, void* self, const mosquitto_message* msg) {
      auto* c = static_cast<MosquittoClient*>(self);
      if (c->on_message && msg->topic != nullptr) {
        c->on_message(msg->topic,
                      std::string(static_cast<const char*>(msg->payload), static_cast<std::size_t>(msg->payloadlen)));
      }
    });
    int rc = mosquitto_connect_async(m_, host.c_str(), port, 30);
    if (rc != MOSQ_ERR_SUCCESS) {
      // Not fatal: the loop thread keeps retrying.
      spdlog::warn("MQTT initial connect to {}:{} failed: {}", host, port, mosquitto_strerror(rc));
    }
    rc = mosquitto_loop_start(m_);
    if (rc != MOSQ_ERR_SUCCESS) {
      error = std::string("mqtt loop: ") + mosquitto_strerror(rc);
      return false;
    }
    return true;
  }

  bool connected() const override { return connected_.load(); }

  int publish(const std::string& topic, const std::string& payload, int qos, bool retain) override {
    int mid = 0;
    const int rc = mosquitto_publish(m_, &mid, topic.c_str(), static_cast<int>(payload.size()), payload.data(), qos,
                                     retain);
    return rc == MOSQ_ERR_SUCCESS ? mid : -1;
  }

  bool subscribe(const std::string& topic, int qos) override {
    return mosquitto_subscribe(m_, nullptr, topic.c_str(), qos) == MOSQ_ERR_SUCCESS;
  }

 private:
  mosquitto* m_ = nullptr;
  std::atomic<bool> connected_{false};
};

}  // namespace

std::unique_ptr<IMqttClient> make_mosquitto_client(const config::Config& cfg, std::string& error) {
  auto c = std::make_unique<MosquittoClient>();
  if (!c->init(cfg, error)) return nullptr;
  return c;
}

}  // namespace irbridge::pub
