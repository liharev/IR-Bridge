// Service configuration (/etc/camai/irbridge.yaml, TZ section 7).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "irbridge/detect.hpp"
#include "irbridge/net.hpp"

namespace irbridge::config {

struct ValidatorCfg {
  std::string ip;
  net::Ip4 ip4 = 0;
  std::string validator_id;
  std::string door_id;
};

struct ProxyRoute {
  std::string listen;    // "0.0.0.0:42616"
  std::string upstream;  // "10.42.0.12:42616"
};

struct Config {
  std::string vehicle_id;

  struct Capture {
    std::string mode = "mirror";  // mirror | bridge | proxy | pcap-file
    std::string interface = "eth1";
    std::vector<std::uint16_t> ir_ports{42616};
    std::vector<std::uint16_t> tls_ports{42800};
    std::string pcap_file;
    std::vector<ProxyRoute> proxy;
    std::vector<int> cpu_affinity{0, 1, 2, 3};
  } capture;

  std::vector<ValidatorCfg> validators;

  struct Session {
    int idle_timeout_s = 120;
    int silence_timeout_s = 30;
  } session;

  detect::DetectorConfig detector;

  struct Aggregation {
    std::string match_scope = "vehicle";  // vehicle | door
    int post_close_tail_s = 120;
    int fallback_window_s = 300;
  } aggregation;

  struct Privacy {
    std::string secret_file = "/var/lib/camai/irbridge/secret.key";
    struct RawCapture {
      bool enabled = false;
      int max_mb = 50;
      int max_age_h = 24;
      std::string dir = "/var/lib/camai/irbridge/raw";
    } raw_capture;
  } privacy;

  struct Storage {
    std::string db_path = "/var/lib/camai/irbridge/events.db";
    int events_retention_days = 30;
    int intervals_retention_days = 90;
    int max_db_mb = 512;
  } storage;

  struct Mqtt {
    bool enabled = true;
    std::string url = "tcp://127.0.0.1:1883";
    std::string client_id;
    std::string username;
    std::string password;
    struct Tls {
      bool enabled = false;
      std::string ca;
      std::string cert;
      std::string key;
    } tls;
    std::string topic_prefix = "camai";
  } mqtt;

  struct Http {
    std::vector<std::string> listen{"127.0.0.1:8095"};
  } http;

  struct Log {
    std::string level = "info";
  } log;

  const ValidatorCfg* find_validator(net::Ip4 ip) const;
};

// Parses and validates. On error returns false and a human-readable message with the YAML path.
bool parse_config(const std::string& yaml_text, Config& out, std::string& error);
bool load_config(const std::string& path, Config& out, std::string& error);

// Parses a list of rules ("approve"/"reject" YAML sequences) - exposed for tests.
bool parse_host_port(const std::string& s, std::string& host, std::uint16_t& port);

}  // namespace irbridge::config
