#include "irbridge/config.hpp"

#include <yaml-cpp/yaml.h>

#include <fstream>
#include <set>
#include <sstream>

#include "gui/picture_id.pb.h"

namespace irbridge::config {

const ValidatorCfg* Config::find_validator(net::Ip4 ip) const {
  for (const auto& v : validators) {
    if (v.ip4 == ip) return &v;
  }
  return nullptr;
}

bool parse_host_port(const std::string& s, std::string& host, std::uint16_t& port) {
  const auto colon = s.rfind(':');
  if (colon == std::string::npos || colon == 0 || colon + 1 >= s.size()) return false;
  host = s.substr(0, colon);
  try {
    const int p = std::stoi(s.substr(colon + 1));
    if (p <= 0 || p > 65535) return false;
    port = static_cast<std::uint16_t>(p);
  } catch (...) {
    return false;
  }
  return true;
}

namespace {

struct Ctx {
  std::string error;
  bool fail(const std::string& path, const std::string& msg) {
    if (error.empty()) error = path + ": " + msg;
    return false;
  }
};

template <class T>
bool get(const YAML::Node& n, const char* key, T& out, const std::string& path, Ctx& c) {
  const YAML::Node v = n[key];
  if (!v || v.IsNull()) return true;  // keep default
  try {
    out = v.as<T>();
  } catch (const YAML::Exception&) {
    return c.fail(path + "." + key, "invalid value");
  }
  return true;
}

bool get_ports(const YAML::Node& n, const char* key, std::vector<std::uint16_t>& out, const std::string& path,
               Ctx& c) {
  const YAML::Node v = n[key];
  if (!v || v.IsNull()) return true;
  if (!v.IsSequence()) return c.fail(path + "." + key, "expected a list of ports");
  out.clear();
  for (std::size_t i = 0; i < v.size(); ++i) {
    int p = 0;
    try {
      p = v[i].as<int>();
    } catch (const YAML::Exception&) {
      return c.fail(path + "." + key + "[" + std::to_string(i) + "]", "invalid port");
    }
    if (p <= 0 || p > 65535) return c.fail(path + "." + key + "[" + std::to_string(i) + "]", "port out of range");
    out.push_back(static_cast<std::uint16_t>(p));
  }
  return true;
}

bool parse_rule(const YAML::Node& n, const std::string& path, detect::Rule& r, Ctx& c) {
  if (!n.IsMap()) return c.fail(path, "expected a mapping with 'type'");
  std::string type;
  if (!get(n, "type", type, path, c)) return false;
  if (type == "gui_picture") {
    r.type = detect::Rule::Type::GuiPicture;
    const YAML::Node ids = n["ids"];
    if (!ids || !ids.IsSequence() || ids.size() == 0) return c.fail(path + ".ids", "expected a non-empty list");
    for (std::size_t i = 0; i < ids.size(); ++i) {
      gui::picture_id::PictureId pid;
      const std::string name = ids[i].as<std::string>("");
      if (!gui::picture_id::PictureId_Parse(name, &pid)) {
        return c.fail(path + ".ids[" + std::to_string(i) + "]", "unknown picture id '" + name + "'");
      }
      r.picture_ids.push_back(pid);
    }
  } else if (type == "gui_text") {
    r.type = detect::Rule::Type::GuiText;
    if (!get(n, "regex", r.regex_source, path, c) || !get(n, "icase", r.icase, path, c)) return false;
    if (r.regex_source.empty()) return c.fail(path + ".regex", "required");
    try {
      r.compile();
    } catch (const std::regex_error& e) {
      return c.fail(path + ".regex", std::string("invalid regular expression: ") + e.what());
    }
  } else if (type == "gui_customer_picture") {
    r.type = detect::Rule::Type::GuiCustomerPicture;
    const YAML::Node names = n["names"];
    if (!names || !names.IsSequence() || names.size() == 0) return c.fail(path + ".names", "expected a non-empty list");
    for (std::size_t i = 0; i < names.size(); ++i) r.names.push_back(names[i].as<std::string>(""));
  } else if (type == "leds") {
    r.type = detect::Rule::Type::Leds;
    if (n["green"]) r.green = n["green"].as<bool>(false);
    if (n["red"]) r.red = n["red"].as<bool>(false);
    if (!r.green && !r.red) return c.fail(path, "leds rule needs 'green' or 'red'");
  } else if (type == "rgb_color") {
    r.type = detect::Rule::Type::RgbColor;
    if (!n["color"]) return c.fail(path + ".color", "required");
    try {
      r.color = n["color"].as<std::uint32_t>();
      r.tolerance = n["tolerance"] ? n["tolerance"].as<std::uint32_t>() : 0;
    } catch (const YAML::Exception&) {
      return c.fail(path, "invalid color or tolerance");
    }
    if (r.color > 0xFFFFFF || r.tolerance > 255) return c.fail(path, "color must be 0xRRGGBB, tolerance 0..255");
  } else if (type == "turnstile_pass") {
    r.type = detect::Rule::Type::TurnstilePass;
  } else {
    return c.fail(path + ".type", "unknown rule type '" + type + "'");
  }
  return true;
}

bool parse_rules(const YAML::Node& n, const std::string& path, std::vector<detect::Rule>& out, Ctx& c) {
  if (!n) return true;  // keep defaults
  if (!n.IsSequence()) return c.fail(path, "expected a list of rules");
  out.clear();
  for (std::size_t i = 0; i < n.size(); ++i) {
    detect::Rule r;
    if (!parse_rule(n[i], path + "[" + std::to_string(i) + "]", r, c)) return false;
    out.push_back(std::move(r));
  }
  return true;
}

bool parse_root(const YAML::Node& root, Config& cfg, Ctx& c) {
  if (!root.IsMap()) return c.fail("<root>", "expected a mapping");
  if (!get(root, "vehicle_id", cfg.vehicle_id, "", c)) return false;
  if (cfg.vehicle_id.empty()) return c.fail("vehicle_id", "required");
  if (cfg.vehicle_id.find_first_of("/#+ ") != std::string::npos) {
    return c.fail("vehicle_id", "must not contain '/', '#', '+' or spaces (used in MQTT topics)");
  }

  if (const YAML::Node cap = root["capture"]) {
    auto& k = cfg.capture;
    if (!get(cap, "mode", k.mode, "capture", c) || !get(cap, "interface", k.interface, "capture", c) ||
        !get_ports(cap, "ir_ports", k.ir_ports, "capture", c) ||
        !get_ports(cap, "tls_ports", k.tls_ports, "capture", c) || !get(cap, "pcap_file", k.pcap_file, "capture", c)) {
      return false;
    }
    if (const YAML::Node aff = cap["cpu_affinity"]) {
      try {
        k.cpu_affinity = aff.as<std::vector<int>>();
      } catch (const YAML::Exception&) {
        return c.fail("capture.cpu_affinity", "expected a list of CPU numbers");
      }
    }
    if (const YAML::Node px = cap["proxy"]) {
      const YAML::Node routes = px["listen"];
      if (routes && routes.IsSequence()) {
        for (std::size_t i = 0; i < routes.size(); ++i) {
          ProxyRoute r;
          const std::string p = "capture.proxy.listen[" + std::to_string(i) + "]";
          if (!get(routes[i], "listen", r.listen, p, c) || !get(routes[i], "upstream", r.upstream, p, c)) return false;
          std::string h;
          std::uint16_t port = 0;
          if (!parse_host_port(r.listen, h, port)) return c.fail(p + ".listen", "expected host:port");
          if (!parse_host_port(r.upstream, h, port)) return c.fail(p + ".upstream", "expected host:port");
          k.proxy.push_back(r);
        }
      }
    }
  }
  static const std::set<std::string> kModes{"mirror", "bridge", "proxy", "pcap-file"};
  if (kModes.count(cfg.capture.mode) == 0) return c.fail("capture.mode", "must be mirror, bridge, proxy or pcap-file");
  if (cfg.capture.mode == "pcap-file" && cfg.capture.pcap_file.empty()) {
    return c.fail("capture.pcap_file", "required for mode pcap-file");
  }
  if (cfg.capture.mode == "proxy" && cfg.capture.proxy.empty()) {
    return c.fail("capture.proxy.listen", "at least one route is required for mode proxy");
  }
  if ((cfg.capture.mode == "mirror" || cfg.capture.mode == "bridge") && cfg.capture.interface.empty()) {
    return c.fail("capture.interface", "required");
  }

  if (const YAML::Node vs = root["validators"]) {
    if (!vs.IsSequence()) return c.fail("validators", "expected a list");
    std::set<net::Ip4> seen_ips;
    std::set<std::string> seen_ids;
    for (std::size_t i = 0; i < vs.size(); ++i) {
      const std::string p = "validators[" + std::to_string(i) + "]";
      ValidatorCfg v;
      if (!get(vs[i], "ip", v.ip, p, c) || !get(vs[i], "validator_id", v.validator_id, p, c) ||
          !get(vs[i], "door_id", v.door_id, p, c)) {
        return false;
      }
      if (!net::parse_ip(v.ip, v.ip4)) return c.fail(p + ".ip", "invalid IPv4 address");
      if (v.validator_id.empty()) return c.fail(p + ".validator_id", "required");
      if (v.validator_id.find_first_of("/#+ ") != std::string::npos) {
        return c.fail(p + ".validator_id", "must not contain '/', '#', '+' or spaces");
      }
      if (!seen_ips.insert(v.ip4).second) return c.fail(p + ".ip", "duplicate address");
      if (!seen_ids.insert(v.validator_id).second) return c.fail(p + ".validator_id", "duplicate id");
      cfg.validators.push_back(v);
    }
  }

  if (const YAML::Node s = root["session"]) {
    if (!get(s, "idle_timeout_s", cfg.session.idle_timeout_s, "session", c) ||
        !get(s, "silence_timeout_s", cfg.session.silence_timeout_s, "session", c)) {
      return false;
    }
  }
  if (cfg.session.idle_timeout_s < 5 || cfg.session.silence_timeout_s < 2) {
    return c.fail("session", "idle_timeout_s >= 5 and silence_timeout_s >= 2 required");
  }

  if (const YAML::Node d = root["detector"]) {
    std::string policy = detect::policy_name(cfg.detector.policy);
    int window = 3000, merge = 1500;
    if (!get(d, "success_policy", policy, "detector", c) || !get(d, "decision_window_ms", window, "detector", c) ||
        !get(d, "same_carrier_merge_ms", merge, "detector", c) ||
        !get(d, "require_ack", cfg.detector.require_ack, "detector", c)) {
      return false;
    }
    if (!detect::parse_policy(policy, cfg.detector.policy)) {
      return c.fail("detector.success_policy", "must be indication, indication_or_write or emv_status");
    }
    if (window < 100 || window > 60000) return c.fail("detector.decision_window_ms", "must be 100..60000");
    if (merge < 0 || merge > window) return c.fail("detector.same_carrier_merge_ms", "must be 0..decision_window_ms");
    cfg.detector.decision_window = static_cast<util::Micros>(window) * util::kMicrosPerMilli;
    cfg.detector.same_carrier_merge = static_cast<util::Micros>(merge) * util::kMicrosPerMilli;
    if (!parse_rules(d["approve"], "detector.approve", cfg.detector.rules.approve, c) ||
        !parse_rules(d["reject"], "detector.reject", cfg.detector.rules.reject, c)) {
      return false;
    }
  }

  if (const YAML::Node a = root["aggregation"]) {
    if (!get(a, "match_scope", cfg.aggregation.match_scope, "aggregation", c) ||
        !get(a, "post_close_tail_s", cfg.aggregation.post_close_tail_s, "aggregation", c) ||
        !get(a, "fallback_window_s", cfg.aggregation.fallback_window_s, "aggregation", c)) {
      return false;
    }
  }
  if (cfg.aggregation.match_scope != "vehicle" && cfg.aggregation.match_scope != "door") {
    return c.fail("aggregation.match_scope", "must be vehicle or door");
  }
  if (cfg.aggregation.post_close_tail_s < 0 || cfg.aggregation.fallback_window_s < 30) {
    return c.fail("aggregation", "post_close_tail_s >= 0 and fallback_window_s >= 30 required");
  }

  if (const YAML::Node p = root["privacy"]) {
    if (!get(p, "secret_file", cfg.privacy.secret_file, "privacy", c)) return false;
    if (const YAML::Node rc = p["raw_capture"]) {
      auto& r = cfg.privacy.raw_capture;
      if (!get(rc, "enabled", r.enabled, "privacy.raw_capture", c) ||
          !get(rc, "max_mb", r.max_mb, "privacy.raw_capture", c) ||
          !get(rc, "max_age_h", r.max_age_h, "privacy.raw_capture", c) ||
          !get(rc, "dir", r.dir, "privacy.raw_capture", c)) {
        return false;
      }
      if (r.max_mb < 1 || r.max_mb > 1024 || r.max_age_h < 1 || r.max_age_h > 168) {
        return c.fail("privacy.raw_capture", "max_mb 1..1024 and max_age_h 1..168 required");
      }
    }
  }

  if (const YAML::Node s = root["storage"]) {
    if (!get(s, "db_path", cfg.storage.db_path, "storage", c) ||
        !get(s, "events_retention_days", cfg.storage.events_retention_days, "storage", c) ||
        !get(s, "intervals_retention_days", cfg.storage.intervals_retention_days, "storage", c) ||
        !get(s, "max_db_mb", cfg.storage.max_db_mb, "storage", c)) {
      return false;
    }
  }
  if (cfg.storage.events_retention_days < 1 || cfg.storage.intervals_retention_days < 1 || cfg.storage.max_db_mb < 16) {
    return c.fail("storage", "retention >= 1 day and max_db_mb >= 16 required");
  }

  if (const YAML::Node m = root["mqtt"]) {
    auto& q = cfg.mqtt;
    if (!get(m, "enabled", q.enabled, "mqtt", c) || !get(m, "url", q.url, "mqtt", c) ||
        !get(m, "client_id", q.client_id, "mqtt", c) || !get(m, "username", q.username, "mqtt", c) ||
        !get(m, "password", q.password, "mqtt", c) || !get(m, "topic_prefix", q.topic_prefix, "mqtt", c)) {
      return false;
    }
    if (const YAML::Node t = m["tls"]) {
      if (!get(t, "enabled", q.tls.enabled, "mqtt.tls", c) || !get(t, "ca", q.tls.ca, "mqtt.tls", c) ||
          !get(t, "cert", q.tls.cert, "mqtt.tls", c) || !get(t, "key", q.tls.key, "mqtt.tls", c)) {
        return false;
      }
    }
  }
  if (cfg.mqtt.client_id.empty()) cfg.mqtt.client_id = "irbridge-" + cfg.vehicle_id;
  if (cfg.mqtt.enabled && cfg.mqtt.url.rfind("tcp://", 0) != 0 && cfg.mqtt.url.rfind("ssl://", 0) != 0 &&
      cfg.mqtt.url.rfind("mqtt://", 0) != 0 && cfg.mqtt.url.rfind("mqtts://", 0) != 0) {
    return c.fail("mqtt.url", "expected tcp://host:port or ssl://host:port");
  }

  if (const YAML::Node h = root["http"]) {
    if (const YAML::Node l = h["listen"]) {
      try {
        cfg.http.listen = l.as<std::vector<std::string>>();
      } catch (const YAML::Exception&) {
        return c.fail("http.listen", "expected a list of host:port");
      }
      for (std::size_t i = 0; i < cfg.http.listen.size(); ++i) {
        std::string host;
        std::uint16_t port = 0;
        if (!parse_host_port(cfg.http.listen[i], host, port)) {
          return c.fail("http.listen[" + std::to_string(i) + "]", "expected host:port");
        }
      }
    }
  }

  if (const YAML::Node l = root["log"]) {
    if (!get(l, "level", cfg.log.level, "log", c)) return false;
  }
  static const std::set<std::string> kLevels{"trace", "debug", "info", "warn", "error", "critical", "off"};
  if (kLevels.count(cfg.log.level) == 0) return c.fail("log.level", "must be trace, debug, info, warn or error");
  return true;
}

}  // namespace

bool parse_config(const std::string& yaml_text, Config& out, std::string& error) {
  Ctx c;
  Config cfg;
  try {
    const YAML::Node root = YAML::Load(yaml_text);
    if (!parse_root(root, cfg, c)) {
      error = c.error;
      return false;
    }
  } catch (const YAML::Exception& e) {
    error = std::string("YAML syntax error: ") + e.what();
    return false;
  }
  out = std::move(cfg);
  return true;
}

bool load_config(const std::string& path, Config& out, std::string& error) {
  std::ifstream f(path);
  if (!f) {
    error = "cannot read " + path;
    return false;
  }
  std::stringstream ss;
  ss << f.rdbuf();
  if (!parse_config(ss.str(), out, error)) {
    error = path + ": " + error;
    return false;
  }
  return true;
}

}  // namespace irbridge::config
