#include <httplib.h>
#include <spdlog/spdlog.h>

#include <nlohmann/json.hpp>

#include "irbridge/json.hpp"
#include "irbridge/pub.hpp"

namespace irbridge::pub {

namespace {

constexpr std::size_t kMaxLimit = 1000;

// "since" accepts RFC 3339 or epoch milliseconds; empty means "everything".
bool parse_since(const httplib::Request& req, util::Micros& out) {
  out = 0;
  if (!req.has_param("since")) return true;
  const std::string s = req.get_param_value("since");
  if (s.empty()) return true;
  if (s.find_first_not_of("0123456789") == std::string::npos) {
    try {
      out = static_cast<util::Micros>(std::stoll(s)) * 1000;
      return true;
    } catch (...) {
      return false;
    }
  }
  return util::parse_rfc3339(s, out);
}

std::size_t parse_limit(const httplib::Request& req, std::size_t def) {
  if (!req.has_param("limit")) return def;
  try {
    const long long v = std::stoll(req.get_param_value("limit"));
    if (v <= 0) return def;
    return std::min<std::size_t>(static_cast<std::size_t>(v), kMaxLimit);
  } catch (...) {
    return def;
  }
}

std::string join_array(const std::vector<std::string>& items) {
  std::string out = "[";
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i != 0) out += ',';
    out += items[i];
  }
  out += ']';
  return out;
}

void bad_request(httplib::Response& res, const std::string& msg) {
  res.status = 400;
  res.set_content(nlohmann::json{{"error", msg}}.dump(), "application/json");
}

}  // namespace

struct HttpApi::Impl {
  Sources src;
  std::vector<std::unique_ptr<httplib::Server>> servers;
  std::vector<std::thread> threads;

  void routes(httplib::Server& s) {
    s.Get("/api/v1/health", [this](const httplib::Request&, httplib::Response& res) {
      res.set_content(src.health_json ? src.health_json() : std::string("{\"status\":\"ok\"}"), "application/json");
    });
    s.Get("/api/v1/validators", [this](const httplib::Request&, httplib::Response& res) {
      nlohmann::json arr = nlohmann::json::array();
      if (src.registry != nullptr) {
        for (const auto& v : src.registry->snapshot()) arr.push_back(json::validator_status(v, json::TimeFormat{}));
      }
      res.set_content(arr.dump(), "application/json");
    });
    s.Get("/api/v1/events", [this](const httplib::Request& req, httplib::Response& res) {
      util::Micros since = 0;
      if (!parse_since(req, since)) return bad_request(res, "bad 'since' (RFC 3339 or epoch ms)");
      const std::size_t limit = parse_limit(req, 100);
      res.set_content(join_array(src.store->validations_since(since, limit)), "application/json");
    });
    s.Get("/api/v1/intervals", [this](const httplib::Request& req, httplib::Response& res) {
      util::Micros since = 0;
      if (!parse_since(req, since)) return bad_request(res, "bad 'since' (RFC 3339 or epoch ms)");
      const std::size_t limit = parse_limit(req, 100);
      res.set_content(join_array(src.store->intervals_since(since, limit)), "application/json");
    });
    s.Get("/metrics", [this](const httplib::Request&, httplib::Response& res) {
      std::vector<health::ValidatorStatus> vs;
      if (src.registry != nullptr) vs = src.registry->snapshot();
      res.set_content(src.metrics != nullptr ? src.metrics->render_prometheus(vs) : std::string(),
                      "text/plain; version=0.0.4");
    });
  }
};

HttpApi::HttpApi(Sources src) : impl_(std::make_unique<Impl>()) { impl_->src = std::move(src); }

HttpApi::~HttpApi() { stop(); }

bool HttpApi::start(const std::vector<std::string>& listen, std::string& error) {
  for (const auto& addr : listen) {
    std::string host;
    std::uint16_t port = 0;
    if (!config::parse_host_port(addr, host, port) || port == 0) {
      error = "http.listen: bad address '" + addr + "'";
      return false;
    }
    auto srv = std::make_unique<httplib::Server>();
    srv->new_task_queue = [] { return new httplib::ThreadPool(2); };
    impl_->routes(*srv);
    if (!srv->bind_to_port(host, port)) {
      error = "http.listen: cannot bind " + addr;
      return false;
    }
    auto* raw = srv.get();
    impl_->threads.emplace_back([raw] { raw->listen_after_bind(); });
    impl_->servers.push_back(std::move(srv));
    spdlog::info("HTTP API listening on {}", addr);
  }
  return true;
}

void HttpApi::stop() {
  if (!impl_) return;
  for (auto& s : impl_->servers) s->stop();
  for (auto& t : impl_->threads) {
    if (t.joinable()) t.join();
  }
  impl_->threads.clear();
  impl_->servers.clear();
}

}  // namespace irbridge::pub
