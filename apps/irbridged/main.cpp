// irbridged - CAMAI IR-Bridge service: observes controller <-> IntelliReader traffic, detects
// successful validations and publishes them with fare intervals to the CAMAI bus.
#include <pthread.h>
#include <sched.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <thread>

#ifdef IRBRIDGE_WITH_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "irbridge/agg.hpp"
#include "irbridge/capture.hpp"
#include "irbridge/config.hpp"
#include "irbridge/health.hpp"
#include "irbridge/json.hpp"
#include "irbridge/pipeline.hpp"
#include "irbridge/privacy.hpp"
#include "irbridge/proxy.hpp"
#include "irbridge/pub.hpp"
#include "irbridge/store.hpp"
#include "irbridge/util.hpp"

using namespace irbridge;
namespace fs = std::filesystem;

namespace {

constexpr const char* kDefaultConfig = "/etc/camai/irbridge.yaml";
constexpr std::size_t kPacketQueueMax = 65536;
constexpr std::size_t kBusQueueMax = 4096;

// 0 = run, 1 = stop (SIGTERM/SIGINT), 2 = reload (SIGHUP)
std::atomic<int> g_signal{0};

extern "C" void on_signal(int sig) { g_signal.store(sig == SIGHUP ? 2 : 1); }

void notify(const char* state) {
#ifdef IRBRIDGE_WITH_SYSTEMD
  sd_notify(0, state);
#else
  (void)state;
#endif
}

util::Micros watchdog_interval() {
#ifdef IRBRIDGE_WITH_SYSTEMD
  std::uint64_t usec = 0;
  if (sd_watchdog_enabled(0, &usec) > 0 && usec > 0) return static_cast<util::Micros>(usec / 2);
#endif
  return 0;
}

void pin_current_thread(const std::vector<int>& cpus) {
  if (cpus.empty()) return;
  cpu_set_t set;
  CPU_ZERO(&set);
  const int ncpu = static_cast<int>(std::thread::hardware_concurrency());
  bool any = false;
  for (int c : cpus) {
    if (c >= 0 && c < CPU_SETSIZE && (ncpu == 0 || c < ncpu)) {
      CPU_SET(c, &set);
      any = true;
    }
  }
  if (!any) return;
  if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0) {
    spdlog::warn("cannot set CPU affinity");
  }
}

// Bounded multi-producer queue (mutex based, used for low-rate or batched handoffs).
template <typename T>
class BoundedQueue {
 public:
  explicit BoundedQueue(std::size_t max) : max_(max) {}
  bool push(T&& v) {
    std::lock_guard<std::mutex> lk(mu_);
    if (q_.size() >= max_) {
      ++dropped_;
      return false;
    }
    q_.push_back(std::move(v));
    cv_.notify_one();
    return true;
  }
  // Moves up to `max` items into `out`; waits up to `wait_ms` if empty.
  void drain(std::vector<T>& out, std::size_t max, int wait_ms) {
    std::unique_lock<std::mutex> lk(mu_);
    if (q_.empty() && wait_ms > 0) cv_.wait_for(lk, std::chrono::milliseconds(wait_ms));
    while (!q_.empty() && out.size() < max) {
      out.push_back(std::move(q_.front()));
      q_.pop_front();
    }
  }
  std::uint64_t dropped() const {
    std::lock_guard<std::mutex> lk(mu_);
    return dropped_;
  }

 private:
  std::size_t max_;
  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::deque<T> q_;
  std::uint64_t dropped_ = 0;
};

struct BusMessage {
  std::string topic;
  std::string payload;
};

// Optional raw traffic recording for diagnostics (TZ FR-9.3): off by default, 0600 files,
// bounded total size and age.
class RawRecorder {
 public:
  explicit RawRecorder(const config::Config::Privacy::RawCapture& rc) : rc_(rc) {
    std::error_code ec;
    fs::create_directories(rc_.dir, ec);
    fs::permissions(rc_.dir, fs::perms::owner_all, ec);
  }
  void write(const capture::Packet& p) {
    const std::uint64_t file_cap = static_cast<std::uint64_t>(rc_.max_mb) * 1024 * 1024 / 4;
    if (!w_ || w_->bytes_written() > file_cap) rotate(p.ts);
    if (w_ && w_->ok()) w_->write(p.ts, p.bytes);
  }

 private:
  void rotate(util::Micros ts) {
    w_.reset();
    cleanup(ts);
    const std::string name = rc_.dir + "/raw-" + std::to_string(ts / util::kMicrosPerSecond) + ".pcap";
    w_ = std::make_unique<capture::PcapWriter>(name, true);
    if (!w_->ok()) spdlog::warn("raw capture: cannot create {}", name);
  }
  void cleanup(util::Micros now) {
    std::error_code ec;
    std::vector<std::pair<fs::path, std::uint64_t>> files;
    for (const auto& e : fs::directory_iterator(rc_.dir, ec)) {
      if (e.path().extension() == ".pcap") files.emplace_back(e.path(), e.file_size(ec));
    }
    std::sort(files.begin(), files.end());  // names carry the start time
    const std::uint64_t cap = static_cast<std::uint64_t>(rc_.max_mb) * 1024 * 1024;
    std::uint64_t total = 0;
    for (const auto& f : files) total += f.second;
    const util::Micros max_age = static_cast<util::Micros>(rc_.max_age_h) * 3600 * util::kMicrosPerSecond;
    for (const auto& f : files) {
      util::Micros started = 0;
      try {
        started = std::stoll(f.first.stem().string().substr(4)) * util::kMicrosPerSecond;
      } catch (...) {
      }
      if (total > cap * 3 / 4 || (started > 0 && now - started > max_age)) {
        fs::remove(f.first, ec);
        total -= f.second;
      }
    }
  }

  config::Config::Privacy::RawCapture rc_;
  std::unique_ptr<capture::PcapWriter> w_;
};

enum class RunResult { Stop, Reload, Fatal };

RunResult run_service(const config::Config& cfg) {
  const util::Micros started = util::now_micros();
  // --- privacy secret ---------------------------------------------------------
  std::vector<std::uint8_t> secret;
  std::string err;
  {
    std::error_code ec;
    fs::create_directories(fs::path(cfg.privacy.secret_file).parent_path(), ec);
  }
  if (!privacy::load_or_create_secret(cfg.privacy.secret_file, secret, err)) {
    spdlog::critical("secret: {}", err);
    return RunResult::Fatal;
  }
  privacy::CarrierHasher hasher(std::move(secret));

  // --- storage ----------------------------------------------------------------
  store::Store db;
  {
    std::error_code ec;
    fs::create_directories(fs::path(cfg.storage.db_path).parent_path(), ec);
  }
  if (!db.open(cfg.storage.db_path, err)) {
    spdlog::critical("storage: {}", err);
    return RunResult::Fatal;
  }

  health::Metrics metrics;
  const json::TimeFormat tf;

  // Status transitions are stored and published as retained messages.
  BoundedQueue<std::pair<std::string, std::string>> status_out(1024);
  health::ValidatorRegistry registry(cfg, [&](const health::ValidatorStatus& s) {
    const std::string j = json::validator_status(s, tf).dump();
    spdlog::info("validator {} ({}) -> {}", s.validator_id, s.ip, health::status_name(s.status));
    db.put_status(s.validator_id, j, util::now_micros());
    status_out.push({s.validator_id, j});
  });

  const bool clock0 = util::clock_synchronized();
  agg::Aggregator aggregator(cfg, registry, [&](agg::FareInterval&& f) {
    metrics.intervals.fetch_add(1, std::memory_order_relaxed);
    if (!db.enqueue(store::Record{store::Kind::Interval, f.interval_id, f.ts_start, json::interval(f, tf).dump()})) {
      metrics.store_dropped.fetch_add(1, std::memory_order_relaxed);
    }
  });
  aggregator.set_clock_synced(clock0);

  pipeline::Pipeline pipe(cfg, hasher, registry, metrics, [&](pipeline::ValidationEvent&& v) {
    aggregator.on_validation(v);
    if (!db.enqueue(store::Record{store::Kind::Validation, v.event_id, v.rec.ts_presented,
                                  json::validation(v, tf).dump()})) {
      metrics.store_dropped.fetch_add(1, std::memory_order_relaxed);
    }
  });
  pipe.set_clock_synced(clock0);
  if (!clock0) spdlog::warn("system clock is not synchronized; events are marked clock_synced=false");

  // --- MQTT ---------------------------------------------------------------------
  BoundedQueue<BusMessage> bus_in(kBusQueueMax);
  std::unique_ptr<pub::IMqttClient> mqtt;
  std::unique_ptr<pub::Publisher> publisher;
  std::atomic<bool> republish_statuses{false};
  const pub::Topics topics = pub::Topics::for_config(cfg);
  if (cfg.mqtt.enabled) {
#ifdef IRBRIDGE_WITH_MQTT
    mqtt = pub::make_mosquitto_client(cfg, err);
    if (!mqtt) {
      spdlog::critical("mqtt: {}", err);
      return RunResult::Fatal;
    }
    pub::IMqttClient* raw = mqtt.get();
    mqtt->on_connection = [&, raw](bool up) {
      if (!up) return;
      raw->subscribe(topics.pax_count, 1);
      raw->subscribe(topics.doors, 1);
      raw->subscribe(topics.pax_fault, 1);
      republish_statuses = true;
    };
    mqtt->on_message = [&](const std::string& topic, const std::string& payload) {
      bus_in.push(BusMessage{topic, payload});
    };
    publisher = std::make_unique<pub::Publisher>(cfg, db, *mqtt, metrics);
#else
    spdlog::warn("built without MQTT support: mqtt.enabled ignored");
#endif
  }

  // --- HTTP API -----------------------------------------------------------------
  pub::HttpApi::Sources hs;
  hs.store = &db;
  hs.registry = &registry;
  hs.metrics = &metrics;
  hs.health_json = [&]() {
    nlohmann::json j;
    std::map<std::string, int> counts;
    bool degraded = false;
    for (const auto& v : registry.snapshot()) {
      counts[health::status_name(v.status)]++;
      if (v.status != health::Status::Observed && v.status != health::Status::Unmapped) degraded = true;
    }
    const bool mqtt_up = mqtt ? mqtt->connected() : false;
    if (cfg.mqtt.enabled && !mqtt_up) degraded = true;
    j["status"] = degraded ? "degraded" : "ok";
    j["version"] = IRBRIDGE_VERSION;
    j["vehicle_id"] = cfg.vehicle_id;
    j["mode"] = cfg.capture.mode;
    j["uptime_s"] = (util::now_micros() - started) / util::kMicrosPerSecond;
    j["validators"] = counts;
    j["mqtt_connected"] = mqtt_up;
    j["unpublished"] = metrics.mqtt_queue.load();
    j["clock_synced"] = util::clock_synchronized();
    j["packets"] = metrics.packets.load();
    j["kernel_drops"] = metrics.kernel_drops.load();
    return j.dump();
  };
  pub::HttpApi http(hs);
  if (!http.start(cfg.http.listen, err)) {
    spdlog::critical("{}", err);
    return RunResult::Fatal;
  }

  // --- capture ------------------------------------------------------------------
  std::atomic<bool> running{true};
  BoundedQueue<capture::Packet> packets(kPacketQueueMax);
  std::unique_ptr<capture::PacketSource> source;
  std::unique_ptr<proxy::Proxy> px;
  const auto& cap = cfg.capture;
  if (cap.mode == "mirror" || cap.mode == "bridge") {
    std::vector<std::uint16_t> ports = cap.ir_ports;
    ports.insert(ports.end(), cap.tls_ports.begin(), cap.tls_ports.end());
    auto s = std::make_unique<capture::AfPacketSource>(cap.interface, ports);
    if (!s->ok()) {
      spdlog::critical("capture on {}: {} (CAP_NET_RAW required)", cap.interface, s->error());
      return RunResult::Fatal;
    }
    source = std::move(s);
  } else if (cap.mode == "pcap-file") {
    auto s = std::make_unique<capture::PcapFileSource>(cap.pcap_file);
    if (!s->ok()) {
      spdlog::critical("pcap {}: {}", cap.pcap_file, s->error());
      return RunResult::Fatal;
    }
    source = std::move(s);
  } else {
    proxy::Proxy::Options po;
    po.routes = cap.proxy;
    po.tls_ports = cap.tls_ports;
    px = std::make_unique<proxy::Proxy>(po);
    if (!px->start(err)) {
      spdlog::critical("{}", err);
      return RunResult::Fatal;
    }
  }
  std::unique_ptr<RawRecorder> raw_rec;
  if (cfg.privacy.raw_capture.enabled) {
    if (source) {
      spdlog::warn("raw traffic recording is ON ({}): contains card data, use for diagnostics only",
                   cfg.privacy.raw_capture.dir);
      raw_rec = std::make_unique<RawRecorder>(cfg.privacy.raw_capture);
    } else {
      spdlog::warn("raw traffic recording is not supported in proxy mode");
    }
  }

  std::thread capture_thread;
  if (source) {
    capture_thread = std::thread([&] {
      pin_current_thread(cap.cpu_affinity);
      capture::Packet p;
      bool eof_logged = false;
      while (running) {
        if (source->next(p, 100)) {
          packets.push(std::move(p));
          p = capture::Packet{};
        } else if (source->eof()) {
          if (!eof_logged) {
            spdlog::info("pcap file finished");
            eof_logged = true;
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
      }
    });
  }

  // --- store / publication thread ---------------------------------------------------
  std::thread store_thread([&] {
    util::Micros last_flush = 0;
    util::Micros last_retention = 0;
    while (running) {
      const util::Micros now = util::now_micros();
      if (now - last_flush >= util::kMicrosPerSecond) {
        db.flush();
        last_flush = now;
      }
      if (now - last_retention >= 3600 * util::kMicrosPerSecond) {
        db.retention(now, cfg.storage.events_retention_days, cfg.storage.intervals_retention_days,
                     static_cast<std::uint64_t>(cfg.storage.max_db_mb) * 1024 * 1024);
        last_retention = now;
      }
      if (publisher) {
        if (republish_statuses.exchange(false)) {
          for (const auto& v : registry.snapshot()) publisher->publish_status(v.validator_id, json::validator_status(v, tf).dump());
        }
        std::vector<std::pair<std::string, std::string>> st;
        status_out.drain(st, 256, 0);
        for (const auto& [id, j] : st) publisher->publish_status(id, j);
        publisher->pump(now);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
  });

  // --- logic loop (this thread) ---------------------------------------------------------
  pin_current_thread(cap.cpu_affinity);
  const util::Micros wd = watchdog_interval();
  notify("READY=1");
  spdlog::info("irbridged {} started: vehicle={}, mode={}", IRBRIDGE_VERSION, cfg.vehicle_id, cap.mode);

  std::vector<capture::Packet> batch;
  std::vector<BusMessage> bus;
  util::Micros last_tick = 0;
  util::Micros file_clock = 0;
  util::Micros last_wd = 0;
  util::Micros last_clock = util::now_micros();
  RunResult result = RunResult::Stop;
  while (true) {
    const int sig = g_signal.exchange(0);
    if (sig == 1) break;
    if (sig == 2) {
      result = RunResult::Reload;
      break;
    }
    batch.clear();
    if (px) {
      proxy::StreamEvent ev;
      int n = 0;
      while (n < 4096 && px->pop(ev)) {
        ++n;
        switch (ev.kind) {
          case proxy::StreamEvent::Kind::Open: pipe.stream_open(ev.key, ev.encrypted, ev.ts); break;
          case proxy::StreamEvent::Kind::Data:
            metrics.proxy_bytes.fetch_add(ev.bytes.size(), std::memory_order_relaxed);
            pipe.stream_data(ev.key, ev.dir, ev.bytes.data(), ev.bytes.size(), ev.ts);
            util::secure_zero(ev.bytes);
            break;
          case proxy::StreamEvent::Kind::Gap: pipe.stream_gap(ev.key, ev.dir, ev.ts); break;
          case proxy::StreamEvent::Kind::Close: pipe.stream_close(ev.key, ev.ts); break;
        }
      }
      metrics.proxy_parse_dropped.store(px->stats().parse_dropped.load(), std::memory_order_relaxed);
      if (n == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    } else {
      packets.drain(batch, 1024, 50);
      for (auto& p : batch) {
        if (raw_rec) raw_rec->write(p);
        pipe.on_packet(p);
        util::secure_zero(p.bytes);  // packets may carry card data
        if (cap.mode == "pcap-file" && p.ts - file_clock >= 100 * util::kMicrosPerMilli) {
          pipe.on_tick(p.ts);  // a file is processed on its own clock
          file_clock = p.ts;
        }
      }
      const auto cs = source->stats();
      metrics.kernel_drops.store(cs.kernel_drops + packets.dropped(), std::memory_order_relaxed);
    }

    bus.clear();
    bus_in.drain(bus, 256, 0);
    for (const auto& m : bus) {
      if (m.topic == topics.pax_count) {
        agg::PaxCount pc;
        if (json::parse_pax(m.payload, pc)) aggregator.on_pax(pc);
        else spdlog::warn("bad pax message on {}", m.topic);
      } else if (m.topic == topics.doors) {
        agg::DoorEvent de;
        if (json::parse_door(m.payload, de)) aggregator.on_door(de);
        else spdlog::warn("bad door message on {}", m.topic);
      } else if (m.topic == topics.pax_fault) {
        agg::CounterFault cf;
        if (json::parse_fault(m.payload, cf)) aggregator.on_fault(cf);
        else spdlog::warn("bad counter fault message on {}", m.topic);
      }
    }

    const util::Micros now = util::now_micros();
    if (now - last_tick >= 100 * util::kMicrosPerMilli) {
      // In pcap-file mode timeouts follow the file's clock until the file ends.
      if (cap.mode != "pcap-file" || (source && source->eof() && batch.empty())) pipe.on_tick(now);
      aggregator.on_tick(now);
      last_tick = now;
    }
    if (now - last_clock >= 10 * util::kMicrosPerSecond) {
      const bool synced = util::clock_synchronized();
      pipe.set_clock_synced(synced);
      aggregator.set_clock_synced(synced);
      last_clock = now;
    }
    if (wd > 0 && now - last_wd >= wd) {
      notify("WATCHDOG=1");
      last_wd = now;
    }
  }

  // --- shutdown (target: under 5 s) --------------------------------------------------
  notify(result == RunResult::Reload ? "RELOADING=1" : "STOPPING=1");
  spdlog::info(result == RunResult::Reload ? "reloading configuration" : "stopping");
  running = false;
  if (capture_thread.joinable()) capture_thread.join();
  if (px) px->stop();
  const util::Micros end = util::now_micros();
  pipe.shutdown(end);
  aggregator.flush(end);
  if (store_thread.joinable()) store_thread.join();
  db.flush();
  spdlog::debug("shutdown: pipeline and store flushed in {} ms", (util::now_micros() - end) / 1000);
  if (publisher && mqtt && mqtt->connected()) {
    // Give QoS 1 deliveries up to ~2 s; whatever is left stays in the store for the next start.
    const util::Micros deadline = util::now_micros() + 2 * util::kMicrosPerSecond;
    while (util::now_micros() < deadline) {
      publisher->pump(util::now_micros());
      if (db.unpublished_count() == 0 && publisher->in_flight() == 0) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }
  spdlog::debug("shutdown: publication done at {} ms", (util::now_micros() - end) / 1000);
  http.stop();
  publisher.reset();
  mqtt.reset();
  db.close();
  spdlog::info("{} in {} ms", result == RunResult::Reload ? "restarted services" : "stopped",
               (util::now_micros() - end) / 1000);
  return result;
}

void usage() {
  std::cout << "Usage: irbridged [--config PATH] [--check-config] [--version]\n"
               "  --config PATH    configuration file (default " << kDefaultConfig << ")\n"
               "  --check-config   validate the configuration and exit (0 = valid)\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::string path = kDefaultConfig;
  bool check_only = false;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if ((a == "--config" || a == "-c") && i + 1 < argc) {
      path = argv[++i];
    } else if (a == "--check-config") {
      check_only = true;
    } else if (a == "--version") {
      std::cout << "irbridged " << IRBRIDGE_VERSION << "\n";
      return 0;
    } else if (a == "--help" || a == "-h") {
      usage();
      return 0;
    } else {
      std::cerr << "unknown argument: " << a << "\n";
      usage();
      return 2;
    }
  }

  config::Config cfg;
  std::string err;
  if (!config::load_config(path, cfg, err)) {
    std::cerr << "config error: " << err << "\n";
    return 1;
  }
  if (check_only) {
    std::cout << "configuration OK: " << path << "\n";
    return 0;
  }
  spdlog::set_level(spdlog::level::from_str(cfg.log.level));
  spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");

  struct sigaction sa{};
  sa.sa_handler = on_signal;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGTERM, &sa, nullptr);
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGHUP, &sa, nullptr);
  std::signal(SIGPIPE, SIG_IGN);

  for (;;) {
    const RunResult r = run_service(cfg);
    if (r == RunResult::Fatal) return 1;
    if (r == RunResult::Stop) return 0;
    config::Config next;
    if (config::load_config(path, next, err)) {
      cfg = std::move(next);
      spdlog::set_level(spdlog::level::from_str(cfg.log.level));
      spdlog::info("configuration reloaded");
    } else {
      spdlog::error("reload failed, keeping the previous configuration: {}", err);
    }
  }
}
