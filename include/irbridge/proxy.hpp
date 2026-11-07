// Proxy mode (TZ FR-1.4): transparent TCP relay controller <-> IntelliReader with a copy of the
// byte streams handed to the pipeline through a bounded lock-free SPSC queue.
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "irbridge/config.hpp"
#include "irbridge/tcp.hpp"
#include "irbridge/util.hpp"

namespace irbridge::proxy {

struct StreamEvent {
  enum class Kind : std::uint8_t { Open, Data, Gap, Close };
  Kind kind = Kind::Data;
  tcp::FlowKey key;
  tcp::Dir dir = tcp::Dir::ToReader;
  bool encrypted = false;
  util::Micros ts = 0;
  std::vector<std::uint8_t> bytes;
};

// Single-producer single-consumer ring. push/pop never block.
template <typename T>
class SpscQueue {
 public:
  explicit SpscQueue(std::size_t capacity) : buf_(capacity + 1) {}
  bool push(T&& v) {
    const std::size_t h = head_.load(std::memory_order_relaxed);
    const std::size_t n = next(h);
    if (n == tail_.load(std::memory_order_acquire)) return false;
    buf_[h] = std::move(v);
    head_.store(n, std::memory_order_release);
    return true;
  }
  bool pop(T& out) {
    const std::size_t t = tail_.load(std::memory_order_relaxed);
    if (t == head_.load(std::memory_order_acquire)) return false;
    out = std::move(buf_[t]);
    tail_.store(next(t), std::memory_order_release);
    return true;
  }
  std::size_t capacity() const { return buf_.size() - 1; }

 private:
  std::size_t next(std::size_t i) const { return (i + 1) % buf_.size(); }
  std::vector<T> buf_;
  alignas(64) std::atomic<std::size_t> head_{0};
  alignas(64) std::atomic<std::size_t> tail_{0};
};

struct ProxyStats {
  std::atomic<std::uint64_t> accepted{0};
  std::atomic<std::uint64_t> upstream_failures{0};
  std::atomic<std::uint64_t> bytes_to_reader{0};
  std::atomic<std::uint64_t> bytes_to_controller{0};
  std::atomic<std::uint64_t> parse_dropped{0};  // events not delivered to the parser (queue full)
};

class Proxy {
 public:
  struct Options {
    std::vector<config::ProxyRoute> routes;
    std::vector<std::uint16_t> tls_ports;
    std::size_t queue_capacity = 8192;
  };
  explicit Proxy(Options opt);
  ~Proxy();
  Proxy(const Proxy&) = delete;
  Proxy& operator=(const Proxy&) = delete;

  // Binds all listeners and starts the relay thread.
  bool start(std::string& error);
  void stop();

  // Consumer side (logic thread).
  bool pop(StreamEvent& ev) { return queue_.pop(ev); }
  const ProxyStats& stats() const { return stats_; }
  // Actual bound ports (useful with port 0 in tests), in route order.
  std::vector<std::uint16_t> bound_ports() const;

 private:
  struct Impl;
  void run();

  Options opt_;
  SpscQueue<StreamEvent> queue_;
  ProxyStats stats_;
  std::unique_ptr<Impl> impl_;
  std::thread thread_;
  std::atomic<bool> running_{false};
};

}  // namespace irbridge::proxy
