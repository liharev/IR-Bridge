// Processing pipeline: packets or byte streams -> frames -> correlation -> validation records.
// Single-threaded: call all methods from one thread.
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>

#include "irbridge/capture.hpp"
#include "irbridge/codec.hpp"
#include "irbridge/config.hpp"
#include "irbridge/corr.hpp"
#include "irbridge/detect.hpp"
#include "irbridge/health.hpp"
#include "irbridge/net.hpp"
#include "irbridge/privacy.hpp"
#include "irbridge/tcp.hpp"

namespace irbridge::pipeline {

struct ValidationEvent {
  std::string event_id;
  std::string vehicle_id;
  std::string validator_id;
  std::string door_id;
  std::string validator_ip;
  std::string ir_version;
  bool clock_synced = true;
  detect::ValidationRecord rec;
};

class Pipeline {
 public:
  using ValidationSink = std::function<void(ValidationEvent&&)>;

  Pipeline(const config::Config& cfg, const privacy::CarrierHasher& hasher, health::ValidatorRegistry& registry,
           health::Metrics& metrics, ValidationSink sink);
  ~Pipeline();
  Pipeline(const Pipeline&) = delete;
  Pipeline& operator=(const Pipeline&) = delete;

  // Mirror/bridge/pcap: one Ethernet frame.
  void on_packet(const capture::Packet& p);

  // Proxy mode (and FlowTable callbacks): reassembled byte streams.
  void stream_open(const tcp::FlowKey& k, bool encrypted, util::Micros ts);
  void stream_data(const tcp::FlowKey& k, tcp::Dir d, const std::uint8_t* data, std::size_t n, util::Micros ts);
  void stream_gap(const tcp::FlowKey& k, tcp::Dir d, util::Micros ts);
  void stream_close(const tcp::FlowKey& k, util::Micros ts);

  // Timeouts (decision windows, idle flows, reassembly holes, validator statuses).
  void on_tick(util::Micros now);
  // Closes all sessions (pending validations become ABORTED).
  void shutdown(util::Micros now);

  void set_clock_synced(bool v) { clock_synced_ = v; }
  // Overrides UUIDv7 generation (deterministic replay output).
  void set_event_id_generator(std::function<std::string(util::Micros)> gen) { id_gen_ = std::move(gen); }

  std::size_t sessions() const { return sessions_.size(); }
  const net::ParseStats& parse_stats() const { return parse_stats_; }
  const tcp::FlowTable& flows() const { return *flows_; }

  struct SessionCounters {
    codec::DecoderStats to_reader;
    codec::DecoderStats to_controller;
    corr::CorrelatorStats corr;
    detect::DetectorStats detect;
  };
  // Totals over closed and open sessions.
  SessionCounters totals() const;

 private:
  struct Session;
  Session& session(const tcp::FlowKey& k, util::Micros ts);
  void on_correlated(Session& s, corr::CorrelatedEvent& ev);
  void emit(Session& s, detect::ValidationRecord&& rec);
  void account(const Session& s);

  const config::Config& cfg_;
  const privacy::CarrierHasher& hasher_;
  health::ValidatorRegistry& registry_;
  health::Metrics& metrics_;
  ValidationSink sink_;
  std::unique_ptr<tcp::FlowTable> flows_;
  std::map<tcp::FlowKey, std::unique_ptr<Session>> sessions_;
  net::ParseStats parse_stats_;
  SessionCounters closed_totals_;
  bool clock_synced_ = true;
  std::function<std::string(util::Micros)> id_gen_;
};

}  // namespace irbridge::pipeline
