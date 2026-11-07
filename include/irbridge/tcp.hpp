// TCP stream reassembly for controller <-> IntelliReader sessions (TZ FR-2.1..2.5).
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "irbridge/net.hpp"
#include "irbridge/util.hpp"

namespace irbridge::tcp {

// The reader (IntelliReader, TCP server) side and the controller (client) side of a session.
struct FlowKey {
  net::Ip4 ir_ip = 0;
  std::uint16_t ir_port = 0;
  net::Ip4 ctl_ip = 0;
  std::uint16_t ctl_port = 0;
  bool operator<(const FlowKey& o) const {
    return std::tie(ir_ip, ir_port, ctl_ip, ctl_port) < std::tie(o.ir_ip, o.ir_port, o.ctl_ip, o.ctl_port);
  }
  bool operator==(const FlowKey& o) const {
    return ir_ip == o.ir_ip && ir_port == o.ir_port && ctl_ip == o.ctl_ip && ctl_port == o.ctl_port;
  }
  std::string str() const;
};

enum class Dir { ToReader, ToController };

enum class CloseReason { Fin, Rst, Idle, Shutdown };
const char* close_reason_name(CloseReason r);

struct FlowStats {
  std::uint64_t segments = 0;
  std::uint64_t bytes = 0;
  std::uint64_t retransmits = 0;
  std::uint64_t out_of_order = 0;
  std::uint64_t gaps = 0;
  std::uint64_t ooo_overflow = 0;
};

struct TableStats {
  std::uint64_t flows_opened = 0;
  std::uint64_t flows_closed = 0;
  std::uint64_t encrypted_flows = 0;
  std::uint64_t ignored_segments = 0;
};

class FlowTable {
 public:
  struct Callbacks {
    std::function<void(const FlowKey&, bool encrypted, util::Micros ts)> on_open;
    std::function<void(const FlowKey&, Dir, const std::uint8_t*, std::size_t, util::Micros ts)> on_data;
    std::function<void(const FlowKey&, Dir, util::Micros ts)> on_gap;
    std::function<void(const FlowKey&, CloseReason, util::Micros ts)> on_close;
  };

  struct Options {
    std::set<std::uint16_t> ir_ports{42616};
    std::set<std::uint16_t> tls_ports{42800};
    util::Micros idle_timeout = 120 * util::kMicrosPerSecond;
    std::size_t max_ooo_bytes = 64 * 1024;
    // A hole older than this is declared lost (mirror ports drop packets that are never resent).
    util::Micros reassembly_timeout = 500 * util::kMicrosPerMilli;
    std::size_t max_flows = 1024;
  };

  FlowTable(Options opt, Callbacks cb);

  void on_segment(const net::TcpSegment& s);
  void on_tick(util::Micros now);
  void close_all(util::Micros now);

  std::size_t size() const { return flows_.size(); }
  const TableStats& stats() const { return stats_; }
  const FlowStats* flow_stats(const FlowKey& k) const;

 private:
  struct Half {
    bool have_seq = false;
    std::uint32_t next_seq = 0;
    std::map<std::uint32_t, std::vector<std::uint8_t>> ooo;  // keyed by seq (relative order via next_seq)
    std::size_t ooo_bytes = 0;
    util::Micros ooo_since = 0;
    bool fin = false;
  };
  struct Flow {
    bool encrypted = false;
    Half to_reader;
    Half to_controller;
    util::Micros last_seen = 0;
    FlowStats stats;
  };

  void deliver(const FlowKey& k, Flow& f, Dir d, Half& h, std::uint32_t seq, const std::uint8_t* p, std::size_t n,
               util::Micros ts);
  void drain_ooo(const FlowKey& k, Flow& f, Dir d, Half& h, util::Micros ts);
  void force_gap(const FlowKey& k, Flow& f, Dir d, Half& h, util::Micros ts);
  void close(std::map<FlowKey, Flow>::iterator it, CloseReason r, util::Micros ts);

  Options opt_;
  Callbacks cb_;
  std::map<FlowKey, Flow> flows_;
  TableStats stats_;
};

}  // namespace irbridge::tcp
