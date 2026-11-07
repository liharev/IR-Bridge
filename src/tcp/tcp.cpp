#include "irbridge/tcp.hpp"

#include <tuple>

namespace irbridge::tcp {

std::string FlowKey::str() const {
  return net::ip_to_string(ctl_ip) + ":" + std::to_string(ctl_port) + "->" + net::ip_to_string(ir_ip) + ":" +
         std::to_string(ir_port);
}

const char* close_reason_name(CloseReason r) {
  switch (r) {
    case CloseReason::Fin: return "fin";
    case CloseReason::Rst: return "rst";
    case CloseReason::Idle: return "idle";
    case CloseReason::Shutdown: return "shutdown";
  }
  return "unknown";
}

namespace {
// Signed distance a - b in sequence space.
std::int32_t seq_diff(std::uint32_t a, std::uint32_t b) { return static_cast<std::int32_t>(a - b); }
}  // namespace

FlowTable::FlowTable(Options opt, Callbacks cb) : opt_(std::move(opt)), cb_(std::move(cb)) {}

const FlowStats* FlowTable::flow_stats(const FlowKey& k) const {
  auto it = flows_.find(k);
  return it == flows_.end() ? nullptr : &it->second.stats;
}

void FlowTable::on_segment(const net::TcpSegment& s) {
  FlowKey key;
  Dir dir;
  bool encrypted = false;
  const auto is_ir = [&](std::uint16_t p) { return opt_.ir_ports.count(p) > 0 || opt_.tls_ports.count(p) > 0; };
  if (is_ir(s.dport)) {
    key = {s.dst, s.dport, s.src, s.sport};
    dir = Dir::ToReader;
    encrypted = opt_.tls_ports.count(s.dport) > 0;
  } else if (is_ir(s.sport)) {
    key = {s.src, s.sport, s.dst, s.dport};
    dir = Dir::ToController;
    encrypted = opt_.tls_ports.count(s.sport) > 0;
  } else {
    ++stats_.ignored_segments;
    return;
  }

  auto it = flows_.find(key);
  if (it == flows_.end()) {
    if ((s.flags & net::kRst) != 0) return;  // RST for an unknown flow
    // A bare ACK/FIN of an unknown flow is the tail of a closed session: do not resurrect it.
    if ((s.flags & net::kSyn) == 0 && s.payload_len == 0) {
      ++stats_.ignored_segments;
      return;
    }
    if (flows_.size() >= opt_.max_flows) {
      ++stats_.ignored_segments;
      return;
    }
    it = flows_.emplace(key, Flow{}).first;
    it->second.encrypted = encrypted;
    ++stats_.flows_opened;
    if (encrypted) ++stats_.encrypted_flows;
    if (cb_.on_open) cb_.on_open(key, encrypted, s.ts);
  }
  Flow& f = it->second;
  f.last_seen = s.ts;
  ++f.stats.segments;

  if ((s.flags & net::kRst) != 0) {
    close(it, CloseReason::Rst, s.ts);
    return;
  }
  Half& h = dir == Dir::ToReader ? f.to_reader : f.to_controller;

  std::uint32_t seq = s.seq;
  if ((s.flags & net::kSyn) != 0) {
    h.have_seq = true;
    h.next_seq = s.seq + 1;
    seq = s.seq + 1;
    h.ooo.clear();
    h.ooo_bytes = 0;
  }

  if (!f.encrypted && s.payload_len > 0) {
    if (!h.have_seq) {  // flow started before capture: begin with the first segment seen
      h.have_seq = true;
      h.next_seq = seq;
    }
    deliver(key, f, dir, h, seq, s.payload, s.payload_len, s.ts);
  }

  if ((s.flags & net::kFin) != 0) {
    h.fin = true;
    if (f.to_reader.fin && f.to_controller.fin) {
      close(it, CloseReason::Fin, s.ts);
      return;
    }
  }
}

void FlowTable::deliver(const FlowKey& k, Flow& f, Dir d, Half& h, std::uint32_t seq, const std::uint8_t* p,
                        std::size_t n, util::Micros ts) {
  f.stats.bytes += n;
  std::int32_t diff = seq_diff(seq, h.next_seq);
  if (diff < 0) {
    // Retransmission or overlap: drop the part already delivered.
    const std::size_t old = static_cast<std::size_t>(-static_cast<std::int64_t>(diff));
    if (old >= n) {
      ++f.stats.retransmits;
      return;
    }
    p += old;
    n -= old;
    seq += static_cast<std::uint32_t>(old);
    diff = 0;
  }
  if (diff == 0) {
    if (cb_.on_data) cb_.on_data(k, d, p, n, ts);
    h.next_seq = seq + static_cast<std::uint32_t>(n);
    drain_ooo(k, f, d, h, ts);
    return;
  }
  // Ahead of the expected sequence: keep for later.
  ++f.stats.out_of_order;
  if (h.ooo.empty()) h.ooo_since = ts;
  auto [pos, inserted] = h.ooo.emplace(seq, std::vector<std::uint8_t>(p, p + n));
  if (inserted) {
    h.ooo_bytes += n;
  } else if (pos->second.size() < n) {
    h.ooo_bytes += n - pos->second.size();
    pos->second.assign(p, p + n);
  }
  if (h.ooo_bytes > opt_.max_ooo_bytes) {
    ++f.stats.ooo_overflow;
    force_gap(k, f, d, h, ts);
  }
}

void FlowTable::drain_ooo(const FlowKey& k, Flow& /*f*/, Dir d, Half& h, util::Micros ts) {
  while (!h.ooo.empty()) {
    // Find the segment closest to next_seq in sequence space (map order is numeric, not modular).
    auto best = h.ooo.end();
    std::int32_t best_diff = 0;
    for (auto it = h.ooo.begin(); it != h.ooo.end(); ++it) {
      const std::int32_t df = seq_diff(it->first, h.next_seq);
      if (best == h.ooo.end() || df < best_diff) {
        best = it;
        best_diff = df;
      }
    }
    if (best_diff > 0) break;  // still a hole
    std::vector<std::uint8_t> data = std::move(best->second);
    const std::uint32_t seq = best->first;
    h.ooo_bytes -= data.size();
    h.ooo.erase(best);
    const std::size_t old = static_cast<std::size_t>(-static_cast<std::int64_t>(best_diff));
    if (old < data.size()) {
      if (cb_.on_data) cb_.on_data(k, d, data.data() + old, data.size() - old, ts);
      h.next_seq = seq + static_cast<std::uint32_t>(data.size());
    }
    util::secure_zero(data);
  }
  if (!h.ooo.empty()) h.ooo_since = ts;
}

void FlowTable::force_gap(const FlowKey& k, Flow& f, Dir d, Half& h, util::Micros ts) {
  if (h.ooo.empty()) return;
  // Jump to the earliest buffered segment.
  auto first = h.ooo.begin();
  std::int32_t best = seq_diff(first->first, h.next_seq);
  for (auto it = h.ooo.begin(); it != h.ooo.end(); ++it) {
    const std::int32_t df = seq_diff(it->first, h.next_seq);
    if (df < best) {
      best = df;
      first = it;
    }
  }
  ++f.stats.gaps;
  if (cb_.on_gap) cb_.on_gap(k, d, ts);
  h.next_seq = first->first;
  drain_ooo(k, f, d, h, ts);
}

void FlowTable::on_tick(util::Micros now) {
  for (auto it = flows_.begin(); it != flows_.end();) {
    Flow& f = it->second;
    if (now - f.last_seen > opt_.idle_timeout) {
      auto victim = it++;
      close(victim, CloseReason::Idle, now);
      continue;
    }
    for (Dir d : {Dir::ToReader, Dir::ToController}) {
      Half& h = d == Dir::ToReader ? f.to_reader : f.to_controller;
      while (!h.ooo.empty() && now - h.ooo_since > opt_.reassembly_timeout) force_gap(it->first, f, d, h, now);
    }
    ++it;
  }
}

void FlowTable::close(std::map<FlowKey, Flow>::iterator it, CloseReason r, util::Micros ts) {
  const FlowKey key = it->first;
  for (Half* h : {&it->second.to_reader, &it->second.to_controller}) {
    for (auto& [s, data] : h->ooo) util::secure_zero(data);
  }
  flows_.erase(it);
  ++stats_.flows_closed;
  if (cb_.on_close) cb_.on_close(key, r, ts);
}

void FlowTable::close_all(util::Micros now) {
  while (!flows_.empty()) close(flows_.begin(), CloseReason::Shutdown, now);
}

}  // namespace irbridge::tcp
