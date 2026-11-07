#include "irbridge/pipeline.hpp"

#include <spdlog/spdlog.h>

#include "common/failure.pb.h"
#include "misc/device.pb.h"
#include "misc/event.pb.h"
#include "misc/stats.pb.h"

namespace irbridge::pipeline {

struct Pipeline::Session {
  tcp::FlowKey key;
  bool encrypted = false;
  codec::StreamDecoder to_reader;
  codec::StreamDecoder to_controller;
  std::unique_ptr<corr::SessionCorrelator> corr;
  std::unique_ptr<detect::ValidationDetector> detector;
  std::uint64_t reported_crc = 0;
};

namespace {

void add(codec::DecoderStats& a, const codec::DecoderStats& b) {
  a.frames += b.frames;
  a.crc_errors += b.crc_errors;
  a.bad_length += b.bad_length;
  a.bad_type += b.bad_type;
  a.resyncs += b.resyncs;
  a.bytes_skipped += b.bytes_skipped;
  a.gaps += b.gaps;
}
void add(corr::CorrelatorStats& a, const corr::CorrelatorStats& b) {
  a.commands += b.commands;
  a.responses += b.responses;
  a.failures += b.failures;
  a.pendings += b.pendings;
  a.notifications += b.notifications;
  a.cancels += b.cancels;
  a.unmatched_responses += b.unmatched_responses;
  a.inferred_responses += b.inferred_responses;
  a.module_mismatches += b.module_mismatches;
  a.payload_errors += b.payload_errors;
  a.direction_errors += b.direction_errors;
  a.expired += b.expired;
}
void add(detect::DetectorStats& a, const detect::DetectorStats& b) {
  a.presentments += b.presentments;
  a.merged += b.merged;
  a.approved += b.approved;
  a.rejected += b.rejected;
  a.no_decision += b.no_decision;
  a.aborted += b.aborted;
  a.orphan_indications += b.orphan_indications;
}

bool is_hardware_failure(common::failure::Error e) {
  switch (e) {
    case common::failure::GENERAL_FAIL:
    case common::failure::NFC_ERROR:
    case common::failure::CONFIGURATION_ERROR:
    case common::failure::ABSENT_HARDWARE_MODULE:
    case common::failure::QRCODE_HARDWARE_ERROR:
    case common::failure::ABSENT_QRCODE_HARDWARE:
    case common::failure::SECURITY_FUNCTIONS_RESTRICTED:
      return true;
    default:
      return false;
  }
}

}  // namespace

Pipeline::Pipeline(const config::Config& cfg, const privacy::CarrierHasher& hasher, health::ValidatorRegistry& registry,
                   health::Metrics& metrics, ValidationSink sink)
    : cfg_(cfg), hasher_(hasher), registry_(registry), metrics_(metrics), sink_(std::move(sink)) {
  tcp::FlowTable::Options opt;
  opt.ir_ports = {cfg.capture.ir_ports.begin(), cfg.capture.ir_ports.end()};
  opt.tls_ports = {cfg.capture.tls_ports.begin(), cfg.capture.tls_ports.end()};
  opt.idle_timeout = static_cast<util::Micros>(cfg.session.idle_timeout_s) * util::kMicrosPerSecond;
  tcp::FlowTable::Callbacks cb;
  cb.on_open = [this](const tcp::FlowKey& k, bool enc, util::Micros ts) { stream_open(k, enc, ts); };
  cb.on_data = [this](const tcp::FlowKey& k, tcp::Dir d, const std::uint8_t* p, std::size_t n, util::Micros ts) {
    stream_data(k, d, p, n, ts);
  };
  cb.on_gap = [this](const tcp::FlowKey& k, tcp::Dir d, util::Micros ts) { stream_gap(k, d, ts); };
  cb.on_close = [this](const tcp::FlowKey& k, tcp::CloseReason r, util::Micros ts) {
    spdlog::debug("session {} closed ({})", k.str(), tcp::close_reason_name(r));
    stream_close(k, ts);
  };
  flows_ = std::make_unique<tcp::FlowTable>(opt, cb);
  id_gen_ = [](util::Micros ts) { return util::uuid_v7(ts); };
}

Pipeline::~Pipeline() = default;

void Pipeline::on_packet(const capture::Packet& p) {
  metrics_.packets.fetch_add(1, std::memory_order_relaxed);
  net::TcpSegment seg;
  if (!net::parse_ethernet(p.bytes.data(), p.bytes.size(), p.ts, seg, parse_stats_)) return;
  flows_->on_segment(seg);
}

Pipeline::Session& Pipeline::session(const tcp::FlowKey& k, util::Micros ts) {
  auto it = sessions_.find(k);
  if (it != sessions_.end()) return *it->second;
  stream_open(k, false, ts);
  return *sessions_.at(k);
}

void Pipeline::stream_open(const tcp::FlowKey& k, bool encrypted, util::Micros ts) {
  if (sessions_.count(k) != 0) return;
  auto s = std::make_unique<Session>();
  s->key = k;
  s->encrypted = encrypted;
  Session* raw = s.get();
  s->corr = std::make_unique<corr::SessionCorrelator>([this, raw](corr::CorrelatedEvent&& ev) { on_correlated(*raw, ev); });
  s->detector = std::make_unique<detect::ValidationDetector>(
      cfg_.detector, hasher_, [this, raw](detect::ValidationRecord&& rec) { emit(*raw, std::move(rec)); });
  sessions_.emplace(k, std::move(s));
  metrics_.sessions_opened.fetch_add(1, std::memory_order_relaxed);
  if (encrypted) {
    registry_.on_encrypted(k.ir_ip, ts);
    spdlog::debug("validator {}: TLS session on port {} cannot be observed", net::ip_to_string(k.ir_ip), k.ir_port);
  } else {
    spdlog::info("session {} opened", k.str());
  }
}

void Pipeline::stream_data(const tcp::FlowKey& k, tcp::Dir d, const std::uint8_t* data, std::size_t n,
                           util::Micros ts) {
  Session& s = session(k, ts);
  if (s.encrypted) {
    registry_.on_encrypted(k.ir_ip, ts);
    return;
  }
  codec::StreamDecoder& dec = d == tcp::Dir::ToReader ? s.to_reader : s.to_controller;
  dec.feed(data, n);
  std::uint64_t frames = 0;
  const corr::Direction cd = d == tcp::Dir::ToReader ? corr::Direction::ToReader : corr::Direction::ToController;
  dec.drain([&](codec::Frame&& f) {
    ++frames;
    s.corr->on_frame(f, ts, cd);
    util::secure_zero(f.payload);
  });
  if (frames > 0) {
    metrics_.frames.fetch_add(frames, std::memory_order_relaxed);
    registry_.on_frames(k.ir_ip, frames, ts);
  }
  const std::uint64_t crc = s.to_reader.stats().crc_errors + s.to_controller.stats().crc_errors;
  if (crc > s.reported_crc) {
    registry_.on_crc_errors(k.ir_ip, crc - s.reported_crc);
    metrics_.crc_errors.fetch_add(crc - s.reported_crc, std::memory_order_relaxed);
    s.reported_crc = crc;
  }
}

void Pipeline::stream_gap(const tcp::FlowKey& k, tcp::Dir d, util::Micros ts) {
  Session& s = session(k, ts);
  metrics_.tcp_gaps.fetch_add(1, std::memory_order_relaxed);
  (d == tcp::Dir::ToReader ? s.to_reader : s.to_controller).mark_gap();
  s.corr->on_gap();
}

void Pipeline::stream_close(const tcp::FlowKey& k, util::Micros ts) {
  auto it = sessions_.find(k);
  if (it == sessions_.end()) return;
  it->second->detector->on_session_closed(ts);
  account(*it->second);
  sessions_.erase(it);
  metrics_.sessions_closed.fetch_add(1, std::memory_order_relaxed);
}

void Pipeline::account(const Session& s) {
  add(closed_totals_.to_reader, s.to_reader.stats());
  add(closed_totals_.to_controller, s.to_controller.stats());
  add(closed_totals_.corr, s.corr->stats());
  add(closed_totals_.detect, s.detector->stats());
}

Pipeline::SessionCounters Pipeline::totals() const {
  SessionCounters t = closed_totals_;
  for (const auto& [k, s] : sessions_) {
    add(t.to_reader, s->to_reader.stats());
    add(t.to_controller, s->to_controller.stats());
    add(t.corr, s->corr->stats());
    add(t.detect, s->detector->stats());
  }
  return t;
}

void Pipeline::on_correlated(Session& s, corr::CorrelatedEvent& ev) {
  // Service information carried by responses.
  if (ev.kind == corr::EventKind::Succeeded && ev.response && ev.response->msg) {
    if (ev.response->kind == proto::ResponseKind::DeviceInfo) {
      const auto& di = static_cast<const misc::device::DeviceInfo&>(*ev.response->msg);
      registry_.on_version(s.key.ir_ip, di.intellireader_version());
    } else if (ev.response->kind == proto::ResponseKind::DeviceStatistic) {
      const auto& st = static_cast<const misc::stats::DeviceStatistic&>(*ev.response->msg);
      for (const auto& e : st.events()) {
        spdlog::info("validator {}: reader event {} ({} ms ago)", net::ip_to_string(s.key.ir_ip),
                     misc::event::EventType_Name(e.event_type()), e.event_time_offset());
      }
    }
  }
  if (ev.kind == corr::EventKind::Failed && ev.failure && is_hardware_failure(ev.failure->error())) {
    registry_.on_hardware_failure(s.key.ir_ip);
  }
  s.detector->on_event(ev);
}

void Pipeline::emit(Session& s, detect::ValidationRecord&& rec) {
  ValidationEvent e;
  e.vehicle_id = cfg_.vehicle_id;
  e.validator_ip = net::ip_to_string(s.key.ir_ip);
  registry_.identity(s.key.ir_ip, e.validator_id, e.door_id);
  e.clock_synced = clock_synced_;
  e.event_id = id_gen_(rec.ts_presented);
  if (!rec.presentment.ir_version.empty()) {
    e.ir_version = rec.presentment.ir_version;
    registry_.on_version(s.key.ir_ip, e.ir_version);
  } else {
    for (const auto& v : registry_.snapshot()) {
      if (v.ip == e.validator_ip) e.ir_version = v.ir_version;
    }
  }
  switch (rec.outcome) {
    case detect::Outcome::Approved: metrics_.validations_approved.fetch_add(1); break;
    case detect::Outcome::Rejected: metrics_.validations_rejected.fetch_add(1); break;
    case detect::Outcome::NoDecision: metrics_.validations_no_decision.fetch_add(1); break;
    case detect::Outcome::Aborted: metrics_.validations_aborted.fetch_add(1); break;
  }
  e.rec = std::move(rec);
  spdlog::debug("validation {} on {}: {} ({})", e.event_id, e.validator_id, detect::outcome_name(e.rec.outcome),
                e.rec.decision_rule);
  if (sink_) sink_(std::move(e));
}

void Pipeline::on_tick(util::Micros now) {
  flows_->on_tick(now);
  for (auto& [k, s] : sessions_) {
    s->corr->on_tick(now);
    s->detector->on_tick(now);
  }
  registry_.evaluate(now);
}

void Pipeline::shutdown(util::Micros now) {
  flows_->close_all(now);
  // Proxy sessions are not in the flow table.
  while (!sessions_.empty()) stream_close(sessions_.begin()->first, now);
}

}  // namespace irbridge::pipeline
