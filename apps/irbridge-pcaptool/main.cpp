// irbridge-pcaptool - offline tool: synthetic traffic, replay through the pipeline, capture statistics.
//
//   irbridge-pcaptool synth  --scenario s.yaml --out s.pcap
//   irbridge-pcaptool replay --pcap s.pcap --config irbridge.yaml [--out events.jsonl] [--strip]
//                            [--test-secret | --secret FILE] [--tz-offset MINUTES]
//   irbridge-pcaptool stats  --pcap s.pcap [--ports 42616,42800]
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

#include <spdlog/spdlog.h>

#include "irbridge/capture.hpp"
#include "irbridge/codec.hpp"
#include "irbridge/config.hpp"
#include "irbridge/json.hpp"
#include "irbridge/pipeline.hpp"
#include "irbridge/privacy.hpp"
#include "irbridge/proto.hpp"
#include "irbridge/synth.hpp"
#include "irbridge/tcp.hpp"

using namespace irbridge;

namespace {

int usage() {
  std::cerr << "Usage:\n"
               "  irbridge-pcaptool synth  --scenario FILE.yaml --out FILE.pcap\n"
               "  irbridge-pcaptool replay --pcap FILE.pcap --config irbridge.yaml [--out events.jsonl]\n"
               "                           [--strip] [--test-secret | --secret FILE] [--tz-offset MINUTES]\n"
               "  irbridge-pcaptool stats  --pcap FILE.pcap [--ports 42616,42800]\n"
               "\n"
               "  --strip        omit event_id and timestamps (comparison with reference outputs)\n"
               "  --test-secret  fixed hashing key (tests only; carrier_hash then is not the device's)\n";
  return 2;
}

struct Args {
  std::map<std::string, std::string> kv;
  std::map<std::string, bool> flags;
  bool has(const std::string& k) const { return kv.count(k) != 0; }
  std::string get(const std::string& k, const std::string& def = {}) const {
    auto it = kv.find(k);
    return it == kv.end() ? def : it->second;
  }
  bool flag(const std::string& k) const { return flags.count(k) != 0; }
};

bool parse_args(int argc, char** argv, int from, Args& a) {
  static const std::map<std::string, bool> kKnown{
      {"--scenario", true}, {"--out", true},    {"--pcap", true},        {"--config", true},
      {"--secret", true},   {"--ports", true},  {"--tz-offset", true},   {"--strip", false},
      {"--test-secret", false}};
  for (int i = from; i < argc; ++i) {
    const std::string k = argv[i];
    auto it = kKnown.find(k);
    if (it == kKnown.end()) {
      std::cerr << "unknown option " << k << "\n";
      return false;
    }
    if (it->second) {
      if (i + 1 >= argc) {
        std::cerr << k << " needs a value\n";
        return false;
      }
      a.kv[k] = argv[++i];
    } else {
      a.flags[k] = true;
    }
  }
  return true;
}

bool read_file(const std::string& path, std::string& out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return true;
}

// ---------------------------------------------------------------------------------------------
int cmd_synth(const Args& a) {
  if (!a.has("--scenario") || !a.has("--out")) return usage();
  std::string yaml;
  if (!read_file(a.get("--scenario"), yaml)) {
    std::cerr << "cannot read " << a.get("--scenario") << "\n";
    return 1;
  }
  capture::PcapWriter w(a.get("--out"));
  if (!w.ok()) {
    std::cerr << "cannot create " << a.get("--out") << "\n";
    return 1;
  }
  std::uint64_t n = 0;
  std::string err;
  const bool ok = synth::run_scenario(yaml, [&](capture::Packet&& p) {
    w.write(p.ts, p.bytes);
    ++n;
  }, err);
  w.flush();
  if (!ok) {
    std::cerr << "scenario error: " << err << "\n";
    return 1;
  }
  std::cerr << "wrote " << n << " packets to " << a.get("--out") << "\n";
  return 0;
}

// ---------------------------------------------------------------------------------------------
bool load_secret_readonly(const std::string& path, std::vector<std::uint8_t>& out, std::string& err) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    err = "cannot open secret " + path + " (use --secret FILE or --test-secret)";
    return false;
  }
  out.resize(privacy::kSecretSize);
  const ssize_t n = ::read(fd, out.data(), out.size());
  ::close(fd);
  if (n != static_cast<ssize_t>(out.size())) {
    err = "secret " + path + " has a wrong size";
    return false;
  }
  return true;
}

void strip_event(nlohmann::json& j) {
  j.erase("event_id");
  j.erase("ts_presented");
  j.erase("ts_decided");
}

int cmd_replay(const Args& a) {
  if (!a.has("--pcap") || !a.has("--config")) return usage();
  config::Config cfg;
  std::string err;
  if (!config::load_config(a.get("--config"), cfg, err)) {
    std::cerr << "config error: " << err << "\n";
    return 1;
  }
  std::vector<std::uint8_t> secret;
  if (a.flag("--test-secret")) {
    secret.assign(privacy::kSecretSize, 0x42);
  } else if (!load_secret_readonly(a.get("--secret", cfg.privacy.secret_file), secret, err)) {
    std::cerr << err << "\n";
    return 1;
  }
  privacy::CarrierHasher hasher(std::move(secret));

  capture::PcapFileSource src(a.get("--pcap"));
  if (!src.ok()) {
    std::cerr << "pcap: " << src.error() << "\n";
    return 1;
  }
  std::ofstream file;
  std::ostream* out = &std::cout;
  if (a.has("--out")) {
    file.open(a.get("--out"), std::ios::trunc);
    if (!file) {
      std::cerr << "cannot create " << a.get("--out") << "\n";
      return 1;
    }
    out = &file;
  }
  json::TimeFormat tf;
  tf.fixed = true;
  tf.offset_minutes = std::stoi(a.get("--tz-offset", "180"));
  const bool strip = a.flag("--strip");

  health::Metrics metrics;
  std::vector<std::string> transitions;
  health::ValidatorRegistry registry(cfg, [&](const health::ValidatorStatus& s) {
    transitions.push_back(s.validator_id + " " + health::status_name(s.status));
  });
  std::map<std::string, int> outcomes;
  std::uint64_t seq = 0;
  pipeline::Pipeline pipe(cfg, hasher, registry, metrics, [&](pipeline::ValidationEvent&& v) {
    outcomes[detect::outcome_name(v.rec.outcome)]++;
    auto j = json::validation(v, tf);
    if (strip) strip_event(j);
    *out << j.dump() << "\n";
  });
  pipe.set_event_id_generator([&](util::Micros) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "replay-%08llu", static_cast<unsigned long long>(++seq));
    return std::string(buf);
  });

  capture::Packet p;
  util::Micros last_tick = 0;
  util::Micros last_ts = 0;
  while (src.next(p, 0)) {
    pipe.on_packet(p);
    last_ts = p.ts;
    if (last_tick == 0) last_tick = p.ts;
    if (p.ts - last_tick >= 100 * util::kMicrosPerMilli) {
      pipe.on_tick(p.ts);
      last_tick = p.ts;
    }
  }
  // Let the decision windows of the last presentments expire, then close what is still open.
  if (last_ts != 0) {
    const util::Micros end = last_ts + cfg.detector.decision_window + util::kMicrosPerSecond;
    pipe.on_tick(end);
    pipe.shutdown(end);
  }
  out->flush();

  const auto t = pipe.totals();
  std::cerr << "packets " << src.stats().packets << ", frames " << metrics.frames.load() << ", crc errors "
            << metrics.crc_errors.load() << ", tcp gaps " << metrics.tcp_gaps.load() << ", sessions "
            << metrics.sessions_opened.load() << "\n";
  std::cerr << "commands " << t.corr.commands << ", responses " << t.corr.responses << ", inferred "
            << t.corr.inferred_responses << ", unmatched " << t.corr.unmatched_responses << "\n";
  std::cerr << "outcomes:";
  for (const auto& [k, v] : outcomes) std::cerr << " " << k << "=" << v;
  std::cerr << "\n";
  for (const auto& tr : transitions) std::cerr << "validator " << tr << "\n";
  return 0;
}

// ---------------------------------------------------------------------------------------------
int cmd_stats(const Args& a) {
  if (!a.has("--pcap")) return usage();
  capture::PcapFileSource src(a.get("--pcap"));
  if (!src.ok()) {
    std::cerr << "pcap: " << src.error() << "\n";
    return 1;
  }
  tcp::FlowTable::Options opt;
  opt.ir_ports = {42616};
  opt.tls_ports = {42800};
  if (a.has("--ports")) {
    opt.ir_ports.clear();
    std::stringstream ss(a.get("--ports"));
    std::string item;
    while (std::getline(ss, item, ',')) opt.ir_ports.insert(static_cast<std::uint16_t>(std::stoi(item)));
  }
  struct Sess {
    codec::StreamDecoder dec[2];
    bool encrypted = false;
  };
  std::map<tcp::FlowKey, Sess> sessions;
  std::map<std::pair<int, int>, std::uint64_t> by_module_type;  // (module, type) -> frames
  std::uint64_t gaps = 0, total_sessions = 0, encrypted = 0;
  codec::DecoderStats agg;
  auto absorb = [&](const codec::DecoderStats& s) {
    agg.frames += s.frames;
    agg.crc_errors += s.crc_errors;
    agg.bad_length += s.bad_length;
    agg.bad_type += s.bad_type;
    agg.resyncs += s.resyncs;
    agg.bytes_skipped += s.bytes_skipped;
  };
  tcp::FlowTable::Callbacks cb;
  cb.on_open = [&](const tcp::FlowKey& k, bool enc, util::Micros) {
    sessions[k].encrypted = enc;
    ++total_sessions;
    if (enc) ++encrypted;
  };
  cb.on_data = [&](const tcp::FlowKey& k, tcp::Dir d, const std::uint8_t* data, std::size_t n, util::Micros) {
    auto& s = sessions[k];
    if (s.encrypted) return;
    auto& dec = s.dec[d == tcp::Dir::ToReader ? 0 : 1];
    dec.feed(data, n);
    dec.drain([&](codec::Frame&& f) { by_module_type[{f.module, static_cast<int>(f.type)}]++; });
  };
  cb.on_gap = [&](const tcp::FlowKey& k, tcp::Dir d, util::Micros) {
    ++gaps;
    sessions[k].dec[d == tcp::Dir::ToReader ? 0 : 1].mark_gap();
  };
  cb.on_close = [&](const tcp::FlowKey& k, tcp::CloseReason, util::Micros) {
    auto it = sessions.find(k);
    if (it == sessions.end()) return;
    absorb(it->second.dec[0].stats());
    absorb(it->second.dec[1].stats());
    sessions.erase(it);
  };
  tcp::FlowTable flows(opt, cb);
  net::ParseStats ps;
  capture::Packet p;
  util::Micros last = 0;
  while (src.next(p, 0)) {
    net::TcpSegment seg;
    if (net::parse_ethernet(p.bytes.data(), p.bytes.size(), p.ts, seg, ps)) flows.on_segment(seg);
    last = p.ts;
  }
  flows.close_all(last);

  std::cout << "packets:   " << src.stats().packets << "\n";
  std::cout << "sessions:  " << total_sessions << " (TLS " << encrypted << ")\n";
  std::cout << "tcp gaps:  " << gaps << "\n";
  std::cout << "frames:    " << agg.frames << "\n";
  std::cout << "crc errors " << agg.crc_errors << ", bad length " << agg.bad_length << ", bad type " << agg.bad_type
            << ", resyncs " << agg.resyncs << ", bytes skipped " << agg.bytes_skipped << "\n";
  std::cout << "frames by MODULE/TYPE:\n";
  for (const auto& [mt, n] : by_module_type) {
    char hex[16];
    std::snprintf(hex, sizeof(hex), "%02X/%02X", mt.first, mt.second);
    std::cout << "  " << hex << "  " << proto::module_name(static_cast<std::uint8_t>(mt.first)) << " "
              << proto::type_name(static_cast<std::uint8_t>(mt.second)) << ": " << n << "\n";
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) return usage();
  spdlog::set_level(spdlog::level::warn);
  const std::string cmd = argv[1];
  Args a;
  if (!parse_args(argc, argv, 2, a)) return usage();
  if (cmd == "synth") return cmd_synth(a);
  if (cmd == "replay") return cmd_replay(a);
  if (cmd == "stats") return cmd_stats(a);
  return usage();
}
