#include "irbridge/synth.hpp"

#include <yaml-cpp/yaml.h>

#include "commands.pb.h"
#include "common/failure.pb.h"
#include "complex/poll_for_event.pb.h"
#include "contactless/token.pb.h"
#include "contactless/transaction.pb.h"
#include "gui/screen.pb.h"
#include "gui/widget.pb.h"
#include "irbridge/codec.hpp"
#include "misc/device.pb.h"
#include "mifare/classic/read.pb.h"
#include "qrcode/qrcode_event.pb.h"
#include "troika/av3/read_ticket.pb.h"
#include "troika/av3/write_ticket.pb.h"

namespace irbridge::synth {

namespace {

std::string ser(const google::protobuf::Message& m) {
  std::string s;
  m.SerializeToString(&s);
  return s;
}

std::string unhex(const std::string& h) {
  std::vector<std::uint8_t> v;
  if (!util::from_hex(h, v)) return {};
  return std::string(v.begin(), v.end());
}

std::string bcd3(int a, int b, int c) {
  auto bcd = [](int x) { return static_cast<char>(((x / 10) << 4) | (x % 10)); };
  return std::string{bcd(a % 100), bcd(b), bcd(c)};
}

}  // namespace

Generator::Generator(util::Micros start, net::Ip4 controller_ip, PacketSink sink)
    : now_(start), ctl_(controller_ip), sink_(std::move(sink)) {}

Generator::Conn& Generator::conn(net::Ip4 ir) {
  auto it = conns_.find(ir);
  if (it == conns_.end()) {
    open(ir);
    it = conns_.find(ir);
  }
  return it->second;
}

void Generator::send(net::Ip4 ir, bool from_controller, const std::vector<std::uint8_t>& data, std::uint8_t flags) {
  Conn& c = conns_.at(ir);
  std::uint32_t& seq = from_controller ? c.seq_ctl : c.seq_ir;
  const std::uint32_t ack = from_controller ? c.seq_ir : c.seq_ctl;
  capture::Packet p;
  p.ts = now_;
  if (from_controller) {
    p.bytes = net::build_tcp_frame(ctl_, c.ctl_port, ir, c.port, seq, ack, flags, data.data(), data.size());
  } else {
    p.bytes = net::build_tcp_frame(ir, c.port, ctl_, c.ctl_port, seq, ack, flags, data.data(), data.size());
  }
  seq += static_cast<std::uint32_t>(data.size());
  if ((flags & (net::kSyn | net::kFin)) != 0) seq += 1;
  if (c.drop_next) {
    c.drop_next = false;  // lost on the mirror: the real peers still received it
    return;
  }
  sink_(std::move(p));
}

void Generator::frame(net::Ip4 ir, bool from_controller, std::uint8_t msgid, std::uint8_t module, std::uint8_t type,
                      const std::string& payload) {
  codec::Frame f;
  f.msgid = msgid;
  f.module = module;
  f.type = type;
  f.payload.assign(payload.begin(), payload.end());
  send(ir, from_controller, codec::encode(f), net::kAck | net::kPsh);
}

void Generator::open(net::Ip4 ir, std::uint16_t port) {
  Conn c;
  c.port = port;
  c.ctl_port = next_port_++;
  c.seq_ctl = 1000u + c.ctl_port * 7u;
  c.seq_ir = 0xFFFFF000u;  // exercises sequence wrap-around
  conns_[ir] = c;
  send(ir, true, {}, net::kSyn);
  step(1);
  send(ir, false, {}, net::kSyn | net::kAck);
  step(1);
  send(ir, true, {}, net::kAck);
  step(5);
}

void Generator::close(net::Ip4 ir) {
  if (conns_.count(ir) == 0) return;
  send(ir, true, {}, net::kFin | net::kAck);
  step(1);
  send(ir, false, {}, net::kFin | net::kAck);
  step(1);
  send(ir, true, {}, net::kAck);
  conns_.erase(ir);
  step(10);
}

void Generator::reset(net::Ip4 ir) {
  if (conns_.count(ir) == 0) return;
  send(ir, false, {}, net::kRst);
  conns_.erase(ir);
  step(10);
}

void Generator::drop_next_packet(net::Ip4 ir) { conn(ir).drop_next = true; }

void Generator::command(net::Ip4 ir, std::uint8_t module, const std::string& payload, bool pending) {
  Conn& c = conn(ir);
  c.msgid = static_cast<std::uint8_t>(c.msgid + 1);
  frame(ir, true, c.msgid, module, 0x01, payload);
  step(3);
  if (pending) {
    frame(ir, false, c.msgid, module, 0x04, "");
    step(5);
  }
}

void Generator::success(net::Ip4 ir, std::uint8_t module, const std::string& payload) {
  frame(ir, false, conn(ir).msgid, module, 0x02, payload);
  step(5);
}

void Generator::failure(net::Ip4 ir, std::uint8_t module, int error) {
  common::failure::FailureResponse f;
  f.set_error(static_cast<common::failure::Error>(error));
  frame(ir, false, conn(ir).msgid, module, 0x03, ser(f));
  step(5);
}

void Generator::echo(net::Ip4 ir) {
  ::Miscellaneous m;
  m.mutable_get_echo()->set_data("ping");
  command(ir, 0x01, ser(m), true);
  misc::echo::Echo e;
  e.set_echo("ping");
  success(ir, 0x01, ser(e));
}

void Generator::device_info(net::Ip4 ir, const std::string& version) {
  ::Miscellaneous m;
  m.mutable_read_device_info();
  command(ir, 0x01, ser(m));
  misc::device::DeviceInfo d;
  d.set_serial_number("VT00012345");
  d.set_intellireader_version(version);
  success(ir, 0x01, ser(d));
}

namespace {
contactless::transaction::PerformTransaction make_txn(std::uint64_t amount, const std::string& indication,
                                                      util::Micros now) {
  contactless::transaction::PerformTransaction t;
  t.mutable_poll_for_token()->set_timeout(1000);
  t.set_amount_authorized(amount);
  const std::time_t secs = static_cast<std::time_t>(now / util::kMicrosPerSecond);
  std::tm tm{};
  gmtime_r(&secs, &tm);
  t.set_transaction_date(bcd3(tm.tm_year, tm.tm_mon + 1, tm.tm_mday));
  t.set_transaction_time(bcd3(tm.tm_hour, tm.tm_min, tm.tm_sec));
  t.set_transaction_type(std::string("\x00", 1));
  t.set_terminal_country_code(std::string("\x06\x43", 2));
  t.set_transaction_currency_code(std::string("\x06\x43", 2));
  t.set_merchant_category_code(std::string("\x41\x31", 2));
  t.set_terminal_identification("VT0012");
  contactless::indication::Indication ind;
  if (contactless::indication::Indication_Parse(indication, &ind)) t.set_indication(ind);
  return t;
}
}  // namespace

void Generator::idle_poll(net::Ip4 ir, int count) {
  for (int i = 0; i < count; ++i) {
    ::ContactlessLevel2 w;
    *w.mutable_perform_transaction() = make_txn(6600, "PROCESSING_ONLY", now_);
    command(ir, 0x04, ser(w), true);
    step(1000);
    failure(ir, 0x04, common::failure::TIMEOUT_EXPIRED);
    step(20);
  }
}

void Generator::bank_card(net::Ip4 ir, const BankCard& c) {
  contactless::transaction::TransactionResult r;
  contactless::transaction::TransactionStatus st;
  if (!contactless::transaction::TransactionStatus_Parse(c.status, &st)) st = contactless::transaction::OFFLINE_DECLINED;
  r.set_status(st);
  r.mutable_token()->set_type(contactless::token_type::ISO_14443_4A);
  r.mutable_token()->set_id(unhex(c.uid));
  r.mutable_token()->set_atqa(unhex("0400"));
  r.mutable_token()->set_sak(unhex("20"));
  contactless::token_carrier_type::TokenCarrierType ct;
  if (contactless::token_carrier_type::TokenCarrierType_Parse(c.carrier, &ct)) r.set_token_carrier_type(ct);
  auto tag = [&](std::uint32_t n, const std::string& v) {
    auto* t = r.add_emv_tags();
    t->set_number(n);
    t->set_value(v);
  };
  tag(0x50, "MIR");
  // Test card data: Luhn-invalid number, must never leave the detector.
  tag(0x5A, unhex("2200000000000001"));
  tag(0x57, unhex("2200000000000001D29122010000000000000F"));
  tag(0x84, unhex(c.aid));
  tag(0x9F02, unhex("000000006600"));
  tag(0xDFF001, c.ir_version);
  r.set_masked_pan("220000******0001");
  if (!c.pan_hash.empty()) r.set_pan_hash(unhex(c.pan_hash));

  if (c.via_complex) {
    ::Complex w;
    *w.mutable_poll_for_event()->mutable_perform_txn() = make_txn(c.amount, c.indication, now_);
    command(ir, 0x0C, ser(w), true);
    step(400);
    complex::poll::Event e;
    *e.mutable_contactless_txn_result() = r;
    success(ir, 0x0C, ser(e));
  } else {
    ::ContactlessLevel2 w;
    *w.mutable_perform_transaction() = make_txn(c.amount, c.indication, now_);
    command(ir, 0x04, ser(w), true);
    step(400);
    success(ir, 0x04, ser(r));
  }
  step(30);
}

void Generator::transport_card(net::Ip4 ir, const TransportCard& c) {
  // EMV first: the reader reports a non-EMV card, the controller then works with Mifare.
  ::ContactlessLevel2 w;
  *w.mutable_perform_transaction() = make_txn(6600, "PROCESSING_ONLY", now_);
  command(ir, 0x04, ser(w), true);
  step(150);
  contactless::transaction::TransactionResult r;
  r.set_status(contactless::transaction::NON_EMV_CARD);
  r.mutable_token()->set_type(contactless::token_type::MIFARE_CLASSIC_1K);
  r.mutable_token()->set_id(unhex(c.uid));
  success(ir, 0x04, ser(r));

  ::Mifare auth;
  auto* a = auth.mutable_mfr_classic_auth_on_clear_key();
  a->set_sector_number(8);
  a->set_key_type(mifare::classic::auth::TYPE_A);
  a->set_clear_key(unhex("A0A1A2A3A4A5"));
  command(ir, 0x05, ser(auth));
  success(ir, 0x05, "");

  ::Mifare rd;
  rd.mutable_mfr_classic_read_blocks()->set_start_block(32);
  rd.mutable_mfr_classic_read_blocks()->set_block_count(3);
  command(ir, 0x05, ser(rd));
  mifare::classic::read::Blocks blocks;
  blocks.set_data(std::string(48, '\x11'));
  success(ir, 0x05, ser(blocks));

  if (c.write) {
    ::Mifare wr;
    wr.mutable_mfr_classic_write_blocks()->set_start_block(33);
    wr.mutable_mfr_classic_write_blocks()->set_data(std::string(16, '\x22'));
    command(ir, 0x05, ser(wr));
    if (c.write_fails) {
      failure(ir, 0x05, common::failure::MIFARE_CARD_NOT_ACKNOWLEDGE_COMMAND);
    } else {
      success(ir, 0x05, "");
    }
  }
  step(20);
}

void Generator::token(net::Ip4 ir, const std::string& uid, const std::string& token_type) {
  ::ContactlessLevel1 w;
  w.mutable_poll_for_token()->set_timeout(1000);
  command(ir, 0x03, ser(w), true);
  step(200);
  contactless::token::Token t;
  contactless::token_type::TokenType tt;
  if (!contactless::token_type::TokenType_Parse(token_type, &tt)) tt = contactless::token_type::UNKNOWN;
  t.set_type(tt);
  t.set_id(unhex(uid));
  success(ir, 0x03, ser(t));
}

void Generator::qr(net::Ip4 ir, const std::string& data) {
  ::QrCode w;
  w.mutable_poll_for_qrcode()->set_timeout(1000);
  command(ir, 0x0D, ser(w), true);
  step(300);
  qrcode::event::QrCodeEvent e;
  e.mutable_raw_data()->set_data(data);
  success(ir, 0x0D, ser(e));
}

void Generator::troika(net::Ip4 ir, const std::string& uid) {
  token(ir, uid, "MIFARE_CLASSIC_1K");
  ::TroikaCard w;
  auto* rt = w.mutable_troika_av3_read_ticket();
  rt->mutable_date()->set_day(7);
  rt->mutable_date()->set_month(11);
  rt->mutable_date()->set_year(2026);
  rt->mutable_time()->set_hour(8);
  rt->mutable_time()->set_minute(15);
  rt->mutable_time()->set_second(0);
  command(ir, 0x12, ser(w));
  troika::av3::read_ticket::Ticket t;
  t.set_sector_number(8);
  t.set_ticket_data(std::string(32, '\x33'));
  success(ir, 0x12, ser(t));
  ::TroikaCard wt;
  auto* wr = wt.mutable_troika_av3_write_ticket();
  wr->mutable_sector()->set_sector_number(8);
  wr->mutable_sector()->set_key_type(mifare::classic::auth::TYPE_A);
  wr->mutable_sector()->mutable_av2_args()->set_slot(contact::card_slot::SAM1_SLOT);
  wr->mutable_sector()->mutable_av2_args()->set_key_number(12);
  wr->set_ticket_params(std::string(8, '\x44'));
  wr->set_validate_params(std::string(8, '\x55'));
  command(ir, 0x12, ser(wt));
  troika::av3::write_ticket::WriteResult res;
  res.set_sector_bitmap(std::string(1, '\x01'));
  res.set_write_ok(true);
  success(ir, 0x12, ser(res));
}

void Generator::indicate(net::Ip4 ir, const Indicate& ind) {
  std::uint8_t module = 0x0A;
  std::string payload;
  if (ind.via == "leds") {
    module = 0x01;
    ::Miscellaneous m;
    auto* l = m.mutable_set_leds_state();
    l->set_blue(false);
    l->set_green(ind.kind == "approve");
    l->set_red(ind.kind == "reject");
    payload = ser(m);
  } else if (ind.via == "rgb") {
    module = 0x01;
    ::Miscellaneous m;
    m.mutable_set_all_rgb_leds()->set_color(ind.color);
    payload = ser(m);
  } else if (ind.via == "turnstile") {
    module = 0x10;
    ::Turnstile t;
    t.mutable_allow_one_pass()->set_timeout_ms(5000);
    payload = ser(t);
  } else {
    ::Gui g;
    auto* root = g.mutable_show_screen()->mutable_root()->mutable_vertical_layout();
    if (ind.via == "text") {
      root->add_widgets()->mutable_text()->set_text(ind.text);
    } else if (ind.via == "customer_picture") {
      root->add_widgets()->mutable_customer_picture()->set_name(ind.name);
    } else {
      auto* pic = root->add_widgets()->mutable_picture();
      if (ind.kind == "approve") pic->set_picture_id(gui::picture_id::APPROVED);
      else if (ind.kind == "reject") pic->set_picture_id(gui::picture_id::REJECTED);
      else pic->set_picture_id(gui::picture_id::EMV_CONTACTLESS_SYMBOL);
      root->add_widgets()->mutable_text()->set_text(ind.kind == "approve" ? "66.00 RUB" : "");
    }
    payload = ser(g);
  }
  command(ir, module, payload);
  if (ind.fail) {
    failure(ir, module, common::failure::GENERAL_FAIL);
  } else {
    success(ir, module, "");
  }
  step(50);
}

void Generator::cancel(net::Ip4 ir) {
  frame(ir, true, 0, 0, 0x06, "");
  step(5);
}

void Generator::wait_ms(int ms) { step(ms); }

// ---------------------------------------------------------------------------------------------
// Scenario files
// ---------------------------------------------------------------------------------------------
namespace {

// Executes a list of steps; "loop" nests a block of steps (budget limits the total work).
bool run_steps(Generator& g, const YAML::Node& steps, const std::string& path, int depth, long long& budget,
               std::string& error) {
  if (!steps || !steps.IsSequence()) {
    error = path + ": expected a list";
    return false;
  }
  if (depth > 4) {
    error = path + ": loops nested too deep";
    return false;
  }
  for (std::size_t i = 0; i < steps.size(); ++i) {
    const YAML::Node s = steps[i];
    const std::string where = path + "[" + std::to_string(i) + "]";
    const std::string action = s["action"].as<std::string>("");
    const int repeat = s["repeat"].as<int>(1);
    net::Ip4 ir = 0;
    if (s["validator"] && !net::parse_ip(s["validator"].as<std::string>(), ir)) {
      error = where + ".validator: invalid IP";
      return false;
    }
    if (repeat < 1 || repeat > 1000000) {
      error = where + ".repeat: out of range";
      return false;
    }
    for (int r = 0; r < repeat; ++r) {
      if (--budget < 0) {
        error = where + ": scenario too large (more than 20 million steps)";
        return false;
      }
      if (action == "loop") {
        if (!run_steps(g, s["steps"], where + ".steps", depth + 1, budget, error)) return false;
        continue;
      }
      if (action == "open") {
        g.open(ir, static_cast<std::uint16_t>(s["port"].as<int>(42616)));
      } else if (action == "close") {
        g.close(ir);
      } else if (action == "reset") {
        g.reset(ir);
      } else if (action == "drop_next_packet") {
        g.drop_next_packet(ir);
      } else if (action == "device_info") {
        g.device_info(ir, s["version"].as<std::string>("1.56.8607"));
      } else if (action == "echo") {
        g.echo(ir);
      } else if (action == "idle_poll") {
        g.idle_poll(ir, s["count"].as<int>(1));
      } else if (action == "bank_card") {
        Generator::BankCard c;
        c.status = s["status"].as<std::string>(c.status);
        c.aid = s["aid"].as<std::string>(c.aid);
        c.carrier = s["carrier"].as<std::string>(c.carrier);
        c.uid = s["uid"].as<std::string>(c.uid);
        c.pan_hash = s["pan_hash"].as<std::string>(c.pan_hash);
        c.amount = s["amount"].as<std::uint64_t>(c.amount);
        c.indication = s["indication"].as<std::string>(c.indication);
        c.via_complex = s["via_complex"].as<bool>(false);
        g.bank_card(ir, c);
      } else if (action == "transport_card") {
        Generator::TransportCard c;
        c.uid = s["uid"].as<std::string>(c.uid);
        c.write = s["write"].as<bool>(true);
        c.write_fails = s["write_fails"].as<bool>(false);
        g.transport_card(ir, c);
      } else if (action == "token") {
        g.token(ir, s["uid"].as<std::string>("04A1B2C3"), s["token_type"].as<std::string>("MIFARE_CLASSIC_1K"));
      } else if (action == "qr") {
        g.qr(ir, s["data"].as<std::string>("TICKET-0001"));
      } else if (action == "troika") {
        g.troika(ir, s["uid"].as<std::string>("7A6B5C4D"));
      } else if (action == "indicate") {
        Generator::Indicate ind;
        ind.kind = s["kind"].as<std::string>(ind.kind);
        ind.via = s["via"].as<std::string>(ind.via);
        ind.text = s["text"].as<std::string>("");
        ind.name = s["name"].as<std::string>("");
        ind.color = s["color"].as<std::uint32_t>(ind.color);
        ind.fail = s["fail"].as<bool>(false);
        g.indicate(ir, ind);
      } else if (action == "cancel") {
        g.cancel(ir);
      } else if (action == "wait") {
        g.wait_ms(s["ms"].as<int>(0));
      } else {
        error = where + ".action: unknown '" + action + "'";
        return false;
      }
    }
  }
  return true;
}

}  // namespace

bool run_scenario(const std::string& yaml_text, const Generator::PacketSink& sink, std::string& error) {
  YAML::Node root;
  try {
    root = YAML::Load(yaml_text);
  } catch (const YAML::Exception& e) {
    error = std::string("YAML: ") + e.what();
    return false;
  }
  util::Micros start = 0;
  if (!util::parse_rfc3339(root["start"].as<std::string>("2026-11-07T08:00:00.000+03:00"), start)) {
    error = "start: invalid timestamp";
    return false;
  }
  net::Ip4 ctl = 0;
  if (!net::parse_ip(root["controller_ip"].as<std::string>("10.42.0.1"), ctl)) {
    error = "controller_ip: invalid";
    return false;
  }
  // Optional: drop everything before this offset (capture started in the middle of a session).
  const int capture_from_ms = root["capture_from_ms"].as<int>(0);
  const util::Micros capture_from = start + static_cast<util::Micros>(capture_from_ms) * util::kMicrosPerMilli;
  Generator g(start, ctl, [&sink, capture_from](capture::Packet&& p) {
    if (p.ts >= capture_from) sink(std::move(p));
  });
  long long budget = 20000000;
  return run_steps(g, root["steps"], "steps", 0, budget, error);
}

}  // namespace irbridge::synth
