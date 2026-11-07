// Synthetic controller <-> IntelliReader traffic (TZ section 8.2, prompt 13).
//
// A scenario (YAML) is a list of steps executed in order on a virtual clock. Each step produces the
// TCP packets a real controller and reader would exchange, with correct IR frames and checksums.
// Card numbers used here are test values that fail the Luhn check.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "irbridge/capture.hpp"
#include "irbridge/net.hpp"
#include "irbridge/util.hpp"

namespace irbridge::synth {

class Generator {
 public:
  using PacketSink = std::function<void(capture::Packet&&)>;

  Generator(util::Micros start, net::Ip4 controller_ip, PacketSink sink);

  // Session control.
  void open(net::Ip4 ir, std::uint16_t port = 42616);
  void close(net::Ip4 ir);  // FIN both ways
  void reset(net::Ip4 ir);  // RST from the reader
  void drop_next_packet(net::Ip4 ir);  // simulates loss on the mirror port

  // Protocol helpers (all advance the clock).
  void device_info(net::Ip4 ir, const std::string& version);
  void idle_poll(net::Ip4 ir, int count);  // PerformTransaction -> Pending -> TIMEOUT_EXPIRED
  void echo(net::Ip4 ir);

  struct BankCard {
    std::string status = "ONLINE_AUTHORIZATION_REQUIRED";
    std::string aid = "A0000006581010";  // MIR
    std::string carrier = "PLASTIC_CARD";
    std::string uid = "0E264417";
    std::string pan_hash;      // hex, optional
    std::uint64_t amount = 6600;
    std::string indication = "PROCESSING_ONLY";
    std::string ir_version = "1.56.8607";
    bool via_complex = false;  // Complex.poll_for_event { perform_txn } instead of ContactlessL2
  };
  void bank_card(net::Ip4 ir, const BankCard& c);

  struct TransportCard {
    std::string uid = "67D15785";
    bool write = true;
    bool write_fails = false;
  };
  void transport_card(net::Ip4 ir, const TransportCard& c);

  void token(net::Ip4 ir, const std::string& uid, const std::string& token_type = "MIFARE_CLASSIC_1K");
  void qr(net::Ip4 ir, const std::string& data);
  void troika(net::Ip4 ir, const std::string& uid);

  struct Indicate {
    std::string kind = "approve";  // approve | reject | neutral
    std::string via = "picture";   // picture | leds | text | customer_picture | rgb | turnstile
    std::string text;              // for via=text
    std::string name;              // for via=customer_picture
    std::uint32_t color = 0x00FF00;
    bool fail = false;             // reader answers with a Failure response
  };
  void indicate(net::Ip4 ir, const Indicate& ind);
  void cancel(net::Ip4 ir);

  void wait_ms(int ms);
  util::Micros now() const { return now_; }

  // Raw frame helpers (tests).
  void command(net::Ip4 ir, std::uint8_t module, const std::string& payload, bool pending = false);
  void success(net::Ip4 ir, std::uint8_t module, const std::string& payload);
  void failure(net::Ip4 ir, std::uint8_t module, int error);

 private:
  struct Conn {
    std::uint16_t port = 42616;
    std::uint16_t ctl_port = 0;
    std::uint32_t seq_ctl = 0;  // controller -> reader
    std::uint32_t seq_ir = 0;   // reader -> controller
    std::uint8_t msgid = 0;
    bool drop_next = false;
  };
  Conn& conn(net::Ip4 ir);
  void send(net::Ip4 ir, bool from_controller, const std::vector<std::uint8_t>& data, std::uint8_t flags);
  void frame(net::Ip4 ir, bool from_controller, std::uint8_t msgid, std::uint8_t module, std::uint8_t type,
             const std::string& payload);
  void step(int ms) { now_ += static_cast<util::Micros>(ms) * util::kMicrosPerMilli; }

  util::Micros now_;
  net::Ip4 ctl_;
  PacketSink sink_;
  std::map<net::Ip4, Conn> conns_;
  std::uint16_t next_port_ = 50000;
};

// Runs a scenario file. Returns false and sets `error` on a malformed scenario.
bool run_scenario(const std::string& yaml_text, const Generator::PacketSink& sink, std::string& error);

}  // namespace irbridge::synth
