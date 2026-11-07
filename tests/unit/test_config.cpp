#include <gtest/gtest.h>

#include <fstream>
#include <iterator>

#include "irbridge/config.hpp"

using namespace irbridge;

namespace {
bool parse(const std::string& y, config::Config& c, std::string& err) { return config::parse_config(y, c, err); }
}  // namespace

TEST(Config, PackagedExampleIsValid) {
  config::Config c;
  std::string err;
  ASSERT_TRUE(config::load_config(IRBRIDGE_TEST_DATA_DIR "/../../packaging/irbridge.yaml", c, err)) << err;
  EXPECT_EQ(c.vehicle_id, "BUS-0001");
  EXPECT_EQ(c.capture.mode, "mirror");
  ASSERT_EQ(c.validators.size(), 2u);
  EXPECT_EQ(c.validators[1].validator_id, "V2");
  EXPECT_EQ(c.detector.policy, detect::SuccessPolicy::Indication);
  EXPECT_FALSE(c.detector.require_ack);
  EXPECT_EQ(c.detector.rules.approve.size(), 3u);
  EXPECT_EQ(c.mqtt.client_id, "irbridge-BUS-0001");
  EXPECT_FALSE(c.privacy.raw_capture.enabled);
}

TEST(Config, ScenarioConfigIsValid) {
  config::Config c;
  std::string err;
  ASSERT_TRUE(config::load_config(IRBRIDGE_TEST_DATA_DIR "/scenario-config.yaml", c, err)) << err;
}

TEST(Config, Defaults) {
  config::Config c;
  std::string err;
  ASSERT_TRUE(parse("vehicle_id: B1\n", c, err)) << err;
  EXPECT_EQ(c.capture.ir_ports, std::vector<std::uint16_t>{42616});
  EXPECT_EQ(c.capture.tls_ports, std::vector<std::uint16_t>{42800});
  EXPECT_EQ(c.detector.decision_window, 3 * util::kMicrosPerSecond);
  EXPECT_EQ(c.aggregation.match_scope, "vehicle");
  EXPECT_EQ(c.aggregation.post_close_tail_s, 120);
  EXPECT_EQ(c.storage.events_retention_days, 30);
  EXPECT_EQ(c.http.listen, std::vector<std::string>{"127.0.0.1:8095"});
  EXPECT_EQ(c.mqtt.topic_prefix, "camai");
  EXPECT_FALSE(c.detector.rules.approve.empty());  // built-in defaults
}

TEST(Config, ErrorsNameThePath) {
  struct Case {
    const char* yaml;
    const char* path;
  };
  const Case cases[] = {
      {"capture: {mode: mirror}\n", "vehicle_id"},
      {"vehicle_id: \"a/b\"\n", "vehicle_id"},
      {"vehicle_id: B\ncapture: {mode: sniff}\n", "capture.mode"},
      {"vehicle_id: B\ncapture: {mode: pcap-file}\n", "capture.pcap_file"},
      {"vehicle_id: B\ncapture: {mode: proxy}\n", "capture.proxy"},
      {"vehicle_id: B\ncapture: {ir_ports: [70000]}\n", "capture.ir_ports[0]"},
      {"vehicle_id: B\nvalidators: [{ip: 10.0.0.300, validator_id: V1}]\n", "validators[0].ip"},
      {"vehicle_id: B\nvalidators: [{ip: 10.0.0.1, validator_id: V1}, {ip: 10.0.0.1, validator_id: V2}]\n",
       "validators[1].ip"},
      {"vehicle_id: B\nvalidators: [{ip: 10.0.0.1, validator_id: V1}, {ip: 10.0.0.2, validator_id: V1}]\n",
       "validators[1].validator_id"},
      {"vehicle_id: B\ndetector: {success_policy: magic}\n", "detector.success_policy"},
      {"vehicle_id: B\ndetector: {decision_window_ms: 10}\n", "detector.decision_window_ms"},
      {"vehicle_id: B\ndetector: {approve: [{type: gui_picture, ids: [NOPE]}]}\n", "detector.approve[0].ids[0]"},
      {"vehicle_id: B\ndetector: {approve: [{type: gui_text, regex: \"(\"}]}\n", "detector.approve[0].regex"},
      {"vehicle_id: B\ndetector: {reject: [{type: leds}]}\n", "detector.reject[0]"},
      {"vehicle_id: B\ndetector: {approve: [{type: rgb_color, color: 0x1000000}]}\n", "detector.approve[0]"},
      {"vehicle_id: B\ndetector: {approve: [{type: blink}]}\n", "detector.approve[0].type"},
      {"vehicle_id: B\naggregation: {match_scope: seat}\n", "aggregation.match_scope"},
      {"vehicle_id: B\nstorage: {max_db_mb: 1}\n", "storage"},
      {"vehicle_id: B\nmqtt: {url: \"http://x\"}\n", "mqtt.url"},
      {"vehicle_id: B\nhttp: {listen: [\"nope\"]}\n", "http.listen[0]"},
      {"vehicle_id: B\nlog: {level: loud}\n", "log.level"},
      {"vehicle_id: B\nprivacy: {raw_capture: {max_mb: 0}}\n", "privacy.raw_capture"},
      {"- just\n- a list\n", "<root>"},
      {"vehicle_id: [unclosed\n", ""},
  };
  for (const auto& c : cases) {
    config::Config cfg;
    std::string err;
    EXPECT_FALSE(parse(c.yaml, cfg, err)) << c.yaml;
    EXPECT_NE(err.find(c.path), std::string::npos) << "yaml: " << c.yaml << "\nerror: " << err;
  }
}

TEST(Config, HostPort) {
  std::string h;
  std::uint16_t p = 0;
  EXPECT_TRUE(config::parse_host_port("127.0.0.1:8095", h, p));
  EXPECT_EQ(h, "127.0.0.1");
  EXPECT_EQ(p, 8095);
  EXPECT_FALSE(config::parse_host_port("127.0.0.1", h, p));
  EXPECT_FALSE(config::parse_host_port("x:99999", h, p));
}

// The example from section 7 of the TZ (docs/TZ_IR-Bridge.md) must load as is.
TEST(Config, TzSection7Example) {
  std::ifstream f(IRBRIDGE_TEST_DATA_DIR "/../../docs/TZ_IR-Bridge.md");
  ASSERT_TRUE(f.good());
  const std::string doc((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  const auto sec = doc.find("## 7.");
  ASSERT_NE(sec, std::string::npos);
  const auto begin = doc.find("```yaml\n", sec);
  ASSERT_NE(begin, std::string::npos);
  const auto end = doc.find("```", begin + 8);
  const std::string yaml = doc.substr(begin + 8, end - begin - 8);
  config::Config c;
  std::string err;
  ASSERT_TRUE(config::parse_config(yaml, c, err)) << err;
  EXPECT_EQ(c.vehicle_id, "bus-1042");
  EXPECT_EQ(c.validators.size(), 2u);
  EXPECT_EQ(c.mqtt.client_id, "irbridge-bus-1042");
  EXPECT_TRUE(c.capture.proxy.empty());
  EXPECT_EQ(c.detector.rules.approve.size(), 3u);
}
