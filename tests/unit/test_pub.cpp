// Publication: at-least-once delivery to MQTT and the local HTTP API (prompt 9).
#include <gtest/gtest.h>
#include <httplib.h>
#include <unistd.h>

#include <filesystem>

#include <nlohmann/json.hpp>

#include "helpers.hpp"
#include "irbridge/pub.hpp"

using namespace irbridge;
namespace fs = std::filesystem;

namespace {

class FakeMqtt : public pub::IMqttClient {
 public:
  struct Msg {
    std::string topic, payload;
    int qos;
    bool retain;
    int mid;
  };
  bool up = true;
  int next_mid = 1;
  std::vector<Msg> sent;
  bool connected() const override { return up; }
  int publish(const std::string& t, const std::string& p, int qos, bool retain) override {
    if (!up) return -1;
    sent.push_back({t, p, qos, retain, next_mid});
    return next_mid++;
  }
  bool subscribe(const std::string&, int) override { return true; }
  void ack(int mid) {
    if (on_published) on_published(mid);
  }
};

struct TempStore {
  fs::path dir;
  store::Store db;
  TempStore() {
    static int n = 0;
    dir = fs::temp_directory_path() / ("irbridge-pub-" + std::to_string(::getpid()) + "-" + std::to_string(++n));
    fs::create_directories(dir);
    std::string err;
    EXPECT_TRUE(db.open((dir / "e.db").string(), err)) << err;
  }
  ~TempStore() {
    db.close();
    fs::remove_all(dir);
  }
};

constexpr util::Micros S = util::kMicrosPerSecond;

}  // namespace

TEST(Publisher, TopicsAndAtLeastOnce) {
  const auto cfg = irbridge::testing::make_config();
  TempStore ts;
  health::Metrics m;
  FakeMqtt mq;
  pub::Publisher p(cfg, ts.db, mq, m);
  ts.db.enqueue({store::Kind::Validation, "e1", 1, "{\"v\":1}"});
  ts.db.enqueue({store::Kind::Interval, "i1", 2, "{\"i\":1}"});
  ts.db.flush();

  p.pump(10 * S);
  ASSERT_EQ(mq.sent.size(), 2u);
  EXPECT_EQ(mq.sent[0].topic, "camai/T1/fare/validation");
  EXPECT_EQ(mq.sent[0].qos, 1);
  EXPECT_FALSE(mq.sent[0].retain);
  EXPECT_EQ(mq.sent[1].topic, "camai/T1/fare/interval");
  p.pump(11 * S);  // waiting for PUBACK: nothing is sent twice
  EXPECT_EQ(mq.sent.size(), 2u);

  mq.ack(mq.sent[0].mid);
  EXPECT_EQ(ts.db.unpublished_count(), 1u);
  EXPECT_EQ(m.mqtt_published.load(), 1u);

  p.pump(50 * S);  // no PUBACK for the interval within 30 s: sent again with the same content
  ASSERT_EQ(mq.sent.size(), 3u);
  EXPECT_EQ(mq.sent[2].payload, "{\"i\":1}");
  p.pump(51 * S);
  EXPECT_EQ(mq.sent.size(), 3u);
  mq.ack(mq.sent[1].mid);  // a late PUBACK of the first attempt is harmless
  mq.ack(mq.sent[2].mid);
  EXPECT_EQ(ts.db.unpublished_count(), 0u);
}

TEST(Publisher, OfflineBufferingAndReconnect) {
  const auto cfg = irbridge::testing::make_config();
  TempStore ts;
  health::Metrics m;
  FakeMqtt mq;
  mq.up = false;
  pub::Publisher p(cfg, ts.db, mq, m);
  for (int i = 0; i < 5; ++i) ts.db.enqueue({store::Kind::Validation, "e" + std::to_string(i), i, "{}"});
  ts.db.flush();
  p.pump(1 * S);
  EXPECT_TRUE(mq.sent.empty());
  EXPECT_EQ(m.mqtt_queue.load(), 5u);
  mq.up = true;
  p.pump(2 * S);
  EXPECT_EQ(mq.sent.size(), 5u);
  // Connection lost before PUBACKs: everything is sent again after the reconnect.
  mq.up = false;
  p.pump(3 * S);
  mq.up = true;
  p.pump(4 * S);
  EXPECT_EQ(mq.sent.size(), 10u);
  for (std::size_t i = 5; i < 10; ++i) mq.ack(mq.sent[i].mid);
  EXPECT_EQ(ts.db.unpublished_count(), 0u);
}

TEST(Publisher, RetainedValidatorStatus) {
  const auto cfg = irbridge::testing::make_config();
  TempStore ts;
  health::Metrics m;
  FakeMqtt mq;
  pub::Publisher p(cfg, ts.db, mq, m);
  p.publish_status("V1", "{\"status\":\"observed\"}");
  ASSERT_EQ(mq.sent.size(), 1u);
  EXPECT_EQ(mq.sent[0].topic, "camai/T1/fare/validator/V1");
  EXPECT_TRUE(mq.sent[0].retain);
}

TEST(HttpApi, Endpoints) {
  const auto cfg = irbridge::testing::make_config();
  TempStore ts;
  health::Metrics m;
  m.frames = 42;
  health::ValidatorRegistry reg(cfg, nullptr);
  reg.evaluate(1 * S);
  for (int i = 0; i < 3; ++i) {
    ts.db.enqueue({store::Kind::Validation, "e" + std::to_string(i), (i + 1) * 1000 * S,
                   "{\"event_id\":\"e" + std::to_string(i) + "\"}"});
  }
  ts.db.enqueue({store::Kind::Interval, "i0", 1000 * S, "{\"interval_id\":\"i0\"}"});
  ts.db.flush();

  pub::HttpApi::Sources src;
  src.store = &ts.db;
  src.registry = &reg;
  src.metrics = &m;
  src.health_json = [] { return std::string("{\"status\":\"ok\"}"); };
  pub::HttpApi api(src);
  const int port = 18000 + static_cast<int>(::getpid() % 2000);
  std::string err;
  ASSERT_TRUE(api.start({"127.0.0.1:" + std::to_string(port)}, err)) << err;

  httplib::Client c("127.0.0.1", port);
  c.set_connection_timeout(2);
  auto r = c.Get("/api/v1/health");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->status, 200);
  EXPECT_EQ(nlohmann::json::parse(r->body)["status"], "ok");

  r = c.Get("/api/v1/validators");
  ASSERT_TRUE(r);
  const auto vs = nlohmann::json::parse(r->body);
  ASSERT_EQ(vs.size(), 2u);
  EXPECT_EQ(vs[0]["status"], "silent");

  r = c.Get("/api/v1/events?since=2000000&limit=1");  // epoch ms
  ASSERT_TRUE(r);
  auto ev = nlohmann::json::parse(r->body);
  ASSERT_EQ(ev.size(), 1u);
  EXPECT_EQ(ev[0]["event_id"], "e1");
  r = c.Get("/api/v1/events?limit=5000");  // limit is capped, not an error
  ASSERT_TRUE(r);
  EXPECT_EQ(nlohmann::json::parse(r->body).size(), 3u);
  r = c.Get("/api/v1/events?since=yesterday");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->status, 400);

  r = c.Get("/api/v1/intervals");
  ASSERT_TRUE(r);
  EXPECT_EQ(nlohmann::json::parse(r->body).size(), 1u);

  r = c.Get("/metrics");
  ASSERT_TRUE(r);
  EXPECT_NE(r->body.find("irbridge_frames_total 42"), std::string::npos);
  api.stop();
}
