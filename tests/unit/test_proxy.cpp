// Proxy mode (prompt 11): transparent relay, copy to the parser, independence from a slow parser.
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <thread>

#include "irbridge/codec.hpp"
#include "irbridge/proxy.hpp"

using namespace irbridge;

namespace {

// Fake IntelliReader: accepts connections and echoes everything back (optionally closes after N bytes).
class EchoServer {
 public:
  explicit EchoServer(std::size_t close_after = 0) : close_after_(close_after) {
    fd_ = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    listen(fd_, 4);
    socklen_t l = sizeof(a);
    getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &l);
    port_ = ntohs(a.sin_port);
    th_ = std::thread([this] { run(); });
  }
  ~EchoServer() {
    stop_ = true;
    shutdown(fd_, SHUT_RDWR);
    close(fd_);
    th_.join();
  }
  std::uint16_t port() const { return port_; }

 private:
  void run() {
    while (!stop_) {
      pollfd p{fd_, POLLIN, 0};
      if (poll(&p, 1, 100) <= 0) continue;
      const int c = accept(fd_, nullptr, nullptr);
      if (c < 0) continue;
      int one = 1;
      setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      char buf[65536];
      std::size_t total = 0;
      for (;;) {
        const ssize_t n = recv(c, buf, sizeof(buf), 0);
        if (n <= 0) break;
        send(c, buf, static_cast<std::size_t>(n), MSG_NOSIGNAL);
        total += static_cast<std::size_t>(n);
        if (close_after_ != 0 && total >= close_after_) break;
      }
      close(c);
    }
  }
  int fd_ = -1;
  std::uint16_t port_ = 0;
  std::size_t close_after_;
  std::atomic<bool> stop_{false};
  std::thread th_;
};

int connect_to(std::uint16_t port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(port);
  if (connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
    close(fd);
    return -1;
  }
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  timeval tv{5, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  return fd;
}

bool read_exact(int fd, std::size_t n, std::string& out) {
  out.clear();
  char buf[65536];
  while (out.size() < n) {
    const ssize_t r = recv(fd, buf, std::min(sizeof(buf), n - out.size()), 0);
    if (r <= 0) return false;
    out.append(buf, static_cast<std::size_t>(r));
  }
  return true;
}

std::unique_ptr<proxy::Proxy> start_proxy(std::uint16_t upstream, std::size_t queue = 8192) {
  proxy::Proxy::Options o;
  o.routes.push_back({"127.0.0.1:0", "127.0.0.1:" + std::to_string(upstream)});
  o.queue_capacity = queue;
  auto p = std::make_unique<proxy::Proxy>(o);
  std::string err;
  EXPECT_TRUE(p->start(err)) << err;
  return p;
}

std::string ir_frame(std::uint8_t msgid) {
  codec::Frame f;
  f.msgid = msgid;
  f.module = 0x01;
  f.type = 0x01;
  f.payload = {0x0A, 0x02, 0x08, 0x01};
  const auto b = codec::encode(f);
  return std::string(b.begin(), b.end());
}

}  // namespace

TEST(Proxy, RelaysBothWaysAndCopiesToParser) {
  EchoServer ir;
  auto px = start_proxy(ir.port());
  const int c = connect_to(px->bound_ports().at(0));
  ASSERT_GE(c, 0);
  const std::string msg = ir_frame(1) + ir_frame(2);
  ASSERT_EQ(send(c, msg.data(), msg.size(), 0), static_cast<ssize_t>(msg.size()));
  std::string echo;
  ASSERT_TRUE(read_exact(c, msg.size(), echo));
  EXPECT_EQ(echo, msg);  // unchanged
  close(c);

  std::string to_reader, to_ctl;
  bool opened = false, closed = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (!closed && std::chrono::steady_clock::now() < deadline) {
    proxy::StreamEvent ev;
    if (!px->pop(ev)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
      continue;
    }
    if (ev.kind == proxy::StreamEvent::Kind::Open) {
      opened = true;
      EXPECT_EQ(ev.key.ir_port, ir.port());
      EXPECT_FALSE(ev.encrypted);
    }
    if (ev.kind == proxy::StreamEvent::Kind::Data) {
      (ev.dir == tcp::Dir::ToReader ? to_reader : to_ctl).append(ev.bytes.begin(), ev.bytes.end());
    }
    if (ev.kind == proxy::StreamEvent::Kind::Close) closed = true;
  }
  EXPECT_TRUE(opened);
  EXPECT_TRUE(closed);
  EXPECT_EQ(to_reader, msg);
  EXPECT_EQ(to_ctl, msg);
}

TEST(Proxy, RelayLatency) {
  EchoServer ir;
  auto px = start_proxy(ir.port());
  const int c = connect_to(px->bound_ports().at(0));
  ASSERT_GE(c, 0);
  std::vector<double> us;
  std::string echo;
  for (int i = 0; i < 1000; ++i) {
    const std::string f = ir_frame(static_cast<std::uint8_t>(i));
    const auto t0 = std::chrono::steady_clock::now();
    send(c, f.data(), f.size(), 0);
    ASSERT_TRUE(read_exact(c, f.size(), echo));
    us.push_back(std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count());
    proxy::StreamEvent ev;
    while (px->pop(ev)) {
    }
  }
  close(c);
  std::sort(us.begin(), us.end());
  const double p99 = us[us.size() * 99 / 100];
  // A round trip crosses the proxy twice; the budget per crossing is 2 ms (p99).
  std::cout << "proxy round trip p50 " << us[us.size() / 2] << " us, p99 " << p99 << " us\n";
  EXPECT_LT(p99, 4000.0);
}

TEST(Proxy, SlowParserDoesNotSlowRelay) {
  EchoServer ir;
  auto px = start_proxy(ir.port(), /*queue=*/4);
  const int c = connect_to(px->bound_ports().at(0));
  ASSERT_GE(c, 0);
  std::string all;
  std::string echo;
  for (int i = 0; i < 200; ++i) {  // nobody pops the parser queue meanwhile
    const std::string f = ir_frame(static_cast<std::uint8_t>(i));
    all += f;
    send(c, f.data(), f.size(), 0);
    ASSERT_TRUE(read_exact(c, f.size(), echo));
    EXPECT_EQ(echo, f);
  }
  EXPECT_GT(px->stats().parse_dropped.load(), 0u);
  // Drain, then send more: the parser must be told about the hole before new data.
  proxy::StreamEvent ev;
  while (px->pop(ev)) {
  }
  const std::string f = ir_frame(9);
  send(c, f.data(), f.size(), 0);
  ASSERT_TRUE(read_exact(c, f.size(), echo));
  bool gap = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (!gap && std::chrono::steady_clock::now() < deadline) {
    if (px->pop(ev)) gap = ev.kind == proxy::StreamEvent::Kind::Gap;
    else std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  EXPECT_TRUE(gap);
  close(c);
}

TEST(Proxy, ReaderCloseClosesController) {
  EchoServer ir(/*close_after=*/9);
  auto px = start_proxy(ir.port());
  const int c = connect_to(px->bound_ports().at(0));
  ASSERT_GE(c, 0);
  const std::string f = ir_frame(1);
  send(c, f.data(), f.size(), 0);
  std::string echo;
  ASSERT_TRUE(read_exact(c, f.size(), echo));
  char b;
  EXPECT_EQ(recv(c, &b, 1, 0), 0);  // orderly close propagated
  close(c);
}

TEST(Proxy, UpstreamDownClosesController) {
  std::uint16_t dead_port = 0;
  {
    EchoServer tmp;
    dead_port = tmp.port();
  }  // nothing listens there now
  auto px = start_proxy(dead_port);
  const int c = connect_to(px->bound_ports().at(0));
  ASSERT_GE(c, 0);
  char b;
  EXPECT_LE(recv(c, &b, 1, 0), 0);
  close(c);
  EXPECT_GE(px->stats().upstream_failures.load(), 1u);
}

TEST(Spsc, OrderAndCapacity) {
  proxy::SpscQueue<int> q(3);
  EXPECT_TRUE(q.push(1));
  EXPECT_TRUE(q.push(2));
  EXPECT_TRUE(q.push(3));
  EXPECT_FALSE(q.push(4));
  int v = 0;
  ASSERT_TRUE(q.pop(v));
  EXPECT_EQ(v, 1);
  EXPECT_TRUE(q.push(4));
  for (int want : {2, 3, 4}) {
    ASSERT_TRUE(q.pop(v));
    EXPECT_EQ(v, want);
  }
  EXPECT_FALSE(q.pop(v));
}
