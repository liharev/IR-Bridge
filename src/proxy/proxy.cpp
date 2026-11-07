#include "irbridge/proxy.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <spdlog/spdlog.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <map>

namespace irbridge::proxy {

namespace {

constexpr std::size_t kReadChunk = 16 * 1024;
constexpr std::size_t kMaxPending = 256 * 1024;  // per direction; reading pauses above this

// host:port; port 0 is accepted (ephemeral listen port, used by tests).
bool resolve(const std::string& hp, sockaddr_in& out) {
  const auto colon = hp.rfind(':');
  if (colon == std::string::npos || colon + 1 >= hp.size()) return false;
  std::string host = hp.substr(0, colon);
  const std::string ps = hp.substr(colon + 1);
  if (ps.find_first_not_of("0123456789") != std::string::npos || ps.size() > 5) return false;
  const int pnum = std::stoi(ps);
  if (pnum > 65535) return false;
  const auto port = static_cast<std::uint16_t>(pnum);
  std::memset(&out, 0, sizeof(out));
  out.sin_family = AF_INET;
  out.sin_port = htons(port);
  if (host.empty() || host == "*") host = "0.0.0.0";
  return inet_pton(AF_INET, host.c_str(), &out.sin_addr) == 1;
}

void set_nodelay(int fd) {
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

}  // namespace

struct Proxy::Impl {
  int ep = -1;
  int wake = -1;
  struct Listener {
    int fd = -1;
    sockaddr_in upstream{};
    std::uint16_t port = 0;
  };
  std::vector<Listener> listeners;

  struct Conn {
    int fd[2] = {-1, -1};  // 0 = controller side, 1 = reader side
    std::string out[2];    // pending bytes to write TO fd[i]
    bool connecting = true;
    bool gap_pending[2] = {false, false};
    bool open_delivered = false;
    tcp::FlowKey key;
    bool encrypted = false;
  };
  std::map<int, std::pair<std::shared_ptr<Conn>, int>> by_fd;  // fd -> (conn, side)
};

Proxy::Proxy(Options opt) : opt_(std::move(opt)), queue_(opt_.queue_capacity), impl_(std::make_unique<Impl>()) {}

Proxy::~Proxy() { stop(); }

std::vector<std::uint16_t> Proxy::bound_ports() const {
  std::vector<std::uint16_t> r;
  for (const auto& l : impl_->listeners) r.push_back(l.port);
  return r;
}

bool Proxy::start(std::string& error) {
  auto& im = *impl_;
  im.ep = epoll_create1(EPOLL_CLOEXEC);
  im.wake = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (im.ep < 0 || im.wake < 0) {
    error = std::string("epoll: ") + std::strerror(errno);
    return false;
  }
  epoll_event ev{};
  ev.events = EPOLLIN;
  ev.data.fd = im.wake;
  epoll_ctl(im.ep, EPOLL_CTL_ADD, im.wake, &ev);
  for (const auto& r : opt_.routes) {
    Impl::Listener l;
    sockaddr_in la{};
    if (!resolve(r.listen, la)) {
      error = "capture.proxy: bad listen address '" + r.listen + "'";
      return false;
    }
    if (!resolve(r.upstream, l.upstream) || l.upstream.sin_port == 0) {
      error = "capture.proxy: bad upstream address '" + r.upstream + "'";
      return false;
    }
    l.fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int one = 1;
    setsockopt(l.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(l.fd, reinterpret_cast<sockaddr*>(&la), sizeof(la)) != 0 || listen(l.fd, 16) != 0) {
      error = "capture.proxy: cannot listen on " + r.listen + ": " + std::strerror(errno);
      close(l.fd);
      return false;
    }
    socklen_t len = sizeof(la);
    getsockname(l.fd, reinterpret_cast<sockaddr*>(&la), &len);
    l.port = ntohs(la.sin_port);
    ev.events = EPOLLIN;
    ev.data.fd = l.fd;
    epoll_ctl(im.ep, EPOLL_CTL_ADD, l.fd, &ev);
    im.listeners.push_back(l);
    spdlog::info("proxy {} -> {}", r.listen, r.upstream);
  }
  running_ = true;
  thread_ = std::thread([this] { run(); });
  return true;
}

void Proxy::stop() {
  if (!running_.exchange(false)) return;
  std::uint64_t one = 1;
  if (write(impl_->wake, &one, sizeof(one)) < 0) {
    // the thread also polls with a timeout
  }
  if (thread_.joinable()) thread_.join();
  for (auto& [fd, cs] : impl_->by_fd) close(fd);
  impl_->by_fd.clear();
  for (auto& l : impl_->listeners) close(l.fd);
  impl_->listeners.clear();
  close(impl_->ep);
  close(impl_->wake);
}

void Proxy::run() {
  auto& im = *impl_;
  using Conn = Impl::Conn;

  auto deliver = [this](StreamEvent&& ev, Conn* c) {
    // When the parser queue is full the relay continues and the parser sees a gap later.
    if (ev.kind == StreamEvent::Kind::Data) {
      const int side = ev.dir == tcp::Dir::ToReader ? 0 : 1;
      if (c->gap_pending[side]) {
        StreamEvent g;
        g.kind = StreamEvent::Kind::Gap;
        g.key = ev.key;
        g.dir = ev.dir;
        g.ts = ev.ts;
        if (!queue_.push(std::move(g))) {
          stats_.parse_dropped.fetch_add(1, std::memory_order_relaxed);
          return;
        }
        c->gap_pending[side] = false;
      }
      if (!queue_.push(std::move(ev))) {
        c->gap_pending[side] = true;
        stats_.parse_dropped.fetch_add(1, std::memory_order_relaxed);
      }
      return;
    }
    if (!queue_.push(std::move(ev))) stats_.parse_dropped.fetch_add(1, std::memory_order_relaxed);
  };

  auto update_interest = [&](Conn& c) {
    for (int side = 0; side < 2; ++side) {
      if (c.fd[side] < 0) continue;
      epoll_event ev{};
      ev.data.fd = c.fd[side];
      const int other = 1 - side;
      // Read from this side only if the opposite pending buffer has room.
      if (!(side == 1 && c.connecting) && c.out[other].size() < kMaxPending) ev.events |= EPOLLIN;
      if (!c.out[side].empty() || (side == 1 && c.connecting)) ev.events |= EPOLLOUT;
      ev.events |= EPOLLRDHUP;
      epoll_ctl(im.ep, EPOLL_CTL_MOD, c.fd[side], &ev);
    }
  };

  auto close_conn = [&](const std::shared_ptr<Conn>& c) {
    for (int side = 0; side < 2; ++side) {
      if (c->fd[side] >= 0) {
        epoll_ctl(im.ep, EPOLL_CTL_DEL, c->fd[side], nullptr);
        close(c->fd[side]);
        im.by_fd.erase(c->fd[side]);
        c->fd[side] = -1;
      }
    }
    if (c->open_delivered) {
      StreamEvent e;
      e.kind = StreamEvent::Kind::Close;
      e.key = c->key;
      e.ts = util::now_micros();
      deliver(std::move(e), c.get());
    }
  };

  auto flush_out = [&](Conn& c, int side) -> bool {
    while (!c.out[side].empty()) {
      const ssize_t n = send(c.fd[side], c.out[side].data(), c.out[side].size(), MSG_NOSIGNAL);
      if (n > 0) {
        c.out[side].erase(0, static_cast<std::size_t>(n));
        continue;
      }
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
      return false;
    }
    return true;
  };

  std::vector<epoll_event> events(64);
  std::vector<std::uint8_t> buf(kReadChunk);
  while (running_) {
    const int n = epoll_wait(im.ep, events.data(), static_cast<int>(events.size()), 200);
    if (n < 0) {
      if (errno == EINTR) continue;
      spdlog::error("proxy epoll_wait: {}", std::strerror(errno));
      break;
    }
    for (int i = 0; i < n; ++i) {
      const int fd = events[static_cast<std::size_t>(i)].data.fd;
      const std::uint32_t evs = events[static_cast<std::size_t>(i)].events;
      if (fd == im.wake) continue;
      auto lit = std::find_if(im.listeners.begin(), im.listeners.end(),
                              [fd](const Impl::Listener& l) { return l.fd == fd; });
      if (lit != im.listeners.end()) {
        for (;;) {
          sockaddr_in peer{};
          socklen_t plen = sizeof(peer);
          const int cfd = accept4(fd, reinterpret_cast<sockaddr*>(&peer), &plen, SOCK_NONBLOCK | SOCK_CLOEXEC);
          if (cfd < 0) break;
          stats_.accepted.fetch_add(1, std::memory_order_relaxed);
          const int ufd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
          const int rc = ufd < 0 ? -1
                                 : connect(ufd, reinterpret_cast<const sockaddr*>(&lit->upstream),
                                           sizeof(lit->upstream));
          if (ufd < 0 || (rc != 0 && errno != EINPROGRESS)) {
            stats_.upstream_failures.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("proxy: upstream connect failed: {}", std::strerror(errno));
            if (ufd >= 0) close(ufd);
            close(cfd);
            continue;
          }
          set_nodelay(cfd);
          set_nodelay(ufd);
          auto c = std::make_shared<Conn>();
          c->fd[0] = cfd;
          c->fd[1] = ufd;
          c->key.ctl_ip = ntohl(peer.sin_addr.s_addr);
          c->key.ctl_port = ntohs(peer.sin_port);
          c->key.ir_ip = ntohl(lit->upstream.sin_addr.s_addr);
          c->key.ir_port = ntohs(lit->upstream.sin_port);
          c->encrypted = std::find(opt_.tls_ports.begin(), opt_.tls_ports.end(), c->key.ir_port) !=
                         opt_.tls_ports.end();
          im.by_fd[cfd] = {c, 0};
          im.by_fd[ufd] = {c, 1};
          epoll_event ev{};
          ev.data.fd = cfd;
          epoll_ctl(im.ep, EPOLL_CTL_ADD, cfd, &ev);
          ev.data.fd = ufd;
          epoll_ctl(im.ep, EPOLL_CTL_ADD, ufd, &ev);
          update_interest(*c);
        }
        continue;
      }
      auto it = im.by_fd.find(fd);
      if (it == im.by_fd.end()) continue;
      std::shared_ptr<Conn> c = it->second.first;
      const int side = it->second.second;
      const int other = 1 - side;
      bool dead = false;

      if (side == 1 && c->connecting && (evs & (EPOLLOUT | EPOLLERR | EPOLLHUP))) {
        int err = 0;
        socklen_t el = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
        if (err != 0) {
          stats_.upstream_failures.fetch_add(1, std::memory_order_relaxed);
          spdlog::warn("proxy: upstream connect failed: {}", std::strerror(err));
          close_conn(c);
          continue;
        }
        c->connecting = false;
        c->open_delivered = true;
        StreamEvent e;
        e.kind = StreamEvent::Kind::Open;
        e.key = c->key;
        e.encrypted = c->encrypted;
        e.ts = util::now_micros();
        deliver(std::move(e), c.get());
        if (!c->out[1].empty()) {
          // Bytes the controller sent while the upstream connection was being established.
          StreamEvent d;
          d.kind = StreamEvent::Kind::Data;
          d.key = c->key;
          d.dir = tcp::Dir::ToReader;
          d.ts = util::now_micros();
          d.bytes.assign(c->out[1].begin(), c->out[1].end());
          deliver(std::move(d), c.get());
        }
      }
      if (!c->connecting && (evs & EPOLLOUT)) {
        if (!flush_out(*c, side)) dead = true;
      }
      if (!dead && (evs & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR))) {
        for (;;) {
          if (c->out[other].size() >= kMaxPending) break;
          const ssize_t r = recv(fd, buf.data(), buf.size(), 0);
          if (r > 0) {
            const auto nb = static_cast<std::size_t>(r);
            const util::Micros ts = util::now_micros();
            c->out[other].append(reinterpret_cast<const char*>(buf.data()), nb);
            if (other == 1) {
              stats_.bytes_to_reader.fetch_add(nb, std::memory_order_relaxed);
            } else {
              stats_.bytes_to_controller.fetch_add(nb, std::memory_order_relaxed);
            }
            // Forward first (latency), then hand a copy to the parser.
            if (!(other == 1 && c->connecting) && !flush_out(*c, other)) {
              dead = true;
              break;
            }
            if (c->open_delivered) {
              StreamEvent e;
              e.kind = StreamEvent::Kind::Data;
              e.key = c->key;
              e.dir = side == 0 ? tcp::Dir::ToReader : tcp::Dir::ToController;
              e.ts = ts;
              e.bytes.assign(buf.data(), buf.data() + nb);
              deliver(std::move(e), c.get());
            }
            continue;
          }
          if (r == 0) {
            dead = true;  // orderly close of one side closes both
          } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            dead = true;
          }
          break;
        }
      }
      if (dead) {
        // Best effort: push what is still pending towards the surviving side.
        if (c->fd[other] >= 0 && !c->connecting) flush_out(*c, other);
        close_conn(c);
        continue;
      }
      update_interest(*c);
    }
  }
}

}  // namespace irbridge::proxy
