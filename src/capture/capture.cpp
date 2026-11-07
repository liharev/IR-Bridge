#include "irbridge/capture.hpp"

#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace irbridge::capture {

// ---------------------------------------------------------------------------------------------
// pcap files
// ---------------------------------------------------------------------------------------------
namespace {
constexpr std::uint32_t kPcapMagicUs = 0xA1B2C3D4;
constexpr std::uint32_t kPcapMagicNs = 0xA1B23C4D;
constexpr std::uint32_t kLinkEthernet = 1;
constexpr std::uint32_t kMaxSnap = 262144;

std::uint32_t bswap32(std::uint32_t v) { return __builtin_bswap32(v); }
}  // namespace

PcapFileSource::PcapFileSource(const std::string& path) {
  f_ = std::fopen(path.c_str(), "rb");
  if (f_ == nullptr) {
    error_ = "cannot open " + path + ": " + std::strerror(errno);
    return;
  }
  std::uint32_t hdr[6];
  if (std::fread(hdr, sizeof(hdr), 1, f_) != 1) {
    error_ = "truncated pcap header in " + path;
    return;
  }
  std::uint32_t magic = hdr[0];
  if (magic == kPcapMagicUs || magic == kPcapMagicNs) {
    swap_ = false;
  } else if (bswap32(magic) == kPcapMagicUs || bswap32(magic) == kPcapMagicNs) {
    swap_ = true;
    magic = bswap32(magic);
  } else if (magic == 0x0A0D0D0A) {
    error_ = path + " is pcapng; convert it with: editcap -F pcap in.pcapng out.pcap";
    return;
  } else {
    error_ = path + " is not a pcap file";
    return;
  }
  nanos_ = magic == kPcapMagicNs;
  const std::uint32_t link = swap_ ? bswap32(hdr[5]) : hdr[5];
  if ((link & 0x0FFFFFFF) != kLinkEthernet) {
    error_ = path + ": unsupported link type " + std::to_string(link) + " (Ethernet expected)";
  }
}

PcapFileSource::~PcapFileSource() {
  if (f_ != nullptr) std::fclose(f_);
}

bool PcapFileSource::next(Packet& out, int /*timeout_ms*/) {
  if (!ok() || eof_) return false;
  std::uint32_t rec[4];
  if (std::fread(rec, sizeof(rec), 1, f_) != 1) {
    eof_ = true;
    return false;
  }
  if (swap_) {
    for (auto& v : rec) v = bswap32(v);
  }
  const std::uint32_t incl = rec[2];
  if (incl > kMaxSnap) {
    error_ = "corrupt pcap record length";
    eof_ = true;
    return false;
  }
  out.bytes.resize(incl);
  if (incl > 0 && std::fread(out.bytes.data(), incl, 1, f_) != 1) {
    eof_ = true;
    return false;
  }
  const util::Micros sub = nanos_ ? rec[1] / 1000 : rec[1];
  out.ts = static_cast<util::Micros>(rec[0]) * util::kMicrosPerSecond + sub;
  ++stats_.packets;
  stats_.bytes += incl;
  return true;
}

PcapWriter::PcapWriter(const std::string& path, bool restrict_mode_0600) {
  const mode_t old = restrict_mode_0600 ? ::umask(077) : 0;
  f_ = std::fopen(path.c_str(), "wb");
  if (restrict_mode_0600) ::umask(old);
  if (f_ == nullptr) return;
  // Native byte order: magic, version 2.4, thiszone, sigfigs, snaplen, linktype.
  const std::uint32_t magic = kPcapMagicUs;
  const std::uint16_t ver[2] = {2, 4};
  const std::uint32_t rest[4] = {0, 0, kMaxSnap, kLinkEthernet};
  std::fwrite(&magic, sizeof(magic), 1, f_);
  std::fwrite(ver, sizeof(ver), 1, f_);
  std::fwrite(rest, sizeof(rest), 1, f_);
  bytes_ = 24;
}

PcapWriter::~PcapWriter() {
  if (f_ != nullptr) std::fclose(f_);
}

void PcapWriter::write(util::Micros ts, const std::uint8_t* data, std::size_t len) {
  if (f_ == nullptr) return;
  const std::uint32_t rec[4] = {static_cast<std::uint32_t>(ts / util::kMicrosPerSecond),
                                static_cast<std::uint32_t>(ts % util::kMicrosPerSecond),
                                static_cast<std::uint32_t>(len), static_cast<std::uint32_t>(len)};
  std::fwrite(rec, sizeof(rec), 1, f_);
  if (len > 0) std::fwrite(data, len, 1, f_);
  bytes_ += sizeof(rec) + len;
}

void PcapWriter::flush() {
  if (f_ != nullptr) std::fflush(f_);
}

// ---------------------------------------------------------------------------------------------
// BPF
// ---------------------------------------------------------------------------------------------
namespace {

struct SymInsn {
  std::uint16_t code;
  int jt;  // absolute target index (-1: next)
  int jf;
  std::uint32_t k;
};

constexpr int kAccept = -100;
constexpr int kReject = -101;

void emit_ipv4_tcp_block(std::vector<SymInsn>& p, std::uint32_t base, const std::vector<std::uint16_t>& ports) {
  // ip proto == tcp
  p.push_back({BPF_LD | BPF_B | BPF_ABS, -1, -1, base + 9});
  p.push_back({BPF_JMP | BPF_JEQ | BPF_K, -1, kReject, 6});
  // not a fragment (offset != 0); MF on a first fragment is rejected in userspace
  p.push_back({BPF_LD | BPF_H | BPF_ABS, -1, -1, base + 6});
  p.push_back({BPF_JMP | BPF_JSET | BPF_K, kReject, -1, 0x1FFF});
  // X = IP header length
  p.push_back({BPF_LDX | BPF_B | BPF_MSH, -1, -1, base});
  // source port
  p.push_back({BPF_LD | BPF_H | BPF_IND, -1, -1, base});
  for (auto port : ports) p.push_back({BPF_JMP | BPF_JEQ | BPF_K, kAccept, -1, port});
  // destination port
  p.push_back({BPF_LD | BPF_H | BPF_IND, -1, -1, base + 2});
  for (auto port : ports) p.push_back({BPF_JMP | BPF_JEQ | BPF_K, kAccept, -1, port});
  p.push_back({BPF_RET | BPF_K, -1, -1, 0});
}

}  // namespace

std::vector<BpfInsn> build_tcp_port_filter(const std::vector<std::uint16_t>& ports) {
  std::vector<SymInsn> p;
  // [0] ethertype
  p.push_back({BPF_LD | BPF_H | BPF_ABS, -1, -1, 12});
  const std::size_t jvlan = p.size();
  p.push_back({BPF_JMP | BPF_JEQ | BPF_K, 0 /*patched*/, -1, 0x8100});
  p.push_back({BPF_JMP | BPF_JEQ | BPF_K, -1, kReject, 0x0800});
  emit_ipv4_tcp_block(p, 14, ports);
  const std::size_t vlan_start = p.size();
  p[jvlan].jt = static_cast<int>(vlan_start);
  p.push_back({BPF_LD | BPF_H | BPF_ABS, -1, -1, 16});
  p.push_back({BPF_JMP | BPF_JEQ | BPF_K, -1, kReject, 0x0800});
  emit_ipv4_tcp_block(p, 18, ports);
  const int accept_idx = static_cast<int>(p.size());
  p.push_back({BPF_RET | BPF_K, -1, -1, 0x40000});  // accept, snap 256 KiB
  const int reject_idx = static_cast<int>(p.size());
  p.push_back({BPF_RET | BPF_K, -1, -1, 0});

  std::vector<BpfInsn> out;
  out.reserve(p.size());
  for (std::size_t i = 0; i < p.size(); ++i) {
    auto resolve = [&](int t) -> std::uint8_t {
      int target = t;
      if (t == -1) target = static_cast<int>(i) + 1;
      if (t == kAccept) target = accept_idx;
      if (t == kReject) target = reject_idx;
      return static_cast<std::uint8_t>(target - static_cast<int>(i) - 1);
    };
    BpfInsn ins{p[i].code, 0, 0, p[i].k};
    if (BPF_CLASS(p[i].code) == BPF_JMP) {
      ins.jt = resolve(p[i].jt);
      ins.jf = resolve(p[i].jf);
    }
    out.push_back(ins);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// AF_PACKET TPACKET_V3
// ---------------------------------------------------------------------------------------------
AfPacketSource::AfPacketSource(const std::string& iface, const std::vector<std::uint16_t>& ports) {
  fd_ = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
  if (fd_ < 0) {
    error_ = std::string("socket(AF_PACKET): ") + std::strerror(errno) + " (CAP_NET_RAW required)";
    return;
  }
  const unsigned ifindex = if_nametoindex(iface.c_str());
  if (ifindex == 0) {
    error_ = "unknown interface " + iface;
    return;
  }
  // Kernel filter: only IR traffic reaches userspace.
  const auto prog = build_tcp_port_filter(ports);
  std::vector<sock_filter> filt;
  for (const auto& i : prog) filt.push_back({i.code, i.jt, i.jf, i.k});
  sock_fprog fprog{static_cast<unsigned short>(filt.size()), filt.data()};
  if (::setsockopt(fd_, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) != 0) {
    // Not fatal: userspace parsing filters as well.
    error_.clear();
  }
  int ver = TPACKET_V3;
  if (::setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) != 0) {
    error_ = std::string("PACKET_VERSION: ") + std::strerror(errno);
    return;
  }
  block_size_ = 1u << 20;  // 1 MiB
  block_count_ = 8;
  tpacket_req3 req{};
  req.tp_block_size = block_size_;
  req.tp_block_nr = block_count_;
  req.tp_frame_size = 1u << 11;
  req.tp_frame_nr = (block_size_ * block_count_) / req.tp_frame_size;
  req.tp_retire_blk_tov = 50;  // ms: deliver partially filled blocks quickly
  if (::setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) != 0) {
    error_ = std::string("PACKET_RX_RING: ") + std::strerror(errno);
    return;
  }
  ring_size_ = static_cast<std::size_t>(block_size_) * block_count_;
  void* m = ::mmap(nullptr, ring_size_, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd_, 0);
  if (m == MAP_FAILED) m = ::mmap(nullptr, ring_size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
  if (m == MAP_FAILED) {
    error_ = std::string("mmap ring: ") + std::strerror(errno);
    return;
  }
  ring_ = static_cast<std::uint8_t*>(m);
  sockaddr_ll ll{};
  ll.sll_family = AF_PACKET;
  ll.sll_protocol = htons(ETH_P_ALL);
  ll.sll_ifindex = static_cast<int>(ifindex);
  if (::bind(fd_, reinterpret_cast<sockaddr*>(&ll), sizeof(ll)) != 0) {
    error_ = std::string("bind ") + iface + ": " + std::strerror(errno);
    return;
  }
  packet_mreq mr{};
  mr.mr_ifindex = static_cast<int>(ifindex);
  mr.mr_type = PACKET_MR_PROMISC;
  if (::setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) != 0) {
    error_ = std::string("promiscuous mode on ") + iface + ": " + std::strerror(errno) + " (CAP_NET_ADMIN required)";
    return;
  }
}

AfPacketSource::~AfPacketSource() {
  if (ring_ != nullptr) ::munmap(ring_, ring_size_);
  if (fd_ >= 0) ::close(fd_);
}

void AfPacketSource::release_block() {
  if (cur_block_ != nullptr) {
    auto* desc = reinterpret_cast<tpacket_block_desc*>(cur_block_);
    __atomic_store_n(&desc->hdr.bh1.block_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE);
    cur_block_ = nullptr;
    block_idx_ = (block_idx_ + 1) % block_count_;
  }
}

bool AfPacketSource::advance_block() {
  auto* desc = reinterpret_cast<tpacket_block_desc*>(ring_ + static_cast<std::size_t>(block_idx_) * block_size_);
  if ((__atomic_load_n(&desc->hdr.bh1.block_status, __ATOMIC_ACQUIRE) & TP_STATUS_USER) == 0) return false;
  cur_block_ = reinterpret_cast<std::uint8_t*>(desc);
  pkts_left_ = desc->hdr.bh1.num_pkts;
  cur_pkt_ = cur_block_ + desc->hdr.bh1.offset_to_first_pkt;
  return true;
}

bool AfPacketSource::next(Packet& out, int timeout_ms) {
  if (!ok()) return false;
  while (true) {
    if (cur_block_ != nullptr && pkts_left_ > 0) {
      auto* hdr = reinterpret_cast<tpacket3_hdr*>(cur_pkt_);
      const std::uint8_t* data = cur_pkt_ + hdr->tp_mac;
      out.bytes.assign(data, data + hdr->tp_snaplen);
      out.ts = static_cast<util::Micros>(hdr->tp_sec) * util::kMicrosPerSecond + hdr->tp_nsec / 1000;
      ++stats_.packets;
      stats_.bytes += hdr->tp_snaplen;
      --pkts_left_;
      cur_pkt_ += hdr->tp_next_offset;
      if (pkts_left_ == 0) release_block();
      return true;
    }
    if (cur_block_ != nullptr) release_block();
    if (advance_block()) continue;
    pollfd pfd{fd_, POLLIN | POLLERR, 0};
    const int rc = ::poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return false;
    if (!advance_block()) return false;
  }
}

CaptureStats AfPacketSource::stats() const {
  if (fd_ >= 0) {
    tpacket_stats_v3 st{};
    socklen_t len = sizeof(st);
    if (::getsockopt(fd_, SOL_PACKET, PACKET_STATISTICS, &st, &len) == 0) stats_.kernel_drops += st.tp_drops;
  }
  return stats_;
}

}  // namespace irbridge::capture
