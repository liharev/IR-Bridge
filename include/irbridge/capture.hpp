// Packet sources: live AF_PACKET capture (TPACKET_V3) and classic pcap files (TZ FR-1.1..1.3).
#pragma once

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "irbridge/util.hpp"

namespace irbridge::capture {

struct Packet {
  util::Micros ts = 0;
  std::vector<std::uint8_t> bytes;  // Ethernet frame
};

struct CaptureStats {
  std::uint64_t packets = 0;
  std::uint64_t kernel_drops = 0;
  std::uint64_t bytes = 0;
};

class PacketSource {
 public:
  virtual ~PacketSource() = default;
  // Returns true and fills `out` with the next packet. For live sources waits at most
  // `timeout_ms` and returns false on timeout; for files returns false at the end.
  virtual bool next(Packet& out, int timeout_ms) = 0;
  virtual bool eof() const = 0;
  virtual CaptureStats stats() const = 0;
};

// Classic pcap (microsecond or nanosecond magic, LINKTYPE_ETHERNET). pcapng is not supported.
class PcapFileSource final : public PacketSource {
 public:
  explicit PcapFileSource(const std::string& path);
  ~PcapFileSource() override;
  PcapFileSource(const PcapFileSource&) = delete;
  PcapFileSource& operator=(const PcapFileSource&) = delete;

  bool ok() const { return f_ != nullptr && error_.empty(); }
  const std::string& error() const { return error_; }
  bool next(Packet& out, int timeout_ms) override;
  bool eof() const override { return eof_; }
  CaptureStats stats() const override { return stats_; }

 private:
  std::FILE* f_ = nullptr;
  bool swap_ = false;
  bool nanos_ = false;
  bool eof_ = false;
  std::string error_;
  CaptureStats stats_;
};

class PcapWriter {
 public:
  explicit PcapWriter(const std::string& path, bool restrict_mode_0600 = false);
  ~PcapWriter();
  PcapWriter(const PcapWriter&) = delete;
  PcapWriter& operator=(const PcapWriter&) = delete;

  bool ok() const { return f_ != nullptr; }
  void write(util::Micros ts, const std::uint8_t* data, std::size_t len);
  void write(util::Micros ts, const std::vector<std::uint8_t>& data) { write(ts, data.data(), data.size()); }
  std::uint64_t bytes_written() const { return bytes_; }
  void flush();

 private:
  std::FILE* f_ = nullptr;
  std::uint64_t bytes_ = 0;
};

// Live capture on a Linux interface with PACKET_MMAP / TPACKET_V3, promiscuous mode and a kernel BPF
// filter for TCP on the given ports (IPv4, optionally behind up to one VLAN tag).
class AfPacketSource final : public PacketSource {
 public:
  AfPacketSource(const std::string& iface, const std::vector<std::uint16_t>& ports);
  ~AfPacketSource() override;
  AfPacketSource(const AfPacketSource&) = delete;
  AfPacketSource& operator=(const AfPacketSource&) = delete;

  bool ok() const { return fd_ >= 0 && error_.empty(); }
  const std::string& error() const { return error_; }
  bool next(Packet& out, int timeout_ms) override;
  bool eof() const override { return false; }
  CaptureStats stats() const override;

 private:
  bool advance_block();
  void release_block();

  int fd_ = -1;
  std::uint8_t* ring_ = nullptr;
  std::size_t ring_size_ = 0;
  unsigned block_size_ = 0;
  unsigned block_count_ = 0;
  unsigned block_idx_ = 0;
  // Iteration state inside the current block.
  std::uint8_t* cur_block_ = nullptr;
  unsigned pkts_left_ = 0;
  std::uint8_t* cur_pkt_ = nullptr;
  std::string error_;
  mutable CaptureStats stats_;
};

// Classic BPF program accepting IPv4 TCP packets (optionally VLAN-tagged) whose source or
// destination port is in `ports`. Exposed for tests.
struct BpfInsn {
  std::uint16_t code;
  std::uint8_t jt, jf;
  std::uint32_t k;
};
std::vector<BpfInsn> build_tcp_port_filter(const std::vector<std::uint16_t>& ports);

}  // namespace irbridge::capture
