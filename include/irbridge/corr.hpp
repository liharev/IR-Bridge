// Request/response correlation inside one TCP session (TZ FR-4.1..4.3).
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>

#include "irbridge/codec.hpp"
#include "irbridge/proto.hpp"
#include "irbridge/util.hpp"

namespace common::failure {
class FailureResponse;
}

namespace irbridge::corr {

enum class Direction { ToReader, ToController };

enum class EventKind {
  CommandIssued,  // controller sent a command
  Succeeded,      // final successful response (response decoded where relevant)
  Failed,         // final failure response
  Cancelled,      // controller sent a Control (cancellation) while the command was pending
};

const char* event_kind_name(EventKind k);

struct CorrelatedEvent {
  util::Micros ts = 0;
  EventKind kind = EventKind::CommandIssued;
  proto::CommandKey key;
  // The command (for CommandIssued, and for responses when the command was seen).
  std::shared_ptr<const proto::DecodedCommand> command;
  // Succeeded only.
  std::optional<proto::DecodedResponse> response;
  // Failed only.
  std::shared_ptr<common::failure::FailureResponse> failure;
  bool inferred = false;
};

struct CorrelatorStats {
  std::uint64_t commands = 0;
  std::uint64_t responses = 0;
  std::uint64_t failures = 0;
  std::uint64_t pendings = 0;
  std::uint64_t notifications = 0;
  std::uint64_t cancels = 0;
  std::uint64_t unmatched_responses = 0;
  std::uint64_t inferred_responses = 0;
  std::uint64_t module_mismatches = 0;
  std::uint64_t payload_errors = 0;
  std::uint64_t direction_errors = 0;
  std::uint64_t expired = 0;
};

class SessionCorrelator {
 public:
  using Sink = std::function<void(CorrelatedEvent&&)>;

  explicit SessionCorrelator(Sink sink, util::Micros pending_ttl = 30 * util::kMicrosPerSecond);

  void on_frame(const codec::Frame& f, util::Micros ts, Direction dir);
  // Data was lost in either direction: forget pending commands (their answers may be gone).
  void on_gap();
  // Drops pending commands older than the TTL.
  void on_tick(util::Micros now);

  const CorrelatorStats& stats() const { return stats_; }
  std::size_t pending() const { return pending_.size(); }

 private:
  struct Pending {
    std::shared_ptr<const proto::DecodedCommand> command;
    util::Micros ts = 0;
    bool cancelled = false;
  };

  void handle_command(const codec::Frame& f, util::Micros ts);
  void handle_response(const codec::Frame& f, util::Micros ts);

  Sink sink_;
  util::Micros ttl_;
  std::map<std::uint8_t, Pending> pending_;  // by MSGID
  std::optional<std::uint8_t> last_msgid_;
  CorrelatorStats stats_;
};

}  // namespace irbridge::corr
