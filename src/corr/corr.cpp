#include "irbridge/corr.hpp"

#include <spdlog/spdlog.h>

#include "common/failure.pb.h"
#include "common/notification.pb.h"

namespace irbridge::corr {

using codec::FrameType;

const char* event_kind_name(EventKind k) {
  switch (k) {
    case EventKind::CommandIssued: return "command";
    case EventKind::Succeeded: return "succeeded";
    case EventKind::Failed: return "failed";
    case EventKind::Cancelled: return "cancelled";
  }
  return "unknown";
}

SessionCorrelator::SessionCorrelator(Sink sink, util::Micros pending_ttl) : sink_(std::move(sink)), ttl_(pending_ttl) {}

void SessionCorrelator::on_frame(const codec::Frame& f, util::Micros ts, Direction dir) {
  switch (f.frame_type()) {
    case FrameType::Command:
      if (dir != Direction::ToReader) {
        ++stats_.direction_errors;
        return;
      }
      handle_command(f, ts);
      return;
    case FrameType::Control: {
      if (dir != Direction::ToReader) {
        ++stats_.direction_errors;
        return;
      }
      ++stats_.cancels;
      // Cancels the command currently processed by the reader: the latest pending one.
      if (last_msgid_) {
        auto it = pending_.find(*last_msgid_);
        if (it != pending_.end() && !it->second.cancelled) {
          it->second.cancelled = true;
          CorrelatedEvent ev;
          ev.ts = ts;
          ev.kind = EventKind::Cancelled;
          ev.key = it->second.command->key;
          ev.command = it->second.command;
          sink_(std::move(ev));
        }
      }
      return;
    }
    case FrameType::Pending:
      if (dir != Direction::ToController) {
        ++stats_.direction_errors;
        return;
      }
      ++stats_.pendings;
      if (auto it = pending_.find(f.msgid); it != pending_.end()) it->second.ts = ts;  // extend TTL
      return;
    case FrameType::Notification: {
      ++stats_.notifications;
      if (spdlog::should_log(spdlog::level::trace)) {
        // Log only the importance level and length: notifications may carry card data in debug mode.
        spdlog::trace("IR notification, {} bytes", f.payload.size());
      }
      return;
    }
    case FrameType::Success:
    case FrameType::Failure:
      if (dir != Direction::ToController) {
        ++stats_.direction_errors;
        return;
      }
      handle_response(f, ts);
      return;
  }
}

void SessionCorrelator::handle_command(const codec::Frame& f, util::Micros ts) {
  ++stats_.commands;
  auto decoded = proto::decode_command(f);
  if (!decoded) {
    ++stats_.payload_errors;
    proto::DecodedCommand bare;
    bare.key.module = f.module;
    decoded = std::move(bare);
  }
  auto cmd = std::make_shared<const proto::DecodedCommand>(std::move(*decoded));
  pending_[f.msgid] = Pending{cmd, ts, false};
  last_msgid_ = f.msgid;
  CorrelatedEvent ev;
  ev.ts = ts;
  ev.kind = EventKind::CommandIssued;
  ev.key = cmd->key;
  ev.command = cmd;
  sink_(std::move(ev));
}

void SessionCorrelator::handle_response(const codec::Frame& f, util::Micros ts) {
  const bool success = f.frame_type() == FrameType::Success;
  CorrelatedEvent ev;
  ev.ts = ts;
  ev.kind = success ? EventKind::Succeeded : EventKind::Failed;

  auto it = pending_.find(f.msgid);
  if (it != pending_.end() && it->second.command->key.module != f.module) {
    ++stats_.module_mismatches;
    it = pending_.end();
  }

  if (it != pending_.end()) {
    ev.command = it->second.command;
    ev.key = ev.command->key;
    pending_.erase(it);
    if (success) {
      ++stats_.responses;
      ev.response = proto::decode_success(ev.key, f);
      if (!ev.response) {
        ++stats_.payload_errors;
        return;
      }
    } else {
      ++stats_.failures;
      ev.failure = proto::decode_failure(f);
      if (!ev.failure) ++stats_.payload_errors;
    }
    sink_(std::move(ev));
    return;
  }

  // The command was not observed.
  ++stats_.unmatched_responses;
  ev.key.module = f.module;
  ev.inferred = true;
  if (success) {
    ev.response = proto::decode_success_inferred(f);
    if (!ev.response) return;  // nothing useful can be said about it
    ++stats_.inferred_responses;
    ev.response->inferred = true;
  } else {
    ev.failure = proto::decode_failure(f);
    if (!ev.failure) {
      ++stats_.payload_errors;
      return;
    }
  }
  sink_(std::move(ev));
}

void SessionCorrelator::on_gap() {
  pending_.clear();
  last_msgid_.reset();
}

void SessionCorrelator::on_tick(util::Micros now) {
  for (auto it = pending_.begin(); it != pending_.end();) {
    if (now - it->second.ts > ttl_) {
      ++stats_.expired;
      it = pending_.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace irbridge::corr
