#include "commands.pb.h"
#include "complex/poll_for_event.pb.h"
#include "contactless/indication.pb.h"
#include "contactless/transaction.pb.h"
#include "irbridge/detect.hpp"

namespace irbridge::detect {

const char* outcome_name(Outcome o) {
  switch (o) {
    case Outcome::Approved: return "APPROVED";
    case Outcome::Rejected: return "REJECTED";
    case Outcome::NoDecision: return "NO_DECISION";
    case Outcome::Aborted: return "ABORTED";
  }
  return "UNKNOWN";
}

const char* policy_name(SuccessPolicy p) {
  switch (p) {
    case SuccessPolicy::Indication: return "indication";
    case SuccessPolicy::IndicationOrWrite: return "indication_or_write";
    case SuccessPolicy::EmvStatus: return "emv_status";
  }
  return "indication";
}

bool parse_policy(const std::string& s, SuccessPolicy& out) {
  if (s == "indication") out = SuccessPolicy::Indication;
  else if (s == "indication_or_write") out = SuccessPolicy::IndicationOrWrite;
  else if (s == "emv_status") out = SuccessPolicy::EmvStatus;
  else return false;
  return true;
}

ValidationDetector::ValidationDetector(const DetectorConfig& cfg, const privacy::CarrierHasher& hasher, Sink sink)
    : cfg_(cfg), hasher_(hasher), sink_(std::move(sink)) {}

namespace {

// Remembers the transaction parameters the controller sent (amount, indication mode, terminal id).
void remember_txn_params(const contactless::transaction::PerformTransaction& t, std::optional<std::uint64_t>& amount,
                         std::optional<std::string>& indication, std::optional<std::string>& terminal) {
  amount = t.amount_authorized();
  indication = contactless::indication::Indication_Name(t.indication());
  if (t.has_terminal_identification()) {
    terminal = t.terminal_identification();
  } else {
    terminal.reset();
  }
}

}  // namespace

void ValidationDetector::on_event(corr::CorrelatedEvent& ev) {
  // 1. Commands: remember transaction parameters, react to indications.
  if (ev.kind == corr::EventKind::CommandIssued && ev.command) {
    const auto& cmd = *ev.command;
    if (cmd.wrapper && static_cast<proto::ModuleId>(cmd.key.module) == proto::ModuleId::ContactlessL2) {
      const auto& w = static_cast<const ::ContactlessLevel2&>(*cmd.wrapper);
      if (w.has_perform_transaction()) {
        remember_txn_params(w.perform_transaction(), last_amount_, last_indication_mode_, last_terminal_id_);
      }
    } else if (cmd.wrapper && static_cast<proto::ModuleId>(cmd.key.module) == proto::ModuleId::Complex) {
      const auto& w = static_cast<const ::Complex&>(*cmd.wrapper);
      if (w.has_poll_for_event() && w.poll_for_event().has_perform_txn()) {
        remember_txn_params(w.poll_for_event().perform_txn(), last_amount_, last_indication_mode_, last_terminal_id_);
      }
    }
    if (!cfg_.require_ack) {
      const RuleMatch m = cfg_.rules.evaluate(cmd);
      if (m.indication != Indication::None) handle_indication(m, ev.ts);
    }
    return;
  }

  if (ev.kind == corr::EventKind::Succeeded) {
    // 2. Indication acknowledged by the reader (require_ack mode).
    if (cfg_.require_ack && ev.command) {
      const RuleMatch m = cfg_.rules.evaluate(*ev.command);
      if (m.indication != Indication::None) {
        handle_indication(m, ev.ts);
        return;
      }
    }
    // 3. Confirmed card write.
    if (ev.command && is_card_write(*ev.command)) {
      if (current_) current_->card_write_confirmed = true;
      return;
    }
    // 4. Presentment.
    if (ev.response) {
      auto p = extract_presentment(*ev.response, hasher_, ev.ts);
      if (p) {
        start(std::move(*p));
        // IntelliReader performs on_event_ui_action itself when a Complex poll event fires.
        if (ev.command) {
          const RuleMatch m = cfg_.rules.evaluate_complex_event_ui(*ev.command);
          if (m.indication != Indication::None) handle_indication(m, ev.ts);
        }
      }
    }
    return;
  }
  // Failed / Cancelled: no effect on the current validation; the decision window handles it.
}

void ValidationDetector::start(Presentment&& p) {
  ++stats_.presentments;
  if (current_) {
    const bool within = p.ts - current_->ts_presented <= cfg_.same_carrier_merge;
    const bool same = p.carrier_hash.empty() || current_->presentment.carrier_hash.empty() ||
                      p.carrier_hash == current_->presentment.carrier_hash;
    if (within && same) {
      // Same carrier in the same validation (EMV first -> transport card read, token -> ticket).
      ++stats_.merged;
      Presentment& cur = current_->presentment;
      if (cur.carrier_hash.empty()) cur.carrier_hash = p.carrier_hash;
      if (p.carrier_class != CarrierClass::Unknown && cur.carrier_class != CarrierClass::Troika) {
        cur.carrier_class = p.carrier_class;
      }
      if (p.carrier_class == CarrierClass::Troika) cur.carrier_class = CarrierClass::Troika;
      if (cur.token_type.empty()) cur.token_type = p.token_type;
      if (cur.token_carrier_type.empty()) cur.token_carrier_type = p.token_carrier_type;
      if (p.emv_status) {
        cur.emv_status = p.emv_status;
        cur.emv_approved = p.emv_approved;
      }
      if (!p.payment_system.empty()) cur.payment_system = p.payment_system;
      if (!p.ir_version.empty()) cur.ir_version = p.ir_version;
      return;
    }
    // A different carrier before the controller decided: close the previous one.
    expire(p.ts);
  }
  ValidationRecord r;
  r.ts_presented = p.ts;
  r.presentment = std::move(p);
  current_ = std::move(r);
}

void ValidationDetector::handle_indication(const RuleMatch& m, util::Micros ts) {
  if (!current_) {
    ++stats_.orphan_indications;
    return;
  }
  if (m.indication == Indication::Approve) {
    finish(Outcome::Approved, ts, m.rule, m.passengers);
  } else if (m.indication == Indication::Reject) {
    finish(Outcome::Rejected, ts, m.rule);
  }
}

void ValidationDetector::finish(Outcome o, util::Micros ts, const std::string& rule, int passengers) {
  if (!current_) return;
  ValidationRecord r = std::move(*current_);
  current_.reset();
  r.outcome = o;
  r.ts_decided = ts;
  r.decision_rule = rule;
  r.passengers = o == Outcome::Approved ? passengers : 0;
  r.amount_minor = last_amount_;
  r.indication_mode = last_indication_mode_;
  r.terminal_identification = last_terminal_id_;
  switch (o) {
    case Outcome::Approved: ++stats_.approved; break;
    case Outcome::Rejected: ++stats_.rejected; break;
    case Outcome::NoDecision: ++stats_.no_decision; break;
    case Outcome::Aborted: ++stats_.aborted; break;
  }
  sink_(std::move(r));
}

// The decision window elapsed (or another carrier arrived) without an explicit indication.
void ValidationDetector::expire(util::Micros now) {
  if (!current_) return;
  const auto& cur = *current_;
  if (cfg_.policy == SuccessPolicy::EmvStatus && cur.presentment.emv_approved) {
    finish(Outcome::Approved, now, "emv_status:" + cur.presentment.emv_status.value_or(""));
    return;
  }
  if (cfg_.policy == SuccessPolicy::IndicationOrWrite && cur.card_write_confirmed) {
    finish(Outcome::Approved, now, "card_write");
    return;
  }
  finish(Outcome::NoDecision, now, "timeout");
}

void ValidationDetector::on_tick(util::Micros now) {
  if (current_ && now - current_->ts_presented >= cfg_.decision_window) expire(now);
}

void ValidationDetector::on_session_closed(util::Micros now) {
  if (current_) finish(Outcome::Aborted, now, "session_closed");
  last_amount_.reset();
  last_indication_mode_.reset();
  last_terminal_id_.reset();
}

}  // namespace irbridge::detect
