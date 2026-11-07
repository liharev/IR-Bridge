// Request/response correlation by MSGID (prompt 5).
#include <gtest/gtest.h>

#include "commands.pb.h"
#include "common/failure.pb.h"
#include "contactless/transaction.pb.h"
#include "irbridge/corr.hpp"

using namespace irbridge;
using corr::Direction;
using corr::EventKind;

namespace {

codec::Frame fr(std::uint8_t msgid, std::uint8_t module, codec::FrameType t, const std::string& payload = {}) {
  codec::Frame f;
  f.msgid = msgid;
  f.module = module;
  f.type = static_cast<std::uint8_t>(t);
  f.payload.assign(payload.begin(), payload.end());
  return f;
}

std::string perform_txn() {
  ::ContactlessLevel2 c;
  auto* t = c.mutable_perform_transaction();
  t->mutable_poll_for_token()->set_timeout(1000);
  t->set_amount_authorized(6600);
  t->set_transaction_date(std::string("\x26\x11\x07", 3));
  t->set_transaction_time(std::string("\x08\x00\x00", 3));
  t->set_transaction_type(std::string("\x00", 1));
  t->set_terminal_country_code(std::string("\x06\x43", 2));
  t->set_transaction_currency_code(std::string("\x06\x43", 2));
  t->set_merchant_category_code(std::string("\x41\x31", 2));
  t->set_terminal_identification("VT0012");
  EXPECT_TRUE(c.IsInitialized()) << c.InitializationErrorString();
  return c.SerializeAsString();
}

std::string txn_result() {
  contactless::transaction::TransactionResult r;
  r.set_status(contactless::transaction::OFFLINE_APPROVED);
  r.mutable_token()->set_type(contactless::token_type::ISO_14443_4A);
  r.mutable_token()->set_id("\x01\x02\x03\x04");
  return r.SerializeAsString();
}

struct Sink {
  std::vector<corr::CorrelatedEvent> ev;
  corr::SessionCorrelator::Sink fn() {
    return [this](corr::CorrelatedEvent&& e) { ev.push_back(std::move(e)); };
  }
};

}  // namespace

TEST(Corr, CommandPendingSuccess) {
  Sink s;
  corr::SessionCorrelator c(s.fn());
  c.on_frame(fr(7, 0x04, codec::FrameType::Command, perform_txn()), 1, Direction::ToReader);
  c.on_frame(fr(7, 0x04, codec::FrameType::Pending), 2, Direction::ToController);
  c.on_frame(fr(7, 0x04, codec::FrameType::Success, txn_result()), 3, Direction::ToController);
  ASSERT_EQ(s.ev.size(), 2u);
  EXPECT_EQ(s.ev[0].kind, EventKind::CommandIssued);
  EXPECT_EQ(s.ev[0].key.name, "perform_transaction");
  EXPECT_EQ(s.ev[1].kind, EventKind::Succeeded);
  ASSERT_TRUE(s.ev[1].response.has_value());
  EXPECT_EQ(s.ev[1].response->kind, proto::ResponseKind::TransactionResult);
  EXPECT_FALSE(s.ev[1].inferred);
  EXPECT_EQ(c.pending(), 0u);
  EXPECT_EQ(c.stats().pendings, 1u);
}

TEST(Corr, Failure) {
  Sink s;
  corr::SessionCorrelator c(s.fn());
  c.on_frame(fr(9, 0x04, codec::FrameType::Command, perform_txn()), 1, Direction::ToReader);
  common::failure::FailureResponse f;
  f.set_error(common::failure::TIMEOUT_EXPIRED);
  c.on_frame(fr(9, 0x04, codec::FrameType::Failure, f.SerializeAsString()), 2, Direction::ToController);
  ASSERT_EQ(s.ev.size(), 2u);
  EXPECT_EQ(s.ev[1].kind, EventKind::Failed);
  ASSERT_NE(s.ev[1].failure, nullptr);
  EXPECT_EQ(s.ev[1].failure->error(), common::failure::TIMEOUT_EXPIRED);
}

TEST(Corr, CancelMarksPending) {
  Sink s;
  corr::SessionCorrelator c(s.fn());
  c.on_frame(fr(3, 0x04, codec::FrameType::Command, perform_txn()), 1, Direction::ToReader);
  c.on_frame(fr(0, 0x00, codec::FrameType::Control), 2, Direction::ToReader);
  EXPECT_EQ(c.stats().cancels, 1u);
  bool cancelled = false;
  for (const auto& e : s.ev) cancelled = cancelled || e.kind == EventKind::Cancelled;
  EXPECT_TRUE(cancelled);
}

TEST(Corr, UnmatchedResponseIsInferred) {
  Sink s;
  corr::SessionCorrelator c(s.fn());
  c.on_frame(fr(42, 0x04, codec::FrameType::Success, txn_result()), 1, Direction::ToController);
  ASSERT_EQ(s.ev.size(), 1u);
  EXPECT_TRUE(s.ev[0].inferred);
  EXPECT_EQ(c.stats().inferred_responses, 1u);
}

TEST(Corr, WrongDirectionAndModuleMismatch) {
  Sink s;
  corr::SessionCorrelator c(s.fn());
  c.on_frame(fr(1, 0x04, codec::FrameType::Command, perform_txn()), 1, Direction::ToController);
  EXPECT_EQ(c.stats().direction_errors, 1u);
  c.on_frame(fr(2, 0x04, codec::FrameType::Command, perform_txn()), 1, Direction::ToReader);
  c.on_frame(fr(2, 0x0A, codec::FrameType::Success), 2, Direction::ToController);
  EXPECT_EQ(c.stats().module_mismatches, 1u);
}

TEST(Corr, PendingExpiresAndGapForgets) {
  Sink s;
  corr::SessionCorrelator c(s.fn(), 10 * util::kMicrosPerSecond);
  c.on_frame(fr(1, 0x04, codec::FrameType::Command, perform_txn()), 0, Direction::ToReader);
  c.on_tick(5 * util::kMicrosPerSecond);
  EXPECT_EQ(c.pending(), 1u);
  c.on_tick(11 * util::kMicrosPerSecond);
  EXPECT_EQ(c.pending(), 0u);
  EXPECT_EQ(c.stats().expired, 1u);
  c.on_frame(fr(2, 0x04, codec::FrameType::Command, perform_txn()), 0, Direction::ToReader);
  c.on_gap();
  EXPECT_EQ(c.pending(), 0u);
}

TEST(Corr, NotificationsCounted) {
  Sink s;
  corr::SessionCorrelator c(s.fn());
  c.on_frame(fr(0, 0x00, codec::FrameType::Notification), 1, Direction::ToController);
  EXPECT_EQ(c.stats().notifications, 1u);
}
