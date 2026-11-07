#include <gtest/gtest.h>

#include "commands.pb.h"
#include "contactless/transaction.pb.h"
#include "misc/echo.pb.h"
#include "gui/screen.pb.h"
#include "gui/widget.pb.h"
#include "irbridge/proto.hpp"

using namespace irbridge;

namespace {
codec::Frame make(std::uint8_t module, codec::FrameType type, const google::protobuf::Message& m) {
  codec::Frame f;
  f.msgid = 1;
  f.module = module;
  f.type = static_cast<std::uint8_t>(type);
  const std::string s = m.SerializeAsString();
  f.payload.assign(s.begin(), s.end());
  return f;
}
}  // namespace

TEST(Proto, Names) {
  EXPECT_STREQ(proto::module_name(0x04), "contactless_l2");
  EXPECT_STREQ(proto::module_name(0x0A), "gui");
  EXPECT_STREQ(proto::module_name(0x7F), "unknown");
  EXPECT_STREQ(proto::type_name(0x02), "success");
  EXPECT_STREQ(proto::type_name(0x05), "notification");
}

TEST(Proto, DecodeGuiShowScreen) {
  ::Gui g;
  g.mutable_show_screen()->mutable_root()->mutable_vertical_layout()->add_widgets()->mutable_picture()->set_picture_id(
      gui::picture_id::APPROVED);
  const auto d = proto::decode_command(make(0x0A, codec::FrameType::Command, g));
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(d->key.module, 0x0A);
  EXPECT_EQ(d->key.name, "show_screen");
  ASSERT_NE(d->wrapper, nullptr);
}

TEST(Proto, DecodeMiscEchoKey) {
  ::Miscellaneous m;
  m.mutable_get_echo()->set_data("ping");
  const auto d = proto::decode_command(make(0x01, codec::FrameType::Command, m));
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(d->key.name, "get_echo");
  EXPECT_EQ(d->key.field, 8);
}

TEST(Proto, GarbageCommandIsRejected) {
  codec::Frame f;
  f.module = 0x0A;
  f.type = static_cast<std::uint8_t>(codec::FrameType::Command);
  f.payload = {0xFF, 0xFF, 0xFF, 0xFF};
  EXPECT_FALSE(proto::decode_command(f).has_value());
}

TEST(Proto, SuccessTypeChosenByCommand) {
  contactless::transaction::TransactionResult r;
  r.set_status(contactless::transaction::OFFLINE_APPROVED);
  r.mutable_token()->set_type(contactless::token_type::ISO_14443_4A);
  r.mutable_token()->set_id("\x0E\x26\x44\x17");
  const proto::CommandKey key{0x04, 1, "perform_transaction"};
  const auto d = proto::decode_success(key, make(0x04, codec::FrameType::Success, r));
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(d->kind, proto::ResponseKind::TransactionResult);
  EXPECT_FALSE(d->inferred);
  const auto inf = proto::decode_success_inferred(make(0x04, codec::FrameType::Success, r));
  ASSERT_TRUE(inf.has_value());
  EXPECT_TRUE(inf->inferred);
}

TEST(Proto, WipeClearsStrings) {
  contactless::transaction::TransactionResult r;
  r.set_status(contactless::transaction::OFFLINE_APPROVED);
  r.mutable_token()->set_id("secret-uid");
  auto* tag = r.add_emv_tags();
  tag->set_number(0x5A);
  tag->set_value("\x22\x00\x00\x00\x00\x00\x00\x01");
  proto::wipe(r);
  EXPECT_FALSE(r.has_token());
  EXPECT_EQ(r.emv_tags_size(), 0);
}
