#include <gtest/gtest.h>
#include <unistd.h>

#include <filesystem>

#include "irbridge/store.hpp"

using namespace irbridge;
namespace fs = std::filesystem;

namespace {

constexpr util::Micros S = util::kMicrosPerSecond;
constexpr util::Micros DAY = 86400 * S;

struct TempDb {
  fs::path dir;
  std::string path;
  TempDb() {
    static int n = 0;
    dir = fs::temp_directory_path() / ("irbridge-store-" + std::to_string(::getpid()) + "-" + std::to_string(++n));
    fs::create_directories(dir);
    path = (dir / "events.db").string();
  }
  ~TempDb() { fs::remove_all(dir); }
};

store::Record rec(store::Kind k, const std::string& id, util::Micros ts) {
  return store::Record{k, id, ts, "{\"id\":\"" + id + "\"}"};
}

}  // namespace

TEST(Store, QueueFlushPublish) {
  TempDb t;
  store::Store s;
  std::string err;
  ASSERT_TRUE(s.open(t.path, err)) << err;
  ASSERT_TRUE(s.enqueue(rec(store::Kind::Validation, "v1", 10 * S)));
  ASSERT_TRUE(s.enqueue(rec(store::Kind::Validation, "v2", 20 * S)));
  ASSERT_TRUE(s.enqueue(rec(store::Kind::Interval, "i1", 15 * S)));
  EXPECT_EQ(s.unpublished(10).size(), 0u);  // not flushed yet
  EXPECT_EQ(s.unpublished_count(), 3u);      // the count includes the in-memory queue
  EXPECT_EQ(s.flush(), 3u);
  EXPECT_EQ(s.unpublished_count(), 3u);
  const auto u = s.unpublished(10);
  ASSERT_EQ(u.size(), 3u);
  s.mark_published(store::Kind::Validation, "v1");
  EXPECT_EQ(s.unpublished_count(), 2u);
  // Duplicate event ids are ignored (at-least-once upstream).
  s.enqueue(rec(store::Kind::Validation, "v2", 20 * S));
  s.flush();
  EXPECT_EQ(s.unpublished_count(), 2u);
  const auto since = s.validations_since(15 * S, 100);
  ASSERT_EQ(since.size(), 1u);
  EXPECT_EQ(since[0], "{\"id\":\"v2\"}");
  EXPECT_EQ(s.intervals_since(0, 100).size(), 1u);
}

TEST(Store, SurvivesReopen) {
  TempDb t;
  std::string err;
  {
    store::Store s;
    ASSERT_TRUE(s.open(t.path, err)) << err;
    s.enqueue(rec(store::Kind::Validation, "v1", 10 * S));
    s.enqueue(rec(store::Kind::Validation, "v2", 11 * S));
    s.flush();
    s.mark_published(store::Kind::Validation, "v1");
    s.put_status("V1", "{\"status\":\"observed\"}", 12 * S);
  }  // closed without checkpoint: WAL recovery on the next open
  store::Store s;
  ASSERT_TRUE(s.open(t.path, err)) << err;
  const auto u = s.unpublished(10);
  ASSERT_EQ(u.size(), 1u);
  EXPECT_EQ(u[0].id, "v2");
  ASSERT_EQ(s.statuses().size(), 1u);
}

TEST(Store, BoundedQueue) {
  TempDb t;
  store::Store s;
  std::string err;
  ASSERT_TRUE(s.open(t.path, err)) << err;
  for (std::size_t i = 0; i < store::Store::kMaxQueue; ++i) {
    ASSERT_TRUE(s.enqueue(rec(store::Kind::Validation, "v" + std::to_string(i), static_cast<util::Micros>(i))));
  }
  EXPECT_FALSE(s.enqueue(rec(store::Kind::Validation, "overflow", 0)));
  EXPECT_EQ(s.stats().dropped, 1u);
  EXPECT_EQ(s.flush(), store::Store::kMaxQueue);
}

TEST(Store, RetentionByAge) {
  TempDb t;
  store::Store s;
  std::string err;
  ASSERT_TRUE(s.open(t.path, err)) << err;
  const util::Micros now = 100 * DAY;
  s.enqueue(rec(store::Kind::Validation, "old", now - 31 * DAY));
  s.enqueue(rec(store::Kind::Validation, "new", now - 1 * DAY));
  s.enqueue(rec(store::Kind::Interval, "iold", now - 91 * DAY));
  s.enqueue(rec(store::Kind::Interval, "inew", now - 31 * DAY));
  s.flush();
  s.retention(now, 30, 90, 1ull << 30);
  EXPECT_EQ(s.validations_since(0, 10).size(), 1u);
  EXPECT_EQ(s.intervals_since(0, 10).size(), 1u);
  EXPECT_EQ(s.stats().pruned, 2u);
}

TEST(Store, RetentionBySizeKeepsUnpublished) {
  TempDb t;
  store::Store s;
  std::string err;
  ASSERT_TRUE(s.open(t.path, err)) << err;
  const std::string big(2000, 'x');
  for (int i = 0; i < 3000; ++i) {
    s.enqueue(store::Record{store::Kind::Validation, "p" + std::to_string(i), i * S, "{\"pad\":\"" + big + "\"}"});
    if (i % 1000 == 999) s.flush();
  }
  s.enqueue(rec(store::Kind::Validation, "unpub", 0));
  s.flush();
  for (int i = 0; i < 3000; ++i) s.mark_published(store::Kind::Validation, "p" + std::to_string(i));
  const std::uint64_t before = s.size_bytes();
  s.retention(4000 * S, 30, 90, before / 3);
  EXPECT_LT(s.validations_since(0, 5000).size(), 3001u);
  EXPECT_EQ(s.unpublished_count(), 1u);
}
