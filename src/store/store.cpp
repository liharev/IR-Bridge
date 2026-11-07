#include "irbridge/store.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

namespace irbridge::store {

namespace {

constexpr int kSchemaVersion = 1;

const char* table(Kind k) { return k == Kind::Validation ? "validations" : "intervals"; }

// RAII wrapper for prepared statements.
struct Stmt {
  sqlite3_stmt* s = nullptr;
  Stmt(sqlite3* db, const char* sql) {
    if (sqlite3_prepare_v2(db, sql, -1, &s, nullptr) != SQLITE_OK) {
      spdlog::error("sqlite prepare failed: {} ({})", sqlite3_errmsg(db), sql);
      s = nullptr;
    }
  }
  ~Stmt() { sqlite3_finalize(s); }
  Stmt(const Stmt&) = delete;
  Stmt& operator=(const Stmt&) = delete;
  explicit operator bool() const { return s != nullptr; }
  void text(int i, const std::string& v) { sqlite3_bind_text(s, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT); }
  void i64(int i, std::int64_t v) { sqlite3_bind_int64(s, i, v); }
  int step() { return sqlite3_step(s); }
  std::string col_text(int i) {
    const auto* p = sqlite3_column_text(s, i);
    return p ? std::string(reinterpret_cast<const char*>(p), static_cast<std::size_t>(sqlite3_column_bytes(s, i))) : std::string();
  }
  std::int64_t col_i64(int i) { return sqlite3_column_int64(s, i); }
};

}  // namespace

Store::~Store() { close(); }

bool Store::exec(const char* sql) {
  char* err = nullptr;
  if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
    spdlog::error("sqlite: {} ({})", err ? err : "?", sql);
    sqlite3_free(err);
    return false;
  }
  return true;
}

bool Store::open(const std::string& path, std::string& error) {
  std::lock_guard<std::mutex> lk(db_mu_);
  if (sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                      nullptr) != SQLITE_OK) {
    error = "cannot open database " + path + ": " + (db_ ? sqlite3_errmsg(db_) : "?");
    sqlite3_close(db_);
    db_ = nullptr;
    return false;
  }
  sqlite3_busy_timeout(db_, 2000);
  const bool ok = exec("PRAGMA journal_mode=WAL;") && exec("PRAGMA synchronous=NORMAL;") &&
                  exec("PRAGMA auto_vacuum=INCREMENTAL;") &&
                  exec("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);") &&
                  exec("CREATE TABLE IF NOT EXISTS validations(event_id TEXT PRIMARY KEY, ts INTEGER NOT NULL, "
                       "json TEXT NOT NULL, published INTEGER NOT NULL DEFAULT 0);") &&
                  exec("CREATE TABLE IF NOT EXISTS intervals(interval_id TEXT PRIMARY KEY, ts INTEGER NOT NULL, "
                       "json TEXT NOT NULL, published INTEGER NOT NULL DEFAULT 0);") &&
                  exec("CREATE TABLE IF NOT EXISTS validator_status(validator_id TEXT PRIMARY KEY, json TEXT NOT NULL, "
                       "updated_at INTEGER NOT NULL);") &&
                  exec("CREATE INDEX IF NOT EXISTS validations_ts ON validations(ts);") &&
                  exec("CREATE INDEX IF NOT EXISTS validations_pub ON validations(published, ts);") &&
                  exec("CREATE INDEX IF NOT EXISTS intervals_ts ON intervals(ts);") &&
                  exec("CREATE INDEX IF NOT EXISTS intervals_pub ON intervals(published, ts);");
  if (!ok) {
    error = "cannot initialise database schema in " + path;
    return false;
  }
  Stmt s(db_, "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?1);");
  if (s) {
    s.text(1, std::to_string(kSchemaVersion));
    s.step();
  }
  return true;
}

void Store::close() {
  std::lock_guard<std::mutex> lk(db_mu_);
  if (db_ != nullptr) {
    sqlite3_close(db_);
    db_ = nullptr;
  }
}

bool Store::enqueue(Record r) {
  std::lock_guard<std::mutex> lk(q_mu_);
  if (queue_.size() >= kMaxQueue) {
    ++stats_.dropped;
    return false;
  }
  queue_.push_back(std::move(r));
  ++stats_.enqueued;
  return true;
}

void Store::put_status(const std::string& validator_id, const std::string& json, util::Micros now) {
  std::lock_guard<std::mutex> lk(db_mu_);
  if (db_ == nullptr) return;
  Stmt s(db_, "INSERT INTO validator_status(validator_id, json, updated_at) VALUES(?1, ?2, ?3) "
              "ON CONFLICT(validator_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at;");
  if (!s) return;
  s.text(1, validator_id);
  s.text(2, json);
  s.i64(3, now);
  s.step();
}

std::size_t Store::flush() {
  std::deque<Record> batch;
  {
    std::lock_guard<std::mutex> lk(q_mu_);
    batch.swap(queue_);
  }
  if (batch.empty()) return 0;
  std::lock_guard<std::mutex> lk(db_mu_);
  if (db_ == nullptr) return 0;
  exec("BEGIN;");
  std::size_t n = 0;
  {
    Stmt v(db_, "INSERT OR IGNORE INTO validations(event_id, ts, json) VALUES(?1, ?2, ?3);");
    Stmt i(db_, "INSERT OR IGNORE INTO intervals(interval_id, ts, json) VALUES(?1, ?2, ?3);");
    for (const auto& r : batch) {
      Stmt& s = r.kind == Kind::Validation ? v : i;
      if (!s) continue;
      sqlite3_reset(s.s);
      s.text(1, r.id);
      s.i64(2, r.ts);
      s.text(3, r.json);
      if (s.step() == SQLITE_DONE) ++n;
    }
  }
  exec("COMMIT;");
  std::lock_guard<std::mutex> lq(q_mu_);
  stats_.written += n;
  return n;
}

std::vector<Record> Store::unpublished(std::size_t limit) {
  std::vector<Record> out;
  std::lock_guard<std::mutex> lk(db_mu_);
  if (db_ == nullptr) return out;
  for (Kind k : {Kind::Validation, Kind::Interval}) {
    const std::string sql = std::string("SELECT ") + (k == Kind::Validation ? "event_id" : "interval_id") +
                            ", ts, json FROM " + table(k) + " WHERE published=0 ORDER BY ts LIMIT ?1;";
    Stmt s(db_, sql.c_str());
    if (!s) continue;
    s.i64(1, static_cast<std::int64_t>(limit));
    while (s.step() == SQLITE_ROW) out.push_back(Record{k, s.col_text(0), s.col_i64(1), s.col_text(2)});
  }
  return out;
}

void Store::mark_published(Kind kind, const std::string& id) {
  std::lock_guard<std::mutex> lk(db_mu_);
  if (db_ == nullptr) return;
  const std::string sql = std::string("UPDATE ") + table(kind) + " SET published=1 WHERE " +
                          (kind == Kind::Validation ? "event_id" : "interval_id") + "=?1;";
  Stmt s(db_, sql.c_str());
  if (!s) return;
  s.text(1, id);
  s.step();
}

std::size_t Store::unpublished_count() {
  std::lock_guard<std::mutex> lk(db_mu_);
  if (db_ == nullptr) return 0;
  std::size_t n = 0;
  for (Kind k : {Kind::Validation, Kind::Interval}) {
    const std::string sql = std::string("SELECT COUNT(*) FROM ") + table(k) + " WHERE published=0;";
    Stmt s(db_, sql.c_str());
    if (s && s.step() == SQLITE_ROW) n += static_cast<std::size_t>(s.col_i64(0));
  }
  std::lock_guard<std::mutex> lq(q_mu_);
  return n + queue_.size();
}

namespace {
std::vector<std::string> since(sqlite3* db, const char* tbl, util::Micros ts, std::size_t limit) {
  std::vector<std::string> out;
  const std::string sql = std::string("SELECT json FROM ") + tbl + " WHERE ts >= ?1 ORDER BY ts LIMIT ?2;";
  Stmt s(db, sql.c_str());
  if (!s) return out;
  s.i64(1, ts);
  s.i64(2, static_cast<std::int64_t>(limit));
  while (s.step() == SQLITE_ROW) out.push_back(s.col_text(0));
  return out;
}
}  // namespace

std::vector<std::string> Store::validations_since(util::Micros ts, std::size_t limit) {
  std::lock_guard<std::mutex> lk(db_mu_);
  return db_ ? since(db_, "validations", ts, limit) : std::vector<std::string>{};
}

std::vector<std::string> Store::intervals_since(util::Micros ts, std::size_t limit) {
  std::lock_guard<std::mutex> lk(db_mu_);
  return db_ ? since(db_, "intervals", ts, limit) : std::vector<std::string>{};
}

std::vector<std::string> Store::statuses() {
  std::vector<std::string> out;
  std::lock_guard<std::mutex> lk(db_mu_);
  if (db_ == nullptr) return out;
  Stmt s(db_, "SELECT json FROM validator_status ORDER BY validator_id;");
  while (s && s.step() == SQLITE_ROW) out.push_back(s.col_text(0));
  return out;
}

std::uint64_t Store::size_bytes() {
  std::lock_guard<std::mutex> lk(db_mu_);
  if (db_ == nullptr) return 0;
  Stmt pc(db_, "PRAGMA page_count;");
  Stmt ps(db_, "PRAGMA page_size;");
  if (!pc || !ps || pc.step() != SQLITE_ROW || ps.step() != SQLITE_ROW) return 0;
  return static_cast<std::uint64_t>(pc.col_i64(0)) * static_cast<std::uint64_t>(ps.col_i64(0));
}

void Store::retention(util::Micros now, int events_days, int intervals_days, std::uint64_t max_bytes) {
  std::uint64_t pruned = 0;
  {
    std::lock_guard<std::mutex> lk(db_mu_);
    if (db_ == nullptr) return;
    const util::Micros day = 86400LL * util::kMicrosPerSecond;
    for (auto [tbl, days] : {std::pair<const char*, int>{"validations", events_days}, {"intervals", intervals_days}}) {
      const std::string sql = std::string("DELETE FROM ") + tbl + " WHERE ts < ?1;";
      Stmt s(db_, sql.c_str());
      if (!s) continue;
      s.i64(1, now - static_cast<util::Micros>(days) * day);
      s.step();
      pruned += static_cast<std::uint64_t>(sqlite3_changes(db_));
    }
  }
  // Size cap: drop the oldest published validations in batches.
  for (int i = 0; i < 100 && size_bytes() > max_bytes; ++i) {
    std::lock_guard<std::mutex> lk(db_mu_);
    Stmt s(db_, "DELETE FROM validations WHERE event_id IN (SELECT event_id FROM validations WHERE published=1 "
                "ORDER BY ts LIMIT 1000);");
    if (!s) break;
    s.step();
    const int ch = sqlite3_changes(db_);
    pruned += static_cast<std::uint64_t>(ch);
    exec("PRAGMA incremental_vacuum;");
    if (ch == 0) break;
  }
  if (pruned > 0) {
    std::lock_guard<std::mutex> lk(db_mu_);
    exec("PRAGMA incremental_vacuum;");
    std::lock_guard<std::mutex> lq(q_mu_);
    stats_.pruned += pruned;
  }
}

StoreStats Store::stats() {
  std::lock_guard<std::mutex> lk(q_mu_);
  return stats_;
}

}  // namespace irbridge::store
