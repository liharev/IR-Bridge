// Local SQLite store: durable queue for publication and history for the HTTP API (TZ FR-8.1, 8.2).
#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include "irbridge/util.hpp"

struct sqlite3;

namespace irbridge::store {

enum class Kind { Validation, Interval };

struct Record {
  Kind kind = Kind::Validation;
  std::string id;
  util::Micros ts = 0;  // presented / start
  std::string json;
};

struct StoreStats {
  std::uint64_t enqueued = 0;
  std::uint64_t written = 0;
  std::uint64_t dropped = 0;
  std::uint64_t pruned = 0;
};

class Store {
 public:
  static constexpr std::size_t kMaxQueue = 10000;

  Store() = default;
  ~Store();
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;

  bool open(const std::string& path, std::string& error);
  void close();

  // Thread-safe. Returns false (and counts a drop) when the in-memory queue is full.
  bool enqueue(Record r);
  void put_status(const std::string& validator_id, const std::string& json, util::Micros now);

  // Writes queued records in one transaction. Call about once a second from the store thread.
  std::size_t flush();

  // Oldest unpublished records first.
  std::vector<Record> unpublished(std::size_t limit);
  void mark_published(Kind kind, const std::string& id);
  std::size_t unpublished_count();

  std::vector<std::string> validations_since(util::Micros since, std::size_t limit);
  std::vector<std::string> intervals_since(util::Micros since, std::size_t limit);
  std::vector<std::string> statuses();

  // Deletes old records and keeps the database under `max_bytes` (oldest published first).
  void retention(util::Micros now, int events_days, int intervals_days, std::uint64_t max_bytes);
  std::uint64_t size_bytes();

  StoreStats stats();

 private:
  bool exec(const char* sql);

  sqlite3* db_ = nullptr;
  std::mutex db_mu_;
  std::mutex q_mu_;
  std::deque<Record> queue_;
  StoreStats stats_;
};

}  // namespace irbridge::store
