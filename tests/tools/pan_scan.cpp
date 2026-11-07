// pan_scan - checks files (event logs, databases, captures) for card numbers.
// Looks for 13..19-digit runs passing the Luhn check in ASCII and in packed BCD form.
// Exit code: 0 = clean, 1 = candidates found, 2 = usage / I/O error.
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include "irbridge/privacy.hpp"

namespace {

// Unpacks BCD nibbles into ASCII digits; any non-decimal nibble becomes a separator.
std::string bcd_to_digits(const std::string& bytes) {
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char b : bytes) {
    const unsigned hi = b >> 4, lo = b & 0x0F;
    out.push_back(hi < 10 ? static_cast<char>('0' + hi) : ' ');
    out.push_back(lo < 10 ? static_cast<char>('0' + lo) : ' ');
  }
  return out;
}

// Text files (JSON, logs) are scanned as ASCII only: their bytes read as BCD give false positives.
bool looks_binary(const std::string& data) {
  std::size_t nonprint = 0;
  for (unsigned char c : data) {
    if ((c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c == 0x7F) ++nonprint;
  }
  return !data.empty() && nonprint * 10 > data.size();  // more than 10 % control bytes
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "Usage: pan_scan [--ascii-only] FILE...\n";
    return 2;
  }
  bool ascii_only = false;
  int found = 0;
  for (int i = 1; i < argc; ++i) {
    const std::string path = argv[i];
    if (path == "--ascii-only") {
      ascii_only = true;
      continue;
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) {
      std::cerr << "cannot read " << path << "\n";
      return 2;
    }
    const std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    for (const auto& c : irbridge::privacy::find_pan_candidates(data)) {
      if (c[0] == '0') continue;  // no PAN starts with 0 (ISO/IEC 7812 major industry identifier)
      std::cout << path << ": ASCII candidate " << c.substr(0, 6) << "..." << c.substr(c.size() - 4) << "\n";
      ++found;
    }
    if (!ascii_only && looks_binary(data)) {
      for (const auto& c : irbridge::privacy::find_pan_candidates(bcd_to_digits(data))) {
        if (c[0] == '0') continue;
        std::cout << path << ": BCD candidate " << c.substr(0, 6) << "..." << c.substr(c.size() - 4) << "\n";
        ++found;
      }
    }
  }
  if (found == 0) std::cout << "no PAN candidates\n";
  return found == 0 ? 0 : 1;
}
