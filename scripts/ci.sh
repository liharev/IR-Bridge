#!/usr/bin/env bash
# Full local check: release build + tests, sanitizer build + tests, scenario PAN scan, package.
# Usage: scripts/ci.sh [--fuzz SECONDS]
set -euo pipefail
cd "$(dirname "$0")/.."
JOBS=$(nproc)
FUZZ_SECONDS=0
if [[ "${1:-}" == "--fuzz" ]]; then FUZZ_SECONDS=${2:-60}; fi

echo "== Release"
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build-release -j"$JOBS"
(cd build-release && ctest -j"$JOBS" --output-on-failure)

echo "== ASan/UBSan"
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DIRBRIDGE_SANITIZE=ON >/dev/null
cmake --build build-asan -j"$JOBS"
(cd build-asan && ctest -j"$JOBS" --output-on-failure)

echo "== PAN scan of scenario outputs"
build-release/pan_scan --ascii-only build-release/scenario_out/*.jsonl

if [[ "$FUZZ_SECONDS" -gt 0 ]]; then
  echo "== Fuzzing ${FUZZ_SECONDS}s per target"
  CC=clang CXX=clang++ cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo -DIRBRIDGE_BUILD_FUZZ=ON \
    -DIRBRIDGE_BUILD_TESTS=OFF >/dev/null
  cmake --build build-fuzz -j"$JOBS" --target fuzz_codec fuzz_tcp fuzz_proto
  for fz in fuzz_codec fuzz_tcp fuzz_proto; do
    build-fuzz/$fz -max_total_time="$FUZZ_SECONDS" -dict=tests/fuzz/dict.txt
  done
fi

echo "== Package"
(cd build-release && cpack >/dev/null && ls -1 ./*.deb)
