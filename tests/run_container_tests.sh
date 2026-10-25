#!/bin/sh
# Host-side runner: runs tests in fixture containers with networking disabled.
# Usage: tests/run_container_tests.sh [debian12 ubuntu2404 rocky9 alpine320]
set -u
RT=${RT:-podman}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$ROOT/tests/results}; mkdir -p "$OUT"
DISTROS=${*:-debian12 ubuntu2404 rocky9 alpine320}
for d in $DISTROS; do
  $RT run --rm --network none --cap-add SYS_PTRACE -v "$ROOT:/br:ro" "localhost/br-$d" sh /br/tests/in_container.sh > "$OUT/$d.txt" 2>&1
  grep '^== RESULT' "$OUT/$d.txt"
  $RT run --rm --network none -v "$ROOT:/br:ro" "localhost/br-$d-real" sh -c "sh /br/tests/real_smoke.sh; sh /br/tests/pkg_rules.sh" > "$OUT/$d-real.txt" 2>&1
  echo "   real: $(grep -E 'VERDICT|exit=' "$OUT/$d-real.txt" | tr '\n' ' ')"
  grep "^== RESULT pkg" "$OUT/$d-real.txt"
done
