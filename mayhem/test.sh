#!/usr/bin/env bash
#
# mayhem/test.sh — ettercap's functional oracle: runs what mayhem/build.sh already built in
# mayhem/build-tests/ (never compiles). exit 0 = pass.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


TESTS="$SRC/mayhem/build-tests"
passed=0 ; failed=0

check() { # <name> <ok:0|1>
  if [ "$2" -eq 0 ]; then passed=$((passed + 1)); else failed=$((failed + 1)); echo "FAIL: $1" >&2; fi
}

# 1) the project's own libcheck suite (decoder registry lookups)
UNIT="$TESTS/tests/test_ec_decode"
if [ -x "$UNIT" ]; then
  out=$("$UNIT" 2>&1) ; rc=$?
  echo "$out"
  if [[ "$out" =~ Checks:\ ([0-9]+),\ Failures:\ ([0-9]+),\ Errors:\ ([0-9]+) ]]; then
    n=${BASH_REMATCH[1]} ; bad=$(( BASH_REMATCH[2] + BASH_REMATCH[3] ))
    passed=$((passed + n - bad)) ; failed=$((failed + bad))
  else
    check "test_ec_decode produced no libcheck summary (rc=$rc)" 1
  fi
else
  check "missing $UNIT (build.sh must build it)" 1
fi

# 2) known-answer frames through the real decoder stack (kat_probe links the dynamic libettercap):
#    one line per frame, byte-for-byte
expected=$(mktemp)
cat > "$expected" <<'EXPECTED'
imap-login: 02:00:00:00:00:01>02:00:00:00:00:02 10.0.0.1>10.0.0.2 proto=6 40002>143 len=24 user=alice pass=hunter2 banner=-
http-get: 02:00:00:00:00:01>02:00:00:00:00:02 10.0.0.1>10.0.0.2 proto=6 40005>80 len=47 user=- pass=- banner=-
imap-plain: 02:00:00:00:00:01>02:00:00:00:00:02 10.0.0.1>10.0.0.2 proto=6 40007>143 len=20 user=bob pass="p w" banner=-
snmp: 02:00:00:00:00:01>02:00:00:00:00:02 10.0.0.1>10.0.0.2 proto=17 40009>161 len=43 user=public pass=  banner=-
irc: 02:00:00:00:00:01>02:00:00:00:00:02 10.0.0.1>10.0.0.2 proto=6 40010>6667 len=23 user=unknown pass=secret banner=-
dns-query: 02:00:00:00:00:01>02:00:00:00:00:02 10.0.0.1>10.0.0.2 proto=17 40003>53 len=19 user=- pass=- banner=-
EXPECTED
PROBE="$TESTS/kat_probe"
if [ -x "$PROBE" ]; then
  actual=$("$PROBE" 2>&1) || true
  echo "$actual"
  while IFS= read -r line; do
    printf '%s\n' "$actual" | grep -Fxq -- "$line" ; check "kat_probe: ${line%%:*}" $?
  done < "$expected"
else
  check "missing $PROBE (build.sh must build it)" 1
fi
rm -f "$expected"

# 3) etterfilter: compile a known script, then disassemble the result
EF="$TESTS/utils/etterfilter"
if [ -x "$EF" ]; then
  work=$(mktemp -d)
  printf 'if (ip.proto == TCP && tcp.dst == 80) {\n drop();\n msg("x");\n}\n' > "$work/f.filter"
  comp=$("$EF" "$work/f.filter" -o "$work/f.ef" 2>&1) || true
  printf '%s\n' "$comp" | grep -Fq 'Script encoded into 6 instructions.' ; check "etterfilter compile: 6 instructions" $?
  dis=$("$EF" -t "$work/f.ef" 2>&1) || true
  printf '%s\n' "$dis" | grep -Fq '0002: TEST level 4, offset 2, size 2, == 80 [0x50]' ; check "etterfilter -t: TCP dst port test" $?
  printf '%s\n' "$dis" | grep -Fq '0004: DROP' ; check "etterfilter -t: DROP" $?
  printf '%s\n' "$dis" | grep -Fq '0005: MSG "x"' ; check "etterfilter -t: MSG" $?
  rm -rf "$work"
else
  check "missing $EF (build.sh must build it)" 1
fi

emit_ctrf "ettercap" "$passed" "$failed" 0
