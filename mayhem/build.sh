#!/usr/bin/env bash
#
# mayhem/build.sh — builds ettercap three ways:
#   1. mayhem/build-fuzz/    the whole project (shared libettercap + etterfilter + etterlog) with
#                            $SANITIZER_FLAGS, $DEBUG_FLAGS and SanCov; the three libFuzzer harnesses link it.
#   2. /mayhem/<target>      the libFuzzer harnesses, plus a -standalone reproducer each; and
#      /mayhem/etterfilter   the sanitized etterfilter, the file-input target.
#   3. mayhem/build-tests/   the project's normal-flag build with its libcheck suite and the KAT probe,
#                            which mayhem/test.sh runs.
# Offline: every dependency is an apt -dev package baked into the image by mayhem/Dockerfile.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

FUZZ="$SRC/mayhem/build-fuzz"
TESTS="$SRC/mayhem/build-tests"

CMAKE_COMMON=(
  -DCMAKE_BUILD_TYPE=Release
  -DENABLE_CURSES=OFF -DENABLE_GTK=OFF -DENABLE_PLUGINS=OFF -DINSTALL_DESKTOP=OFF
  -DBUNDLED_LIBS=OFF
)

# share/ is found through INSTALL_DATADIR/ettercap; point it at the checkout so nothing is installed.
link_data() {
  mkdir -p "$1/data"
  ln -sfn "$SRC/share" "$1/data/ettercap"
}

# LeakSanitizer off for every fuzz binary (SPEC §6.2 item 15), the project's own executables included.
HDIR="$FUZZ/harness"
mkdir -p "$HDIR"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$HDIR/lsan_off.o"

# Benign-in-practice UB (left shift of a negative value, null+0, misaligned header loads) halts on the first packet and hides the
# memory-safety bugs behind it, so those UBSan checks are off for the project; the rest stays halting.
RELAX_UBSAN="-fno-sanitize=shift-base,pointer-overflow,alignment"

# 1) sanitized project. -fsanitize=fuzzer-no-link is unconditional so the library carries SanCov even
#    when SANITIZER_FLAGS is empty.
cmake -S "$SRC" -B "$FUZZ" "${CMAKE_COMMON[@]}" \
  -DINSTALL_DATADIR="$FUZZ/data" \
  -DCMAKE_EXE_LINKER_FLAGS="$HDIR/lsan_off.o" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $RELAX_UBSAN $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
link_data "$FUZZ"
cmake --build "$FUZZ" -j"$MAYHEM_JOBS"

# 2) harnesses
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$HDIR/standalone_main.o"

LIBDIR="$(dirname "$(find "$FUZZ/src" -maxdepth 1 -name 'libettercap.so' -o -maxdepth 1 -name 'libettercap.so.*' | head -n1)")"
HARNESS_CFLAGS=(-I"$SRC/include" -I"$FUZZ/include" -I"$SRC/mayhem")
HARNESS_LIBS=(-L"$LIBDIR" -lettercap -Wl,-rpath,"$LIBDIR")

for t in fuzz_decode fuzz_dissect fuzz_hosts; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${HARNESS_CFLAGS[@]}" $LIB_FUZZING_ENGINE \
      "$SRC/mayhem/$t.c" "$HDIR/lsan_off.o" "${HARNESS_LIBS[@]}" -o "$SRC/$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${HARNESS_CFLAGS[@]}" \
      "$SRC/mayhem/$t.c" "$HDIR/standalone_main.o" "$HDIR/lsan_off.o" "${HARNESS_LIBS[@]}" \
      -o "$SRC/$t-standalone"
done

# etterfilter defines ec_gbls in its own main (and libettercap.so defines it too: the executable's copy
# interposes). ASan's odr-violation check aborts at startup on that pair, so main's object is recompiled without
# ASan global instrumentation and the executable relinked; everything else stays fully instrumented.
EFD="$FUZZ/utils/CMakeFiles/etterfilter.dir"
$CC $(sed -n 's/^C_DEFINES = //p' "$EFD/flags.make") $(sed -n 's/^C_INCLUDES = //p' "$EFD/flags.make") \
    $(sed -n 's/^C_FLAGS = //p' "$EFD/flags.make") -mllvm -asan-globals=0 \
    -c "$SRC/utils/etterfilter/ef_main.c" -o "$EFD/etterfilter/ef_main.noglobals.o"
(cd "$FUZZ/utils" && bash -c "$(sed 's#etterfilter/ef_main\.c\.o#etterfilter/ef_main.noglobals.o#' "$EFD/link.txt")")
cp "$FUZZ/utils/etterfilter" "$SRC/etterfilter"

# 3) test build with the project's normal flags
cmake -S "$SRC" -B "$TESTS" "${CMAKE_COMMON[@]}" \
  -DENABLE_TESTS=ON \
  -DINSTALL_DATADIR="$TESTS/data" \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS"
link_data "$TESTS"
cmake --build "$TESTS" -j"$MAYHEM_JOBS"

# 4) the known-answer probe, linked dynamically against the normal-flags libettercap like ettercap itself
TESTLIB="$(dirname "$(find "$TESTS/src" -maxdepth 1 -name 'libettercap.so' -o -maxdepth 1 -name 'libettercap.so.*' | head -n1)")"
$CC $COVERAGE_FLAGS -w -I"$SRC/include" -I"$TESTS/include" -I"$SRC/mayhem" "$SRC/mayhem/kat_probe.c" \
    -L"$TESTLIB" -lettercap -Wl,-rpath,"$TESTLIB" -o "$TESTS/kat_probe"
