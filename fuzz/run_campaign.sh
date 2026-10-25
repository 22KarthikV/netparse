#!/bin/sh
# SPDX-License-Identifier: MIT
# Run the fuzzing campaign used for the README numbers:
#   AFL++  (afl-clang-fast, ASan+UBSan) on both targets in parallel, AFL_TIME s each
#   libFuzzer (clang, ASan+UBSan)       on both targets in parallel, LF_TIME s each
# Results land in fuzz/out/ (git-ignored). Needs: make fuzz-afl, make fuzz FUZZ_TIME=1.
set -eu
cd "$(dirname "$0")/.."
AFL_TIME=${AFL_TIME:-540}
LF_TIME=${LF_TIME:-240}
OUT=fuzz/out
rm -rf "$OUT"
mkdir -p "$OUT"

export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1
for t in fuzz_parse fuzz_pcap; do
    afl-fuzz -V "$AFL_TIME" -i "fuzz/corpus/$t" -o "$OUT/afl-$t" -- "build-afl/$t" \
        > "$OUT/afl-$t.log" 2>&1 &
done
wait

for t in fuzz_parse fuzz_pcap; do
    mkdir -p "$OUT/lf-corpus-$t"
    "./build-fuzz/$t" -max_total_time="$LF_TIME" -print_final_stats=1 \
        -artifact_prefix="$OUT/lf-$t-" "$OUT/lf-corpus-$t" "fuzz/corpus/$t" \
        > "$OUT/lf-$t.log" 2>&1 &
done
wait

echo "== AFL++ =="
for t in fuzz_parse fuzz_pcap; do
    s="$OUT/afl-$t/default/fuzzer_stats"
    echo "$t: $(grep -E '^(run_time|execs_done|execs_per_sec|corpus_count|saved_crashes|saved_hangs|bitmap_cvg|edges_found|total_edges)' "$s" | tr -s ' ' | tr '\n' ' ')"
done
echo "== libFuzzer =="
for t in fuzz_parse fuzz_pcap; do
    echo "$t: $(grep -E 'stat::number_of_executed_units|stat::average_exec_per_sec' "$OUT/lf-$t.log" | tr -s ' ' | tr '\n' ' ') $(grep -E '^#[0-9]+ *DONE' "$OUT/lf-$t.log" | tail -1)"
    ls "$OUT"/lf-"$t"-* 2>/dev/null || echo "  no crash artifacts"
done
