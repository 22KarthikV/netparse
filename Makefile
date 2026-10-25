# netparse - top-level build.
#
#   make            library + CLI + unit tests + bench binaries (build/)
#   make test       unit tests (plain and ASan+UBSan) and the pytest suite
#   make bench      run the parser benchmark
#   make fuzz       build and run libFuzzer targets (clang), FUZZ_TIME s each
#   make fuzz-afl   build AFL++ targets (afl-clang-fast) into build-afl/
#   make coverage   gcov/gcovr line + branch coverage of unit + pytest runs
#   make clean

CC      ?= cc
BUILD   ?= build
PYTHON  ?= python3
WARN    := -Wall -Wextra -Werror -pedantic -Wshadow -Wstrict-prototypes \
           -Wmissing-prototypes -Wcast-align -Wpointer-arith
OPT     ?= -O2 -g
CFLAGS  ?=
CPPFLAGS += -Iinclude -Isrc
ALLCFLAGS = -std=c11 $(WARN) $(OPT) $(CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)

LIB_SRC := src/parse.c src/pcap.c src/flow.c
LIB_OBJ := $(LIB_SRC:src/%.c=$(BUILD)/obj/%.o)
LIB     := $(BUILD)/libnetparse.a
CLI     := $(BUILD)/netparse
UNIT    := $(BUILD)/unit_tests
BENCH   := $(BUILD)/bench_parse
HDRS    := $(wildcard include/netparse/*.h src/*.h)

SAN_FLAGS := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

FUZZ_TIME ?= 60
FUZZ_CC   ?= clang

.PHONY: all test unit unit-san pytest bench fuzz fuzz-afl coverage clean

all: $(LIB) $(CLI) $(UNIT) $(BENCH)

$(BUILD)/obj/%.o: src/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(ALLCFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJ)
	ar rcs $@ $^

$(CLI): tools/netparse.c $(LIB) $(HDRS)
	$(CC) $(CPPFLAGS) $(ALLCFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(UNIT): tests/unit_tests.c tests/test.h tests/pktbuild.h $(LIB) $(HDRS)
	$(CC) $(CPPFLAGS) $(ALLCFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(BENCH): bench/bench_parse.c tests/pktbuild.h $(LIB) $(HDRS)
	$(CC) $(CPPFLAGS) -Itests $(ALLCFLAGS) $< $(LIB) $(LDFLAGS) -o $@

# ---- tests --------------------------------------------------------------

test: unit unit-san pytest

unit: $(UNIT)
	./$(UNIT)

unit-san:
	$(MAKE) BUILD=build-san EXTRA_CFLAGS="$(SAN_FLAGS)" EXTRA_LDFLAGS="$(SAN_FLAGS)" \
	    build-san/unit_tests build-san/netparse
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1 \
	    ./build-san/unit_tests

# The pytest suite drives the sanitizer build of the CLI so every pcap
# case also runs under ASan+UBSan.
pytest: unit-san
	NETPARSE_BIN=$(CURDIR)/build-san/netparse $(PYTHON) -m pytest -q tests/py

# ---- bench --------------------------------------------------------------

bench: $(BENCH)
	./$(BENCH)

# ---- fuzzing ------------------------------------------------------------

FUZZ_TARGETS := fuzz_parse fuzz_pcap

fuzz:
	@mkdir -p build-fuzz
	for t in $(FUZZ_TARGETS); do \
	  $(FUZZ_CC) $(CPPFLAGS) -std=c11 -g -O1 -fsanitize=fuzzer,address,undefined \
	    -fno-sanitize-recover=all fuzz/$$t.c $(LIB_SRC) -o build-fuzz/$$t || exit 1; \
	done
	for t in $(FUZZ_TARGETS); do \
	  mkdir -p build-fuzz/corpus-$$t; \
	  ./build-fuzz/$$t -max_total_time=$(FUZZ_TIME) -print_final_stats=1 \
	    build-fuzz/corpus-$$t fuzz/corpus/$$t || exit 1; \
	done

fuzz-afl:
	@mkdir -p build-afl
	for t in $(FUZZ_TARGETS); do \
	  AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast $(CPPFLAGS) -std=c11 -g -O2 \
	    -fsanitize=fuzzer fuzz/$$t.c $(LIB_SRC) -o build-afl/$$t || exit 1; \
	done

# ---- coverage -----------------------------------------------------------

coverage:
	rm -rf build-cov
	$(MAKE) CC=gcc BUILD=build-cov OPT="-O0 -g" EXTRA_CFLAGS="--coverage" \
	    EXTRA_LDFLAGS="--coverage" build-cov/unit_tests build-cov/netparse
	./build-cov/unit_tests
	NETPARSE_BIN=$(CURDIR)/build-cov/netparse $(PYTHON) -m pytest -q tests/py
	gcovr --root . --filter src/ --object-directory build-cov/obj \
	    --txt-metric branch --print-summary --txt build-cov/coverage.txt
	@cat build-cov/coverage.txt

clean:
	rm -rf build build-san build-cov build-fuzz build-afl tests/py/__pycache__ \
	    tests/py/.pytest_cache .pytest_cache
