/* SPDX-License-Identifier: MIT
 * Single-core parser throughput benchmark.
 *
 * Builds an in-memory set of frames with a fixed size mix, pins itself to
 * one CPU, and parses the set repeatedly. Each configuration is timed over
 * RUNS runs; the median, min and max are reported.
 *
 *   usage: bench_parse [runs] [cpu]
 */
#define _GNU_SOURCE
#include "netparse/flow.h"
#include "netparse/netparse.h"
#include "pktbuild.h"

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NFRAMES 4096
#define NFLOWS  1024

static uint8_t *arena;
static uint32_t off[NFRAMES], len[NFRAMES];
static np_flow slots[4096];
static volatile uint64_t sink;

/* Packet mix (by count). Sizes are Ethernet frame lengths without FCS. */
struct kind {
    const char *name;
    unsigned weight;
} kinds[] = {
    {"TCP pure ACK + timestamps, 66 B", 40},
    {"TCP SYN, 5 options, 74 B", 5},
    {"TCP data 1448 B payload + TS, 1514 B", 25},
    {"TCP ACK + SACK(2) + TS, 86 B", 5},
    {"UDP 64 B payload, 106 B", 10},
    {"802.1Q TCP 512 B payload, 578 B", 10},
    {"IPv6 TCP 200 B payload, 286 B", 5},
};

static const uint8_t opt_ts[12] = {1, 1, 8, 10, 0, 0, 0x10, 0, 0, 0, 0x20, 0};
static const uint8_t opt_syn[20] = {2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1,
                                    0, 0, 0, 0, 1, 3, 3, 7};
static const uint8_t opt_sack[32] = {1, 1, 8, 10, 0, 0, 0x10, 0, 0, 0, 0x20, 0,
                                     1, 1, 5, 18, 0, 0, 0x10, 0, 0, 0, 0x20, 0,
                                     0, 0, 0x30, 0, 0, 0, 0x40, 0};

static size_t build_kind(int k, uint32_t i, uint8_t *out, size_t cap)
{
    struct pb_spec s = pb_tcp4(i * 1448u, 1000, NP_TCP_ACK, 0);
    s.sport = (uint16_t)(10000 + i % NFLOWS);
    switch (k) {
    case 0: s.tcpopts = opt_ts; s.tcpopts_len = 12; break;
    case 1: s.tcp_flags = NP_TCP_SYN; s.tcpopts = opt_syn; s.tcpopts_len = 20; break;
    case 2: s.tcpopts = opt_ts; s.tcpopts_len = 12; s.payload_len = 1448; break;
    case 3: s.tcpopts = opt_sack; s.tcpopts_len = 32; break;
    case 4: s.proto = NP_IPPROTO_UDP; s.payload_len = 64; break;
    case 5: s.nvlan = 1; s.vlan_tci[0] = 100; s.payload_len = 512; break;
    case 6:
        s.ipv6 = 1;
        s.src6[0] = 0x20; s.src6[1] = 0x01; s.src6[15] = 1;
        s.dst6[0] = 0x20; s.dst6[1] = 0x01; s.dst6[15] = 2;
        s.payload_len = 200;
        break;
    }
    return pb_build(&s, out, cap);
}

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

enum mode { M_PARSE, M_PARSE_IPCSUM, M_PARSE_FLOW, M_PARSE_ALLCSUM };
static const char *mode_names[] = {
    "parse only (no checksum verify)",
    "parse + IPv4 header checksum",
    "parse + flow tracking (1024 flows)",
    "parse + IPv4 and TCP/UDP checksum",
};

static double run_once(enum mode m, unsigned passes)
{
    np_flow_table ft;
    np_flow_table_init(&ft, slots, sizeof slots / sizeof slots[0]);
    unsigned opts = m == M_PARSE_IPCSUM ? NP_OPT_IP_CSUM
                  : m == M_PARSE_ALLCSUM ? (NP_OPT_IP_CSUM | NP_OPT_L4_CSUM) : 0;
    uint64_t acc = 0;
    np_packet p;
    double t0 = now_ns();
    for (unsigned r = 0; r < passes; r++) {
        for (unsigned i = 0; i < NFRAMES; i++) {
            np_err e = np_parse_eth(arena + off[i], len[i], &p, opts);
            acc += (uint64_t)e + p.payload_len + p.layers + p.flags;
            if (m == M_PARSE_FLOW) {
                unsigned ev;
                np_flow_update(&ft, &p, (uint64_t)r * NFRAMES + i, &ev);
                acc += ev;
            }
        }
    }
    double t1 = now_ns();
    sink += acc;
    return (t1 - t0) / ((double)passes * NFRAMES);
}

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv)
{
    int runs = argc > 1 ? atoi(argv[1]) : 7;
    int cpu = argc > 2 ? atoi(argv[2]) : 1;
    if (runs < 1 || runs > 101)
        runs = 7;

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    int pinned = sched_setaffinity(0, sizeof set, &set) == 0;

    /* Build the frame set: kinds interleaved by weight, deterministic order. */
    unsigned total_w = 0;
    for (size_t k = 0; k < sizeof kinds / sizeof kinds[0]; k++)
        total_w += kinds[k].weight;
    arena = malloc((size_t)NFRAMES * 1600);
    if (!arena)
        return 1;
    size_t pos = 0;
    uint64_t bytes = 0;
    unsigned counts[8] = {0};
    uint64_t lcg = 12345;
    for (uint32_t i = 0; i < NFRAMES; i++) {
        lcg = lcg * 6364136223846793005ull + 1442695040888963407ull;
        unsigned pick = (unsigned)(lcg >> 33) % total_w;
        int k = 0;
        while (pick >= kinds[k].weight) {
            pick -= kinds[k].weight;
            k++;
        }
        size_t n = build_kind(k, i, arena + pos, 1600);
        off[i] = (uint32_t)pos;
        len[i] = (uint32_t)n;
        pos += (n + 63) & ~(size_t)63; /* each frame starts on a cache line, as in a NIC ring */
        bytes += n;
        counts[k]++;
    }

    printf("netparse benchmark: %d frames, mean frame %.1f B, %d runs per mode, "
           "cpu %d (%s)\n",
           NFRAMES, (double)bytes / NFRAMES, runs, cpu, pinned ? "pinned" : "NOT pinned");
    printf("packet mix:\n");
    for (size_t k = 0; k < sizeof kinds / sizeof kinds[0]; k++)
        printf("  %5.1f%%  %s\n", 100.0 * counts[k] / NFRAMES, kinds[k].name);
    printf("\n%-38s %10s %10s %10s %10s\n", "mode", "Mpps(med)", "ns/pkt med", "min",
           "max");

    for (int m = 0; m < 4; m++) {
        /* Calibrate passes so one run takes roughly 0.3 s. */
        run_once((enum mode)m, 20);
        double est = run_once((enum mode)m, 50);
        unsigned passes = (unsigned)(0.3e9 / (est * NFRAMES));
        if (passes < 10)
            passes = 10;
        double v[101];
        for (int r = 0; r < runs; r++)
            v[r] = run_once((enum mode)m, passes);
        qsort(v, (size_t)runs, sizeof v[0], cmp_d);
        double med = v[runs / 2];
        printf("%-38s %10.1f %10.2f %10.2f %10.2f\n", mode_names[m], 1000.0 / med, med,
               v[0], v[runs - 1]);
    }
    free(arena);
    return (int)(sink & 0);
}
