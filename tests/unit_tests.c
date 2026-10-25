/* SPDX-License-Identifier: MIT
 * Unit tests for libnetparse. Packets under test are copied into heap
 * buffers of exactly caplen bytes so that, under ASan, any read past the
 * end of the capture is reported as a heap-buffer-overflow. */
#define _POSIX_C_SOURCE 200809L
#include "netparse/flow.h"
#include "netparse/netparse.h"
#include "netparse/pcap.h"
#include "pktbuild.h"
#include "test.h"

#include <stdlib.h>

static uint8_t frame[4096];

/* Parse a copy of buf[0..len) held in an exact-size heap allocation. */
static np_err parse_exact(const uint8_t *buf, size_t len, np_packet *p, unsigned opts)
{
    uint8_t *copy = malloc(len ? len : 1);
    if (!copy)
        abort();
    memcpy(copy, buf, len);
    np_err e = np_parse_eth(copy, len, p, opts);
    /* Pointers into the copy must not be used after free. */
    p->data = NULL;
    free(copy);
    return e;
}

static const uint8_t OPTS_SYN[] = {
    2, 4, 0x05, 0xb4,           /* MSS 1460 */
    4, 2,                       /* SACK permitted */
    8, 10, 0, 0, 0, 1, 0, 0, 0, 0, /* TS val 1 ecr 0 */
    1,                          /* NOP */
    3, 3, 7                     /* wscale 7 */
};

/* ---- checksum -------------------------------------------------------- */

static void test_checksum_rfc1071(void)
{
    /* RFC 1071 section 3 example: sum = ddf2 */
    static const uint8_t d[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    CHECK_EQ(np_csum_fold(np_csum_partial(d, sizeof d, 0)), 0xddf2);
    /* Odd length pads with zero. */
    static const uint8_t o[] = {0x01, 0x02, 0x03};
    CHECK_EQ(np_csum_fold(np_csum_partial(o, 3, 0)), 0x0402);
    CHECK_EQ(np_csum_fold(0x1ffff), 1);
}

/* ---- Ethernet / VLAN --------------------------------------------------- */

static void test_eth_short(void)
{
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_SYN, 0);
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    for (size_t i = 0; i < 14; i++)
        CHECK_EQ(parse_exact(frame, i, &p, 0), NP_ERR_TRUNC_ETH);
    CHECK(n > 14);
    CHECK_EQ(np_parse_eth(NULL, 10, &p, 0), NP_ERR_NULL);
    CHECK_EQ(np_parse_eth(frame, 10, NULL, 0), NP_ERR_NULL);
}

static void test_eth_non_ip(void)
{
    struct pb_spec s = pb_tcp4(1, 0, 0, 0);
    s.ethertype = 0x0806; /* ARP */
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK);
    CHECK_EQ(p.layers, NP_L_ETH);
    CHECK_EQ(p.ethertype, 0x0806);
    /* 802.3 length field */
    s.ethertype = 0x002e;
    n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK);
    CHECK_EQ(p.layers, NP_L_ETH);
}

static void test_vlan_single(void)
{
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_SYN, 0);
    s.nvlan = 1;
    s.vlan_tci[0] = (5u << 13) | (1u << 12) | 100; /* PCP 5, DEI 1, VID 100 */
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK);
    CHECK(p.layers & NP_L_VLAN);
    CHECK_EQ(p.vlan_count, 1);
    CHECK_EQ(p.vlan_tpid[0], NP_ETHERTYPE_VLAN);
    CHECK_EQ(p.vlan_tci[0] & 0xfff, 100);
    CHECK_EQ(p.vlan_tci[0] >> 13, 5);
    CHECK_EQ(p.l3_off, 18);
    CHECK(p.layers & NP_L_TCP);
}

static void test_vlan_qinq(void)
{
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_SYN, 10);
    s.nvlan = 2;
    s.vlan_tpid[0] = NP_ETHERTYPE_QINQ;
    s.vlan_tci[0] = 300;
    s.vlan_tpid[1] = NP_ETHERTYPE_VLAN;
    s.vlan_tci[1] = 42;
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK);
    CHECK_EQ(p.vlan_count, 2);
    CHECK_EQ(p.vlan_tpid[0], NP_ETHERTYPE_QINQ);
    CHECK_EQ(p.vlan_tci[0], 300);
    CHECK_EQ(p.vlan_tci[1], 42);
    CHECK_EQ(p.l3_off, 22);
    CHECK_EQ(p.payload_len, 10);
    /* Old 0x9100 outer tag works too. */
    s.vlan_tpid[0] = NP_ETHERTYPE_QINQ_OLD;
    n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK);
    CHECK_EQ(p.vlan_count, 2);
}

static void test_vlan_too_deep(void)
{
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_SYN, 0);
    s.nvlan = 3;
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_VLAN_DEPTH);
    CHECK_EQ(p.vlan_count, 2);
    /* Truncated tag */
    s.nvlan = 1;
    pb_build(&s, frame, sizeof frame);
    for (size_t len = 14; len < 18; len++)
        CHECK_EQ(parse_exact(frame, len, &p, 0), NP_ERR_TRUNC_VLAN);
}

/* ---- IPv4 ------------------------------------------------------------ */

static void test_ipv4_basic(void)
{
    struct pb_spec s = pb_tcp4(1000, 2000, NP_TCP_ACK | NP_TCP_PSH, 100);
    s.ip_id = 0x1234;
    s.ttl = 17;
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_IP_CSUM | NP_OPT_L4_CSUM), NP_OK);
    CHECK_EQ(p.layers, NP_L_ETH | NP_L_IPV4 | NP_L_TCP);
    CHECK_EQ(p.flags, 0);
    CHECK_EQ(p.ip4.src, 0x0a000001);
    CHECK_EQ(p.ip4.dst, 0x0a000002);
    CHECK_EQ(p.ip4.id, 0x1234);
    CHECK_EQ(p.ip_ttl, 17);
    CHECK_EQ(p.ip4.df, 1);
    CHECK_EQ(p.ip4.mf, 0);
    CHECK_EQ(p.ip4.tot_len, 20 + 20 + 100);
    CHECK_EQ(p.l3_off, 14);
    CHECK_EQ(p.l4_off, 34);
    CHECK_EQ(p.payload_off, 54);
    CHECK_EQ(p.payload_len, 100);
    CHECK_EQ(p.payload_caplen, 100);
}

static void test_ipv4_bad_header(void)
{
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_SYN, 0);
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    uint8_t f[128];
    memcpy(f, frame, n);
    f[14] = 0x55; /* version 5 */
    CHECK_EQ(parse_exact(f, n, &p, 0), NP_ERR_IPV4_VERSION);
    CHECK(!(p.layers & NP_L_IPV4));
    f[14] = 0x44; /* ihl 4 */
    CHECK_EQ(parse_exact(f, n, &p, 0), NP_ERR_IPV4_IHL);
    f[14] = 0x4f; /* ihl 15 = 60 bytes > captured */
    CHECK_EQ(parse_exact(f, n, &p, 0), NP_ERR_TRUNC_IPV4);
    memcpy(f, frame, n);
    f[16] = 0;
    f[17] = 19; /* total length < header */
    CHECK_EQ(parse_exact(f, n, &p, 0), NP_ERR_IPV4_TOTLEN);
}

static void test_ipv4_checksum_flag(void)
{
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_SYN, 0);
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    frame[24] ^= 0xff; /* corrupt IPv4 checksum */
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_IP_CSUM), NP_OK);
    CHECK(p.flags & NP_F_IP_CSUM_BAD);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK); /* not verified */
    CHECK(!(p.flags & NP_F_IP_CSUM_BAD));
}

static void test_ipv4_options(void)
{
    /* NOP, Record Route (len 7, ptr 4, one empty slot), EOL */
    static const uint8_t rr[] = {1, 7, 7, 4, 0, 0, 0, 0};
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_SYN, 0);
    s.ipopts = rr;
    s.ipopts_len = sizeof rr;
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_IP_CSUM | NP_OPT_L4_CSUM), NP_OK);
    CHECK(p.flags & NP_F_IP_OPTIONS);
    CHECK(!(p.flags & (NP_F_IP_CSUM_BAD | NP_F_L4_CSUM_BAD)));
    CHECK_EQ(p.ip4.ihl, 7);
    CHECK_EQ(p.ip4.opt_len, 8);
    CHECK_EQ(p.l4_off, 14 + 28);

    static const uint8_t bad_len0[] = {7, 0, 0, 0};
    static const uint8_t bad_len1[] = {1, 1, 7, 1};
    static const uint8_t overrun[] = {1, 7, 9, 0};
    static const uint8_t lone[] = {1, 1, 1, 0x44};
    const uint8_t *bad[] = {bad_len0, bad_len1, overrun, lone};
    for (int i = 0; i < 4; i++) {
        s.ipopts = bad[i];
        s.ipopts_len = 4;
        n = pb_build(&s, frame, sizeof frame);
        CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_IPV4_OPTIONS);
    }
    /* EOL ends the list: garbage after it is ignored. */
    static const uint8_t eol[] = {0, 0xff, 0xff, 0xff};
    s.ipopts = eol;
    n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK);
}

static void test_ipv4_fragments(void)
{
    np_packet p;
    /* First fragment: MF set, offset 0, TCP header still parsed. */
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_ACK, 64);
    s.frag = 0x2000;
    size_t n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK(p.flags & NP_F_IP_FRAG);
    CHECK(!(p.flags & NP_F_IP_FRAG_LATER));
    CHECK(p.layers & NP_L_TCP);
    CHECK(!(p.flags & NP_F_L4_CSUM_BAD)); /* not verified on fragments */
    CHECK_EQ(p.ip4.mf, 1);

    /* Later fragment: offset 185*8 = 1480, no L4 parse. */
    s.frag = 185;
    n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK);
    CHECK(p.flags & NP_F_IP_FRAG_LATER);
    CHECK(!(p.layers & NP_L_TCP));
    CHECK_EQ(p.ip4.frag_off, 1480);
    CHECK_EQ(p.payload_off, 34);
    CHECK_EQ(p.payload_len, 20 + 64);

    /* Ping of death: offset 8189*8 + payload > 65535. */
    s.frag = 0x1fff;
    n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_IPV4_FRAG);

    /* UDP first fragment: udp.len describes the reassembled datagram. */
    s = pb_tcp4(0, 0, 0, 100);
    s.proto = NP_IPPROTO_UDP;
    s.frag = 0x2000;
    n = pb_build(&s, frame, sizeof frame);
    frame[34 + 4] = 0x10; /* udp len 4096+ > IP payload */
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK);
    CHECK(p.layers & NP_L_UDP);
    CHECK_EQ(p.payload_len, 100);
}

static void test_ipv4_padding_and_truncation(void)
{
    np_packet p;
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_ACK, 0);
    size_t n = pb_build(&s, frame, sizeof frame); /* 54 bytes */
    memset(frame + n, 0, 6);                     /* Ethernet pad to 60 */
    CHECK_EQ(parse_exact(frame, 60, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK(p.flags & NP_F_ETH_PADDED);
    CHECK(!(p.flags & NP_F_L4_CSUM_BAD));
    CHECK_EQ(p.payload_len, 0);

    s.payload_len = 1000;
    n = pb_build(&s, frame, sizeof frame);
    /* snaplen 96: headers present, payload cut. */
    CHECK_EQ(parse_exact(frame, 96, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK(p.flags & NP_F_TRUNCATED);
    CHECK(!(p.flags & NP_F_L4_CSUM_BAD)); /* skipped: incomplete */
    CHECK_EQ(p.payload_len, 1000);
    CHECK_EQ(p.payload_caplen, 96 - 54);
    CHECK(n > 96);
}

/* ---- TCP ------------------------------------------------------------- */

static void test_tcp_syn_options(void)
{
    struct pb_spec s = pb_tcp4(0xfffffff0u, 0, NP_TCP_SYN, 0);
    s.tcpopts = OPTS_SYN;
    s.tcpopts_len = sizeof OPTS_SYN;
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_IP_CSUM | NP_OPT_L4_CSUM), NP_OK);
    CHECK_EQ(p.flags, 0);
    CHECK_EQ(p.tcp.seq, 0xfffffff0u);
    CHECK_EQ(p.tcp.flags, NP_TCP_SYN);
    CHECK_EQ(p.tcp.doff, 10);
    CHECK_EQ(p.tcp.opts.present,
             NP_TCPOPT_MSS | NP_TCPOPT_SACK_OK | NP_TCPOPT_TS | NP_TCPOPT_WSCALE);
    CHECK_EQ(p.tcp.opts.mss, 1460);
    CHECK_EQ(p.tcp.opts.wscale, 7);
    CHECK_EQ(p.tcp.opts.ts_val, 1);
    CHECK_EQ(p.tcp.opts.ts_ecr, 0);
    CHECK_EQ(p.payload_off, 14 + 20 + 40);
}

static void test_tcp_sack_blocks(void)
{
    np_packet p;
    for (unsigned nb = 1; nb <= 4; nb++) {
        uint8_t o[40];
        size_t ol = 0;
        o[ol++] = 1;
        o[ol++] = 1;
        o[ol++] = 5;
        o[ol++] = (uint8_t)(2 + 8 * nb);
        for (unsigned b = 0; b < nb; b++) {
            pb_put32(o + ol, 1000 * (b + 1));
            pb_put32(o + ol + 4, 1000 * (b + 1) + 500);
            ol += 8;
        }
        while (ol % 4)
            o[ol++] = 0;
        struct pb_spec s = pb_tcp4(1, 1, NP_TCP_ACK, 0);
        s.tcpopts = o;
        s.tcpopts_len = ol;
        size_t n = pb_build(&s, frame, sizeof frame);
        CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_L4_CSUM), NP_OK);
        CHECK(p.tcp.opts.present & NP_TCPOPT_SACK);
        CHECK_EQ(p.tcp.opts.sack_count, nb);
        CHECK_EQ(p.tcp.opts.sack[nb - 1].left, 1000 * nb);
        CHECK_EQ(p.tcp.opts.sack[nb - 1].right, 1000 * nb + 500);
    }
}

static void test_tcp_bad_options(void)
{
    static const uint8_t cases[][8] = {
        {2, 3, 5, 0, 0, 0, 0, 0},    /* MSS len 3 */
        {3, 4, 7, 0, 0, 0, 0, 0},    /* wscale len 4 */
        {4, 3, 0, 0, 0, 0, 0, 0},    /* SACK-perm len 3 */
        {5, 6, 0, 0, 0, 0, 0, 0},    /* SACK len 6 (< 10) */
        {8, 6, 0, 0, 0, 0, 0, 0},    /* TS len 6 */
        {99, 0, 0, 0, 0, 0, 0, 0},   /* len 0 */
        {99, 1, 0, 0, 0, 0, 0, 0},   /* len 1 */
        {99, 9, 0, 0, 0, 0, 0, 0},   /* overruns option area */
        {1, 1, 1, 1, 1, 1, 1, 30},   /* kind with no length byte */
    };
    np_packet p;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        struct pb_spec s = pb_tcp4(1, 0, NP_TCP_SYN, 0);
        s.tcpopts = cases[i];
        s.tcpopts_len = 8;
        size_t n = pb_build(&s, frame, sizeof frame);
        CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_TCP_OPTIONS);
        CHECK(!(p.layers & NP_L_TCP));
        CHECK(p.layers & NP_L_IPV4);
    }
    /* SACK with 18 bytes: (18-2) % 8 == 0 -> 2 blocks, fine; 14 is bad. */
    static const uint8_t sack14[16] = {5, 14};
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_ACK, 0);
    s.tcpopts = sack14;
    s.tcpopts_len = 16;
    size_t n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_TCP_OPTIONS);
    /* Unknown option with valid length is accepted and flagged. */
    static const uint8_t unk[4] = {30, 4, 0, 0};
    s.tcpopts = unk;
    s.tcpopts_len = 4;
    n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK);
    CHECK_EQ(p.tcp.opts.present, NP_TCPOPT_UNKNOWN);
}

static void test_tcp_doff(void)
{
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_SYN, 0);
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    frame[34 + 12] = 4 << 4;
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_TCP_DOFF);
    frame[34 + 12] = 6 << 4; /* 24 bytes > 20-byte IP payload */
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_TCP_DOFF);
    /* doff fits the IP payload but the capture was cut short. */
    s.payload_len = 100;
    n = pb_build(&s, frame, sizeof frame);
    frame[34 + 12] = 15 << 4;
    CHECK_EQ(parse_exact(frame, 34 + 40, &p, 0), NP_ERR_TRUNC_TCP);
    CHECK(n > 74);
}

static void test_tcp_checksum_flag(void)
{
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_ACK, 33); /* odd length */
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK(!(p.flags & NP_F_L4_CSUM_BAD));
    frame[n - 1] ^= 1;
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK(p.flags & NP_F_L4_CSUM_BAD);
}

/* ---- UDP ------------------------------------------------------------- */

static void test_udp(void)
{
    struct pb_spec s = pb_tcp4(0, 0, 0, 25);
    s.proto = NP_IPPROTO_UDP;
    s.sport = 5353;
    s.dport = 53;
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK_EQ(p.layers, NP_L_ETH | NP_L_IPV4 | NP_L_UDP);
    CHECK(!(p.flags & NP_F_L4_CSUM_BAD));
    CHECK_EQ(p.udp.sport, 5353);
    CHECK_EQ(p.udp.len, 33);
    CHECK_EQ(p.payload_len, 25);

    /* Checksum 0 = not computed (IPv4): never flagged. */
    frame[40] = frame[41] = 0;
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK(!(p.flags & NP_F_L4_CSUM_BAD));

    /* len < 8 */
    pb_put16(frame + 38, 7);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_UDP_LEN);
    /* len > IP payload */
    pb_put16(frame + 38, 34);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_UDP_LEN);
    /* len < IP payload: payload follows udp.len, rest is trailing junk */
    pb_put16(frame + 38, 20);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK);
    CHECK_EQ(p.payload_len, 12);
    /* IP payload shorter than a UDP header */
    s.payload_len = 0;
    n = pb_build(&s, frame, sizeof frame);
    pb_put16(frame + 16, 20 + 4);
    CHECK_EQ(parse_exact(frame, 14 + 24, &p, 0), NP_ERR_TRUNC_UDP);
}

static void test_other_l4(void)
{
    struct pb_spec s = pb_tcp4(0, 0, 0, 40);
    s.proto = 1; /* ICMP */
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK_EQ(p.layers, NP_L_ETH | NP_L_IPV4);
    CHECK_EQ(p.ip_proto, 1);
    CHECK_EQ(p.payload_off, 34);
    CHECK_EQ(p.payload_len, 40);
}

/* ---- IPv6 ------------------------------------------------------------ */

static struct pb_spec pb_tcp6(size_t payload)
{
    struct pb_spec s = pb_tcp4(7, 9, NP_TCP_ACK, payload);
    s.ipv6 = 1;
    s.src6[0] = 0x20;
    s.src6[1] = 0x01;
    s.src6[2] = 0x0d;
    s.src6[3] = 0xb8;
    s.src6[15] = 1;
    memcpy(s.dst6, s.src6, 16);
    s.dst6[15] = 2;
    return s;
}

static void test_ipv6_basic(void)
{
    struct pb_spec s = pb_tcp6(50);
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK_EQ(p.layers, NP_L_ETH | NP_L_IPV6 | NP_L_TCP);
    CHECK(!(p.flags & NP_F_L4_CSUM_BAD));
    CHECK_EQ(p.ip6.payload_len, 70);
    CHECK_EQ(p.l4_off, 54);
    CHECK_EQ(p.payload_len, 50);
    char buf[64];
    p.data = frame;
    np_fmt_ipv6(frame + p.ip6.src_off, buf, sizeof buf);
    CHECK(strcmp(buf, "2001:db8::1") == 0);

    frame[14] = 0x45;
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_IPV6_VERSION);
    for (size_t len = 14; len < 54; len++)
        CHECK_EQ(parse_exact(frame, len, &p, 0), NP_ERR_TRUNC_IPV6);

    /* UDP over IPv6 with checksum */
    s.proto = NP_IPPROTO_UDP;
    n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK(p.layers & NP_L_UDP);
    CHECK(!(p.flags & NP_F_L4_CSUM_BAD));
}

static void test_ipv6_ext_headers(void)
{
    np_packet p;
    /* Hop-by-hop (8 bytes, PadN) -> Destination options (16 bytes) -> TCP */
    uint8_t ext[24] = {0};
    ext[0] = 60;  /* next: dstopts */
    ext[1] = 0;   /* 8 bytes */
    ext[2] = 1;   /* PadN */
    ext[3] = 4;
    ext[8] = 6;   /* next: TCP */
    ext[9] = 1;   /* 16 bytes */
    ext[10] = 1;
    ext[11] = 12;
    struct pb_spec s = pb_tcp6(10);
    s.ip6ext = ext;
    s.ip6ext_len = sizeof ext;
    s.ip6ext_first = 0;
    size_t n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK_EQ(p.ip6.ext_count, 2);
    CHECK_EQ(p.ip_proto, 6);
    CHECK_EQ(p.l4_off, 14 + 40 + 24);
    CHECK(!(p.flags & NP_F_L4_CSUM_BAD));
    /* Truncate inside each extension header */
    for (size_t len = 54; len < 78; len++)
        CHECK_EQ(parse_exact(frame, len, &p, 0), NP_ERR_TRUNC_IPV6);
    /* Ext header length overruns the payload length */
    frame[14 + 40 + 9] = 200;
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_IPV6_EXTHDR);

    /* Fragment header, offset != 0: no L4 parse */
    uint8_t fh[8] = {6, 0, 0, 0, 0, 0, 0, 77};
    pb_put16(fh + 2, (uint16_t)(1232 | 1)); /* offset 1232, M=1 */
    s.ip6ext = fh;
    s.ip6ext_len = 8;
    s.ip6ext_first = 44;
    n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_OK);
    CHECK(p.flags & NP_F_IP_FRAG);
    CHECK(p.flags & NP_F_IP_FRAG_LATER);
    CHECK(!(p.layers & NP_L_TCP));
    CHECK_EQ(p.ip6.frag_off, 1232);
    CHECK_EQ(p.ip6.frag_id, 77);
    /* First fragment: L4 parsed */
    pb_put16(fh + 2, 1);
    n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK(p.layers & NP_L_TCP);
    CHECK(!(p.flags & NP_F_IP_FRAG_LATER));

    /* Nine chained hop-by-hop headers: over the limit */
    uint8_t chain[72] = {0};
    for (int i = 0; i < 9; i++)
        chain[i * 8] = 0;
    chain[8 * 8 + 0] = 6;
    s.ip6ext = chain;
    s.ip6ext_len = sizeof chain;
    s.ip6ext_first = 0;
    n = pb_build(&s, frame, sizeof frame);
    CHECK_EQ(parse_exact(frame, n, &p, 0), NP_ERR_IPV6_EXTHDR);
}

static void test_parse_ip_raw(void)
{
    struct pb_spec s = pb_tcp4(5, 6, NP_TCP_ACK, 3);
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(np_parse_ip(frame + 14, n - 14, &p, NP_OPT_L4_CSUM), NP_OK);
    CHECK_EQ(p.layers, NP_L_IPV4 | NP_L_TCP);
    CHECK_EQ(p.l3_off, 0);
    CHECK_EQ(p.payload_len, 3);
    CHECK_EQ(np_parse_ip(frame, 0, &p, 0), NP_ERR_TRUNC_IPV4);
    struct pb_spec s6 = pb_tcp6(0);
    n = pb_build(&s6, frame, sizeof frame);
    CHECK_EQ(np_parse_ip(frame + 14, n - 14, &p, 0), NP_OK);
    CHECK(p.layers & NP_L_IPV6);
}

/* ---- Truncation at every byte offset ---------------------------------- */

/* For a well-formed frame, every prefix must either fail with a truncation
 * error (if it ends inside a header) or parse OK with NP_F_TRUNCATED. No
 * prefix may read out of bounds (checked by ASan via exact-size buffers). */
static void sweep_prefixes(const uint8_t *f, size_t n, size_t hdr_end)
{
    np_packet full;
    CHECK_EQ(parse_exact(f, n, &full, NP_OPT_IP_CSUM | NP_OPT_L4_CSUM), NP_OK);
    for (size_t len = 0; len <= n; len++) {
        np_packet p;
        np_err e = parse_exact(f, len, &p, NP_OPT_IP_CSUM | NP_OPT_L4_CSUM);
        if (len < hdr_end) {
            CHECK(e == NP_ERR_TRUNC_ETH || e == NP_ERR_TRUNC_VLAN ||
                  e == NP_ERR_TRUNC_IPV4 || e == NP_ERR_TRUNC_IPV6 ||
                  e == NP_ERR_TRUNC_TCP || e == NP_ERR_TRUNC_UDP);
        } else {
            CHECK_EQ(e, NP_OK);
            CHECK_EQ(p.layers, full.layers);
            CHECK_EQ(p.payload_len, full.payload_len);
            CHECK_EQ(p.payload_caplen, len - hdr_end);
            CHECK_EQ(!!(p.flags & NP_F_TRUNCATED), len < n);
        }
    }
}

static void test_truncation_every_offset(void)
{
    struct pb_spec s = pb_tcp4(1, 2, NP_TCP_SYN | NP_TCP_ACK, 64);
    s.nvlan = 2;
    s.vlan_tpid[0] = NP_ETHERTYPE_QINQ;
    s.tcpopts = OPTS_SYN;
    s.tcpopts_len = sizeof OPTS_SYN;
    static const uint8_t rr[] = {1, 7, 7, 4, 0, 0, 0, 0};
    s.ipopts = rr;
    s.ipopts_len = sizeof rr;
    size_t n = pb_build(&s, frame, sizeof frame);
    sweep_prefixes(frame, n, 22 + 28 + 40);

    struct pb_spec u = pb_tcp4(0, 0, 0, 30);
    u.proto = NP_IPPROTO_UDP;
    n = pb_build(&u, frame, sizeof frame);
    sweep_prefixes(frame, n, 14 + 20 + 8);

    struct pb_spec v6 = pb_tcp6(40);
    uint8_t ext[8] = {6, 0, 1, 4, 0, 0, 0, 0};
    v6.ip6ext = ext;
    v6.ip6ext_len = 8;
    v6.ip6ext_first = 0;
    v6.tcpopts = OPTS_SYN;
    v6.tcpopts_len = sizeof OPTS_SYN;
    n = pb_build(&v6, frame, sizeof frame);
    sweep_prefixes(frame, n, 14 + 48 + 40);
}

/* ---- Random mutation robustness -------------------------------------- */

static uint64_t rng_state = 0x243f6a8885a308d3ull;
static uint32_t rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)rng_state;
}

static void test_random_mutations(void)
{
    struct pb_spec s = pb_tcp4(1, 2, NP_TCP_SYN, 32);
    s.nvlan = 1;
    s.tcpopts = OPTS_SYN;
    s.tcpopts_len = sizeof OPTS_SYN;
    uint8_t base[256];
    size_t n = pb_build(&s, base, sizeof base);
    unsigned ok = 0, err = 0;
    for (int it = 0; it < 100000; it++) {
        uint8_t m[256];
        memcpy(m, base, n);
        int flips = 1 + (int)(rng() % 4);
        for (int k = 0; k < flips; k++)
            m[rng() % n] = (uint8_t)rng();
        size_t len = rng() % (n + 1);
        np_packet p;
        np_err e = parse_exact(m, len, &p, NP_OPT_IP_CSUM | NP_OPT_L4_CSUM);
        CHECK((unsigned)e < NP_ERR__COUNT);
        if (e == NP_OK) {
            ok++;
            /* Offsets and lengths must stay inside the capture. */
            if (p.layers & (NP_L_TCP | NP_L_UDP))
                CHECK((size_t)p.payload_off + p.payload_caplen <= len);
        } else {
            err++;
        }
    }
    CHECK(ok > 0);
    CHECK(err > 0);
}

static void test_strerror(void)
{
    for (int i = 0; i < NP_ERR__COUNT; i++)
        CHECK(np_strerror((np_err)i) != NULL && np_strerror((np_err)i)[0]);
    CHECK(strcmp(np_strerror((np_err)999), "unknown error") == 0);
    for (int i = 0; i <= NP_PCAP_ERR_IO; i++)
        CHECK(np_pcap_strerror((np_pcap_err)i)[0]);
}

static void test_fmt(void)
{
    char b[64];
    np_fmt_ipv4(0xc0a80001, b, sizeof b);
    CHECK(strcmp(b, "192.168.0.1") == 0);
    uint8_t a[16] = {0};
    a[15] = 1;
    np_fmt_ipv6(a, b, sizeof b);
    CHECK(strcmp(b, "::1") == 0);
}

/* ---- pcap reader ----------------------------------------------------- */

static size_t mk_pcap(uint8_t *out, int big_endian, int nsec, const uint8_t *pkt,
                      uint32_t pktlen, int nrec)
{
    uint32_t magic = nsec ? 0xa1b23c4du : 0xa1b2c3d4u;
    uint32_t hdr[6] = {magic, 2u | (4u << 16), 0, 0, 65535, 1};
    size_t o = 0;
#define PUT32(v)                                                         \
    do {                                                                 \
        uint32_t _v = (v);                                               \
        if (big_endian)                                                  \
            pb_put32(out + o, _v);                                       \
        else {                                                           \
            out[o] = (uint8_t)_v;                                        \
            out[o + 1] = (uint8_t)(_v >> 8);                             \
            out[o + 2] = (uint8_t)(_v >> 16);                            \
            out[o + 3] = (uint8_t)(_v >> 24);                            \
        }                                                                \
        o += 4;                                                          \
    } while (0)
    PUT32(hdr[0]);
    /* version is two 16-bit fields */
    if (big_endian) {
        pb_put16(out + o, 2);
        pb_put16(out + o + 2, 4);
    } else {
        out[o] = 2; out[o + 1] = 0; out[o + 2] = 4; out[o + 3] = 0;
    }
    o += 4;
    PUT32(0);
    PUT32(0);
    PUT32(hdr[4]);
    PUT32(hdr[5]);
    for (int r = 0; r < nrec; r++) {
        PUT32(1700000000u + (uint32_t)r);
        PUT32(nsec ? 123456789u : 123456u);
        PUT32(pktlen);
        PUT32(pktlen + 10);
        memcpy(out + o, pkt, pktlen);
        o += pktlen;
    }
#undef PUT32
    return o;
}

static void test_pcap_variants(void)
{
    struct pb_spec s = pb_tcp4(1, 0, NP_TCP_SYN, 0);
    size_t n = pb_build(&s, frame, sizeof frame);
    static uint8_t file[4096];
    for (int be = 0; be < 2; be++)
        for (int ns = 0; ns < 2; ns++) {
            size_t fl = mk_pcap(file, be, ns, frame, (uint32_t)n, 3);
            np_pcap r;
            CHECK_EQ(np_pcap_open_mem(&r, file, fl), NP_PCAP_OK);
            CHECK_EQ(r.swapped, be);
            CHECK_EQ(r.nsec, ns);
            CHECK_EQ(r.linktype, 1);
            CHECK_EQ(r.snaplen, 65535);
            CHECK_EQ(r.ver_minor, 4);
            np_pcap_rec rec;
            for (int i = 0; i < 3; i++) {
                CHECK_EQ(np_pcap_next(&r, &rec), NP_PCAP_OK);
                CHECK_EQ(rec.ts_sec, 1700000000u + (uint32_t)i);
                CHECK_EQ(rec.ts_nsec, ns ? 123456789u : 123456000u);
                CHECK_EQ(rec.caplen, n);
                CHECK_EQ(rec.origlen, n + 10);
                CHECK(memcmp(rec.data, frame, n) == 0);
            }
            CHECK_EQ(np_pcap_next(&r, &rec), NP_PCAP_EOF);
            /* Truncation at every byte of the last record */
            for (size_t cut = fl - n - 16; cut < fl; cut++) {
                CHECK_EQ(np_pcap_open_mem(&r, file, cut), NP_PCAP_OK);
                np_pcap_err e;
                int recs = 0;
                while ((e = np_pcap_next(&r, &rec)) == NP_PCAP_OK)
                    recs++;
                CHECK_EQ(recs, 2);
                CHECK_EQ(e, cut == fl - n - 16 ? NP_PCAP_EOF
                            : cut < fl - n     ? NP_PCAP_ERR_TRUNC_HDR
                                               : NP_PCAP_ERR_TRUNC_DATA);
            }
        }
}

static void test_pcap_errors(void)
{
    static uint8_t file[512];
    np_pcap r;
    np_pcap_rec rec;
    size_t fl = mk_pcap(file, 0, 0, frame, 60, 1);
    for (size_t i = 0; i < 24; i++)
        CHECK_EQ(np_pcap_open_mem(&r, file, i), NP_PCAP_ERR_SHORT);
    CHECK_EQ(np_pcap_open_mem(NULL, file, fl), NP_PCAP_ERR_NULL);
    CHECK_EQ(np_pcap_open_mem(&r, NULL, 5), NP_PCAP_ERR_NULL);
    /* Header-only file: immediate EOF */
    CHECK_EQ(np_pcap_open_mem(&r, file, 24), NP_PCAP_OK);
    CHECK_EQ(np_pcap_next(&r, &rec), NP_PCAP_EOF);
    CHECK_EQ(np_pcap_next(NULL, &rec), NP_PCAP_ERR_NULL);
    /* pcapng magic */
    uint8_t ng[24] = {0x0a, 0x0d, 0x0d, 0x0a};
    CHECK_EQ(np_pcap_open_mem(&r, ng, 24), NP_PCAP_ERR_MAGIC);
    /* bad major version */
    file[4] = 3;
    CHECK_EQ(np_pcap_open_mem(&r, file, fl), NP_PCAP_ERR_VERSION);
    file[4] = 2;
    /* caplen above the 256 KiB ceiling */
    file[24 + 8] = 0;
    file[24 + 9] = 0;
    file[24 + 10] = 0x10;
    file[24 + 11] = 0;
    CHECK_EQ(np_pcap_open_mem(&r, file, fl), NP_PCAP_OK);
    CHECK_EQ(np_pcap_next(&r, &rec), NP_PCAP_ERR_CAPLEN);
    /* bogus microsecond value clamps instead of wrapping */
    fl = mk_pcap(file, 0, 0, frame, 60, 1);
    file[24 + 4] = 0xff;
    file[24 + 5] = 0xff;
    file[24 + 6] = 0xff;
    file[24 + 7] = 0xff;
    CHECK_EQ(np_pcap_open_mem(&r, file, fl), NP_PCAP_OK);
    CHECK_EQ(np_pcap_next(&r, &rec), NP_PCAP_OK);
    CHECK_EQ(rec.ts_nsec, 0xffffffffu);
}

static void test_pcap_file(void)
{
    np_pcap_file f;
    CHECK_EQ(np_pcap_map_file("/nonexistent/x.pcap", &f), NP_PCAP_ERR_IO);
    CHECK_EQ(np_pcap_map_file(NULL, &f), NP_PCAP_ERR_NULL);
    char path[] = "/tmp/np_unit_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0)
        return;
    static uint8_t file[512];
    size_t fl = mk_pcap(file, 1, 1, frame, 60, 2);
    FILE *fp = fdopen(fd, "wb");
    fwrite(file, 1, fl, fp);
    fclose(fp);
    CHECK_EQ(np_pcap_map_file(path, &f), NP_PCAP_OK);
    CHECK_EQ(f.len, fl);
    CHECK(f.mapped);
    np_pcap r;
    CHECK_EQ(np_pcap_open_mem(&r, f.base, f.len), NP_PCAP_OK);
    np_pcap_unmap_file(&f);
    CHECK(f.base == NULL);
    /* Empty file: success with no mapping; the reader then reports SHORT. */
    fp = fopen(path, "wb");
    fclose(fp);
    CHECK_EQ(np_pcap_map_file(path, &f), NP_PCAP_OK);
    CHECK(f.base == NULL && f.len == 0);
    CHECK_EQ(np_pcap_open_mem(&r, f.base, f.len), NP_PCAP_ERR_SHORT);
    np_pcap_unmap_file(&f);
    remove(path);
}

/* ---- Flow tracker ---------------------------------------------------- */

static np_flow slots[64];

struct seg {
    int dir; /* 0: client->server */
    uint32_t seq, ack;
    uint8_t flags;
    size_t len;
    uint16_t win;
    uint64_t ts_us;
};

static unsigned feed(np_flow_table *t, const struct seg *sg, np_flow **out)
{
    struct pb_spec s = pb_tcp4(sg->seq, sg->ack, sg->flags, sg->len);
    s.win = sg->win ? sg->win : 1000;
    if (sg->win == 0xffff)
        s.win = 0;
    if (sg->dir) {
        uint32_t a = s.src4;
        s.src4 = s.dst4;
        s.dst4 = a;
        uint16_t pp = s.sport;
        s.sport = s.dport;
        s.dport = pp;
    }
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(np_parse_eth(frame, n, &p, 0), NP_OK);
    unsigned ev;
    np_flow *f = np_flow_update(t, &p, sg->ts_us * 1000, &ev);
    if (out)
        *out = f;
    return ev;
}

static void test_flow_handshake_inorder(void)
{
    np_flow_table t;
    CHECK_EQ(np_flow_table_init(&t, slots, 64), 0);
    np_flow *f = NULL;
    const struct seg segs[] = {
        {0, 100, 0, NP_TCP_SYN, 0, 0, 0},
        {1, 500, 101, NP_TCP_SYN | NP_TCP_ACK, 0, 0, 10},
        {0, 101, 501, NP_TCP_ACK, 0, 0, 20},
        {0, 101, 501, NP_TCP_ACK, 100, 0, 30},
        {0, 201, 501, NP_TCP_ACK, 100, 0, 40},
        {1, 501, 301, NP_TCP_ACK, 0, 0, 50},
        {0, 301, 501, NP_TCP_FIN | NP_TCP_ACK, 0, 0, 60},
    };
    unsigned evs = 0;
    for (size_t i = 0; i < sizeof segs / sizeof segs[0]; i++)
        evs |= feed(&t, &segs[i], &f);
    CHECK(f != NULL);
    if (!f)
        return;
    CHECK_EQ(t.count, 1);
    CHECK_EQ(evs & ~NP_FEV_NEW_FLOW, 0);
    const np_flow_dir *c = &f->dir[f->initiator], *sv = &f->dir[f->initiator ^ 1];
    CHECK_EQ(c->packets, 5);
    CHECK_EQ(sv->packets, 2);
    CHECK_EQ(c->payload_bytes, 200);
    CHECK_EQ(c->bytes, 5 * 40 + 200);
    CHECK_EQ(c->retransmits + c->out_of_order + c->dup_acks, 0);
    CHECK_EQ(c->syn, 1);
    CHECK_EQ(c->fin, 1);
    CHECK_EQ(c->max_seq_end, 302);
    CHECK_EQ(c->wscale, 0xff);
}

static void test_flow_retrans_ooo(void)
{
    np_flow_table t;
    np_flow_table_init(&t, slots, 64);
    np_flow *f = NULL;
    unsigned ev;
    struct seg sg[] = {
        {0, 1000, 1, NP_TCP_ACK, 100, 0, 0},     /* [1000,1100) */
        {0, 1200, 1, NP_TCP_ACK, 100, 0, 100},   /* gap [1100,1200) */
        {0, 1100, 1, NP_TCP_ACK, 100, 0, 200},   /* fills gap, 100us: OOO */
        {0, 1000, 1, NP_TCP_ACK, 100, 0, 300},   /* already seen: retrans */
        {0, 1400, 1, NP_TCP_ACK, 100, 0, 400},   /* gap [1300,1400) */
        {0, 1300, 1, NP_TCP_ACK, 100, 0, 50000}, /* fills gap after 49.6ms: retrans */
        {0, 1450, 1, NP_TCP_ACK, 100, 0, 50100}, /* partial overlap: retrans */
    };
    CHECK_EQ(feed(&t, &sg[0], &f) & NP_FEV_NEW_FLOW, NP_FEV_NEW_FLOW);
    CHECK_EQ(feed(&t, &sg[1], &f), NP_FEV_GAP);
    CHECK_EQ(f->dir[f->initiator].nholes, 1);
    CHECK_EQ(feed(&t, &sg[2], &f), NP_FEV_OOO);
    CHECK_EQ(f->dir[f->initiator].nholes, 0);
    CHECK_EQ(feed(&t, &sg[3], &f), NP_FEV_RETRANS);
    CHECK_EQ(feed(&t, &sg[4], &f), NP_FEV_GAP);
    CHECK_EQ(feed(&t, &sg[5], &f), NP_FEV_RETRANS);
    ev = feed(&t, &sg[6], &f);
    CHECK_EQ(ev, NP_FEV_RETRANS);
    const np_flow_dir *c = &f->dir[f->initiator];
    CHECK_EQ(c->out_of_order, 1);
    CHECK_EQ(c->retransmits, 3);
    CHECK_EQ(c->max_seq_end, 1550);
    CHECK_EQ(c->gaps, 2);
}

static void test_flow_hole_split_and_ack(void)
{
    np_flow_table t;
    np_flow_table_init(&t, slots, 64);
    np_flow *f = NULL;
    struct seg a = {0, 0, 1, NP_TCP_ACK, 100, 0, 0};
    feed(&t, &a, &f);
    a.seq = 1000; /* hole [100,1000) */
    feed(&t, &a, &f);
    a.seq = 400; /* inside: splits into [100,400) and [500,1000) */
    CHECK_EQ(feed(&t, &a, &f), NP_FEV_OOO);
    CHECK_EQ(f->dir[f->initiator].nholes, 2);
    /* Receiver ACKs 600: [100,400) dropped, [500,1000) trimmed to [600,1000) */
    struct seg ack = {1, 1, 600, NP_TCP_ACK, 0, 0, 1};
    feed(&t, &ack, &f);
    const np_flow_dir *c = &f->dir[f->initiator];
    CHECK_EQ(c->nholes, 1);
    CHECK_EQ(c->holes[0].left, 600);
    CHECK_EQ(c->holes[0].right, 1000);
    /* Data below the ack is a retransmission now */
    a.seq = 200;
    CHECK_EQ(feed(&t, &a, &f), NP_FEV_RETRANS);
    /* Fill the rest: hole removed entirely */
    a.seq = 600;
    a.len = 400;
    CHECK_EQ(feed(&t, &a, &f), NP_FEV_OOO);
    CHECK_EQ(f->dir[f->initiator].nholes, 0);
}

static void test_flow_hole_partial_overlap(void)
{
    np_flow_table t;
    np_flow_table_init(&t, slots, 64);
    np_flow *f = NULL;
    struct seg a = {0, 0, 1, NP_TCP_ACK, 100, 0, 0};
    feed(&t, &a, &f);
    a.seq = 1000; /* hole [100,1000) */
    feed(&t, &a, &f);
    a.seq = 50; /* [50,150): overlaps seen data and the hole's left edge */
    CHECK_EQ(feed(&t, &a, &f), NP_FEV_RETRANS);
    const np_flow_dir *c = &f->dir[f->initiator];
    CHECK_EQ(c->nholes, 1);
    CHECK_EQ(c->holes[0].left, 150);
    a.seq = 950; /* [950,1050): overlaps the hole's right edge */
    CHECK_EQ(feed(&t, &a, &f), NP_FEV_RETRANS);
    CHECK_EQ(c->holes[0].left, 150);
    CHECK_EQ(c->holes[0].right, 950);
}

static void test_flow_hole_overflow(void)
{
    np_flow_table t;
    np_flow_table_init(&t, slots, 64);
    np_flow *f = NULL;
    struct seg a = {0, 0, 1, NP_TCP_ACK, 10, 0, 0};
    for (int i = 0; i < NP_FLOW_MAX_HOLES + 3; i++) {
        a.seq = (uint32_t)i * 20;
        feed(&t, &a, &f);
    }
    const np_flow_dir *c = &f->dir[f->initiator];
    CHECK_EQ(c->nholes, NP_FLOW_MAX_HOLES);
    CHECK_EQ(c->holes_lost, 2);
}

static void test_flow_dupack_sack_zwin_keepalive(void)
{
    np_flow_table t;
    np_flow_table_init(&t, slots, 64);
    np_flow *f = NULL;
    struct seg d = {0, 1, 1, NP_TCP_ACK, 100, 0, 0};
    feed(&t, &d, &f);
    struct seg ack = {1, 1, 101, NP_TCP_ACK, 0, 500, 1};
    CHECK_EQ(feed(&t, &ack, &f) & ~NP_FEV_NEW_FLOW, 0);
    CHECK_EQ(feed(&t, &ack, &f), NP_FEV_DUP_ACK);
    CHECK_EQ(feed(&t, &ack, &f), NP_FEV_DUP_ACK);
    ack.win = 600; /* window update: not a dup ack */
    CHECK_EQ(feed(&t, &ack, &f), 0);
    ack.win = 0xffff; /* encoded as window 0 by feed() */
    CHECK_EQ(feed(&t, &ack, &f), NP_FEV_ZERO_WIN);
    CHECK_EQ(feed(&t, &ack, &f), NP_FEV_ZERO_WIN); /* repeated: not a dup ack */
    /* keep-alive: seq = max_seq_end - 1, 0 or 1 byte */
    struct seg ka = {0, 100, 1, NP_TCP_ACK, 0, 0, 2};
    CHECK_EQ(feed(&t, &ka, &f), NP_FEV_KEEPALIVE);
    ka.len = 1;
    CHECK_EQ(feed(&t, &ka, &f), NP_FEV_KEEPALIVE);

    /* SACK option from the receiver */
    uint8_t o[12] = {1, 1, 5, 10};
    pb_put32(o + 4, 201);
    pb_put32(o + 8, 301);
    struct pb_spec s = pb_tcp4(1, 101, NP_TCP_ACK, 0);
    s.tcpopts = o;
    s.tcpopts_len = sizeof o;
    s.src4 = 0x0a000002;
    s.dst4 = 0x0a000001;
    s.sport = 80;
    s.dport = 40000;
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    CHECK_EQ(np_parse_eth(frame, n, &p, 0), NP_OK);
    unsigned ev;
    f = np_flow_update(&t, &p, 5000, &ev);
    CHECK(ev & NP_FEV_SACK);
    const np_flow_dir *sv = &f->dir[f->initiator ^ 1];
    CHECK_EQ(sv->sack_packets, 1);
    CHECK_EQ(sv->sack_blocks, 1);
    CHECK_EQ(sv->dup_acks, 2);
    CHECK_EQ(sv->zero_windows, 2);
    CHECK_EQ(f->dir[f->initiator].keepalives, 2);
}

static void test_flow_syn_retrans_and_wrap(void)
{
    np_flow_table t;
    np_flow_table_init(&t, slots, 64);
    np_flow *f = NULL;
    struct pb_spec s = pb_tcp4(0xffffffffu, 0, NP_TCP_SYN, 0);
    s.tcpopts = OPTS_SYN;
    s.tcpopts_len = sizeof OPTS_SYN;
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    np_parse_eth(frame, n, &p, 0);
    unsigned ev;
    f = np_flow_update(&t, &p, 0, &ev);
    f = np_flow_update(&t, &p, 1000000000, &ev); /* SYN again after 1 s */
    CHECK_EQ(ev, NP_FEV_RETRANS);
    CHECK_EQ(f->dir[f->initiator].wscale, 7);
    CHECK_EQ(f->dir[f->initiator].mss, 1460);
    CHECK_EQ(f->dir[f->initiator].max_seq_end, 0);
    /* Data across the 2^32 wrap stays in order. */
    struct seg d = {0, 0, 1, NP_TCP_ACK, 100, 0, 2000000};
    CHECK_EQ(feed(&t, &d, &f), 0);
    CHECK_EQ(f->dir[f->initiator].max_seq_end, 100);
    CHECK_EQ(f->dir[f->initiator].retransmits, 1);
}

static void test_flow_rst_and_udp(void)
{
    np_flow_table t;
    np_flow_table_init(&t, slots, 64);
    np_flow *f = NULL;
    struct seg r = {1, 5, 0, NP_TCP_RST, 0, 0, 0};
    unsigned ev = feed(&t, &r, &f);
    CHECK_EQ(ev, NP_FEV_NEW_FLOW); /* window 1000 so no zero-window */
    CHECK_EQ(f->dir[f->initiator].rst, 1);
    CHECK_EQ(f->initiator, f->initiator); /* server sent first */

    struct pb_spec u = pb_tcp4(0, 0, 0, 10);
    u.proto = NP_IPPROTO_UDP;
    size_t n = pb_build(&u, frame, sizeof frame);
    np_packet p;
    np_parse_eth(frame, n, &p, 0);
    f = np_flow_update(&t, &p, 0, &ev);
    CHECK(f && (ev & NP_FEV_NEW_FLOW));
    CHECK_EQ(f->key.proto, NP_IPPROTO_UDP);
    CHECK_EQ(t.count, 2);
    CHECK(np_flow_lookup(&t, &p) == f);
    /* ICMP: not tracked */
    u.proto = 1;
    n = pb_build(&u, frame, sizeof frame);
    np_parse_eth(frame, n, &p, 0);
    CHECK(np_flow_update(&t, &p, 0, &ev) == NULL);
    CHECK(np_flow_lookup(&t, &p) == NULL);
    CHECK(np_flow_update(NULL, &p, 0, &ev) == NULL);
}

static void test_flow_table_full(void)
{
    np_flow_table t;
    CHECK_EQ(np_flow_table_init(&t, slots, 7), -1);
    CHECK_EQ(np_flow_table_init(&t, slots, 12), -1);
    CHECK_EQ(np_flow_table_init(&t, NULL, 16), -1);
    CHECK_EQ(np_flow_table_init(&t, slots, 16), 0);
    np_packet p;
    unsigned created = 0;
    for (uint16_t port = 1; port <= 40; port++) {
        struct pb_spec s = pb_tcp4(1, 0, NP_TCP_SYN, 0);
        s.sport = port;
        size_t n = pb_build(&s, frame, sizeof frame);
        np_parse_eth(frame, n, &p, 0);
        unsigned ev;
        if (np_flow_update(&t, &p, 0, &ev))
            created++;
    }
    CHECK_EQ(created, 14);
    CHECK_EQ(t.count, 14);
    CHECK_EQ(t.dropped, 26);
    size_t cur = 0, seen = 0;
    while (np_flow_next(&t, &cur))
        seen++;
    CHECK_EQ(seen, 14);
}

static void test_flow_ipv6(void)
{
    np_flow_table t;
    np_flow_table_init(&t, slots, 64);
    struct pb_spec s = pb_tcp6(10);
    size_t n = pb_build(&s, frame, sizeof frame);
    np_packet p;
    np_parse_eth(frame, n, &p, 0);
    unsigned ev;
    np_flow *f = np_flow_update(&t, &p, 0, &ev);
    CHECK(f != NULL);
    CHECK_EQ(f->key.family, 6);
    CHECK_EQ(f->dir[f->initiator].bytes, 40 + 30);
    /* reverse direction maps to same flow */
    struct pb_spec r = s;
    memcpy(r.src6, s.dst6, 16);
    memcpy(r.dst6, s.src6, 16);
    r.sport = s.dport;
    r.dport = s.sport;
    n = pb_build(&r, frame, sizeof frame);
    np_parse_eth(frame, n, &p, 0);
    CHECK(np_flow_update(&t, &p, 0, &ev) == f);
    CHECK_EQ(t.count, 1);
}

int main(void)
{
    RUN(test_checksum_rfc1071);
    RUN(test_eth_short);
    RUN(test_eth_non_ip);
    RUN(test_vlan_single);
    RUN(test_vlan_qinq);
    RUN(test_vlan_too_deep);
    RUN(test_ipv4_basic);
    RUN(test_ipv4_bad_header);
    RUN(test_ipv4_checksum_flag);
    RUN(test_ipv4_options);
    RUN(test_ipv4_fragments);
    RUN(test_ipv4_padding_and_truncation);
    RUN(test_tcp_syn_options);
    RUN(test_tcp_sack_blocks);
    RUN(test_tcp_bad_options);
    RUN(test_tcp_doff);
    RUN(test_tcp_checksum_flag);
    RUN(test_udp);
    RUN(test_other_l4);
    RUN(test_ipv6_basic);
    RUN(test_ipv6_ext_headers);
    RUN(test_parse_ip_raw);
    RUN(test_truncation_every_offset);
    RUN(test_random_mutations);
    RUN(test_strerror);
    RUN(test_fmt);
    RUN(test_pcap_variants);
    RUN(test_pcap_errors);
    RUN(test_pcap_file);
    RUN(test_flow_handshake_inorder);
    RUN(test_flow_retrans_ooo);
    RUN(test_flow_hole_split_and_ack);
    RUN(test_flow_hole_partial_overlap);
    RUN(test_flow_hole_overflow);
    RUN(test_flow_dupack_sack_zwin_keepalive);
    RUN(test_flow_syn_retrans_and_wrap);
    RUN(test_flow_rst_and_udp);
    RUN(test_flow_table_full);
    RUN(test_flow_ipv6);
    return TEST_SUMMARY();
}
