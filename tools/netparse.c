/* SPDX-License-Identifier: MIT
 * netparse CLI: read a pcap (or capture live on Linux with AF_PACKET),
 * print one line per packet and per-flow TCP statistics.
 */
#define _DEFAULT_SOURCE
#include "netparse/flow.h"
#include "netparse/netparse.h"
#include "netparse/pcap.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define FLOW_SLOTS 65536

struct opts {
    const char *file;
    const char *iface;
    int json;
    int quiet;
    int no_flows;
    int no_csum;
    uint64_t count;
};

static volatile sig_atomic_t stop_flag;

static void on_signal(int sig)
{
    (void)sig;
    stop_flag = 1;
}

struct ctx {
    struct opts o;
    np_flow_table ft;
    uint64_t npkts;
    uint64_t errs[NP_ERR__COUNT];
    FILE *out;
};

/* ---- Text output ----------------------------------------------------- */

static void fmt_addr(const np_packet *p, int dst, char *buf, size_t n)
{
    if (p->layers & NP_L_IPV4)
        np_fmt_ipv4(dst ? p->ip4.dst : p->ip4.src, buf, n);
    else
        np_fmt_ipv6(p->data + (dst ? p->ip6.dst_off : p->ip6.src_off), buf, n);
}

static void tcp_flag_str(uint8_t f, char *s)
{
    /* tcpdump letters: S F R P . U E W */
    int i = 0;
    if (f & NP_TCP_SYN) s[i++] = 'S';
    if (f & NP_TCP_FIN) s[i++] = 'F';
    if (f & NP_TCP_RST) s[i++] = 'R';
    if (f & NP_TCP_PSH) s[i++] = 'P';
    if (f & NP_TCP_URG) s[i++] = 'U';
    if (f & NP_TCP_ECE) s[i++] = 'E';
    if (f & NP_TCP_CWR) s[i++] = 'W';
    if (f & NP_TCP_ACK) s[i++] = '.';
    s[i] = 0;
    if (i == 0)
        memcpy(s, "none", 5);
}

static const char *proto_name(uint8_t p)
{
    switch (p) {
    case 1: return "ICMP";
    case 6: return "TCP";
    case 17: return "UDP";
    case 58: return "ICMP6";
    default: return NULL;
    }
}

static void print_events(FILE *o, unsigned ev, int json)
{
    static const struct { unsigned bit; const char *name; } names[] = {
        {NP_FEV_RETRANS, "retransmission"}, {NP_FEV_OOO, "out-of-order"},
        {NP_FEV_DUP_ACK, "dup-ack"},        {NP_FEV_SACK, "sack"},
        {NP_FEV_ZERO_WIN, "zero-window"},   {NP_FEV_KEEPALIVE, "keep-alive"},
    };
    int first = 1;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (!(ev & names[i].bit))
            continue;
        if (json)
            fprintf(o, "%s\"%s\"", first ? "" : ",", names[i].name);
        else
            fprintf(o, " [%s]", names[i].name);
        first = 0;
    }
}

static void print_text(struct ctx *c, const np_packet *p, np_err e,
                       const np_pcap_rec *r, unsigned ev)
{
    FILE *o = c->out;
    char s[64], d[64];
    fprintf(o, "%" PRIu32 ".%06" PRIu32 " ", r->ts_sec, r->ts_nsec / 1000);
    for (unsigned i = 0; i < p->vlan_count; i++)
        fprintf(o, "vlan %u p %u ", p->vlan_tci[i] & 0xfff, p->vlan_tci[i] >> 13);

    if (!(p->layers & (NP_L_IPV4 | NP_L_IPV6))) {
        if (p->layers & NP_L_ETH)
            fprintf(o, "ethertype 0x%04x, length %" PRIu32, p->ethertype, r->origlen);
        else
            fprintf(o, "length %" PRIu32, r->origlen);
        goto tail;
    }
    fmt_addr(p, 0, s, sizeof s);
    fmt_addr(p, 1, d, sizeof d);
    const char *ipname = (p->layers & NP_L_IPV4) ? "IP" : "IP6";
    if (p->layers & NP_L_TCP) {
        char fl[12];
        tcp_flag_str(p->tcp.flags, fl);
        fprintf(o, "%s %s.%u > %s.%u: Flags [%s], seq %" PRIu32, ipname, s,
                p->tcp.sport, d, p->tcp.dport, fl, p->tcp.seq);
        if (p->payload_len)
            fprintf(o, ":%" PRIu32, (uint32_t)(p->tcp.seq + p->payload_len));
        if (p->tcp.flags & NP_TCP_ACK)
            fprintf(o, ", ack %" PRIu32, p->tcp.ack);
        fprintf(o, ", win %u", p->tcp.window);
        const np_tcp_opts *t = &p->tcp.opts;
        if (t->present) {
            const char *sep = "";
            fprintf(o, ", options [");
            if (t->present & NP_TCPOPT_MSS) { fprintf(o, "%smss %u", sep, t->mss); sep = ","; }
            if (t->present & NP_TCPOPT_WSCALE) { fprintf(o, "%swscale %u", sep, t->wscale); sep = ","; }
            if (t->present & NP_TCPOPT_SACK_OK) { fprintf(o, "%ssackOK", sep); sep = ","; }
            if (t->present & NP_TCPOPT_SACK) {
                fprintf(o, "%ssack %u", sep, t->sack_count);
                for (unsigned i = 0; i < t->sack_count; i++)
                    fprintf(o, " {%" PRIu32 ":%" PRIu32 "}", t->sack[i].left, t->sack[i].right);
                sep = ",";
            }
            if (t->present & NP_TCPOPT_TS) {
                fprintf(o, "%sTS val %" PRIu32 " ecr %" PRIu32, sep, t->ts_val, t->ts_ecr);
                sep = ",";
            }
            if (t->present & NP_TCPOPT_UNKNOWN) fprintf(o, "%sunknown", sep);
            fprintf(o, "]");
        }
        fprintf(o, ", length %u", p->payload_len);
    } else if (p->layers & NP_L_UDP) {
        fprintf(o, "%s %s.%u > %s.%u: UDP, length %u", ipname, s, p->udp.sport,
                d, p->udp.dport, p->payload_len);
    } else {
        fprintf(o, "%s %s > %s:", ipname, s, d);
        if (p->flags & NP_F_IP_FRAG_LATER) {
            uint32_t off = (p->layers & NP_L_IPV4) ? p->ip4.frag_off : p->ip6.frag_off;
            fprintf(o, " frag off %" PRIu32, off);
        }
        const char *pn = proto_name(p->ip_proto);
        if (pn)
            fprintf(o, " %s", pn);
        else
            fprintf(o, " proto %u", p->ip_proto);
        fprintf(o, ", length %u", p->payload_len);
    }
    if ((p->layers & NP_L_IPV4) && (p->ip4.mf || p->ip4.frag_off))
        fprintf(o, " (frag id %u off %u%s)", p->ip4.id, p->ip4.frag_off,
                p->ip4.mf ? " MF" : "");
    if (p->flags & NP_F_IP_OPTIONS)
        fprintf(o, " (ip options %u bytes)", p->ip4.opt_len);
    if (p->flags & NP_F_IP_CSUM_BAD)
        fprintf(o, " [bad ip cksum]");
    if (p->flags & NP_F_L4_CSUM_BAD)
        fprintf(o, " [bad l4 cksum]");
    if (p->flags & NP_F_TRUNCATED)
        fprintf(o, " [truncated capture]");
tail:
    if (e != NP_OK)
        fprintf(o, " [malformed: %s]", np_strerror(e));
    print_events(o, ev, 0);
    fputc('\n', o);
}

/* ---- JSON output ----------------------------------------------------- */

static void print_json(struct ctx *c, const np_packet *p, np_err e,
                       const np_pcap_rec *r, unsigned ev)
{
    FILE *o = c->out;
    fprintf(o, "{\"type\":\"pkt\",\"n\":%" PRIu64 ",\"ts_sec\":%" PRIu32
               ",\"ts_nsec\":%" PRIu32 ",\"caplen\":%" PRIu32 ",\"len\":%" PRIu32
               ",\"err\":\"%s\",\"layers\":[",
            c->npkts, r->ts_sec, r->ts_nsec, r->caplen, r->origlen,
            e == NP_OK ? "ok" : np_strerror(e));
    static const char *const ln[] = {"eth", "vlan", "ipv4", "ipv6", "tcp", "udp"};
    int first = 1;
    for (unsigned i = 0; i < 6; i++)
        if (p->layers & (1u << i)) {
            fprintf(o, "%s\"%s\"", first ? "" : ",", ln[i]);
            first = 0;
        }
    fprintf(o, "]");
    if (p->layers & NP_L_ETH)
        fprintf(o, ",\"ethertype\":%u", p->ethertype);
    if (p->vlan_count) {
        fprintf(o, ",\"vlan\":[");
        for (unsigned i = 0; i < p->vlan_count; i++)
            fprintf(o, "%s{\"tpid\":%u,\"vid\":%u,\"pcp\":%u,\"dei\":%u}", i ? "," : "",
                    p->vlan_tpid[i], p->vlan_tci[i] & 0xfff, p->vlan_tci[i] >> 13,
                    (p->vlan_tci[i] >> 12) & 1);
        fprintf(o, "]");
    }
    char s[64], d[64];
    if (p->layers & NP_L_IPV4) {
        fmt_addr(p, 0, s, sizeof s);
        fmt_addr(p, 1, d, sizeof d);
        fprintf(o, ",\"ip\":{\"ver\":4,\"src\":\"%s\",\"dst\":\"%s\",\"ihl\":%u,\"tos\":%u,"
                   "\"tot_len\":%u,\"id\":%u,\"df\":%u,\"mf\":%u,\"frag_off\":%u,"
                   "\"ttl\":%u,\"proto\":%u,\"csum\":%u,\"opt_len\":%u,\"csum_bad\":%s}",
                s, d, p->ip4.ihl, p->ip4.tos, p->ip4.tot_len, p->ip4.id, p->ip4.df,
                p->ip4.mf, p->ip4.frag_off, p->ip_ttl, p->ip_proto, p->ip4.csum,
                p->ip4.opt_len, (p->flags & NP_F_IP_CSUM_BAD) ? "true" : "false");
    } else if (p->layers & NP_L_IPV6) {
        fmt_addr(p, 0, s, sizeof s);
        fmt_addr(p, 1, d, sizeof d);
        fprintf(o, ",\"ip\":{\"ver\":6,\"src\":\"%s\",\"dst\":\"%s\",\"tc\":%u,"
                   "\"flow_label\":%" PRIu32 ",\"plen\":%u,\"hlim\":%u,\"proto\":%u,"
                   "\"ext_count\":%u,\"frag_off\":%u}",
                s, d, p->ip6.traffic_class, p->ip6.flow_label, p->ip6.payload_len,
                p->ip_ttl, p->ip_proto, p->ip6.ext_count, p->ip6.frag_off);
    }
    if (p->layers & NP_L_TCP) {
        const np_tcp_opts *t = &p->tcp.opts;
        fprintf(o, ",\"tcp\":{\"sport\":%u,\"dport\":%u,\"seq\":%" PRIu32 ",\"ack\":%" PRIu32
                   ",\"doff\":%u,\"flags\":%u,\"win\":%u,\"csum\":%u,\"urg\":%u,\"opts\":{",
                p->tcp.sport, p->tcp.dport, p->tcp.seq, p->tcp.ack, p->tcp.doff,
                p->tcp.flags, p->tcp.window, p->tcp.csum, p->tcp.urg);
        const char *sep = "";
        if (t->present & NP_TCPOPT_MSS) { fprintf(o, "%s\"mss\":%u", sep, t->mss); sep = ","; }
        if (t->present & NP_TCPOPT_WSCALE) { fprintf(o, "%s\"wscale\":%u", sep, t->wscale); sep = ","; }
        if (t->present & NP_TCPOPT_SACK_OK) { fprintf(o, "%s\"sack_ok\":true", sep); sep = ","; }
        if (t->present & NP_TCPOPT_TS) {
            fprintf(o, "%s\"ts\":[%" PRIu32 ",%" PRIu32 "]", sep, t->ts_val, t->ts_ecr);
            sep = ",";
        }
        if (t->present & NP_TCPOPT_SACK) {
            fprintf(o, "%s\"sack\":[", sep);
            for (unsigned i = 0; i < t->sack_count; i++)
                fprintf(o, "%s[%" PRIu32 ",%" PRIu32 "]", i ? "," : "", t->sack[i].left,
                        t->sack[i].right);
            fprintf(o, "]");
        }
        fprintf(o, "}}");
    }
    if (p->layers & NP_L_UDP)
        fprintf(o, ",\"udp\":{\"sport\":%u,\"dport\":%u,\"len\":%u,\"csum\":%u}",
                p->udp.sport, p->udp.dport, p->udp.len, p->udp.csum);
    if (p->layers & (NP_L_IPV4 | NP_L_IPV6))
        fprintf(o, ",\"payload_len\":%u,\"payload_caplen\":%u", p->payload_len,
                p->payload_caplen);
    fprintf(o, ",\"flags\":{\"truncated\":%s,\"frag\":%s,\"l4_csum_bad\":%s,\"padded\":%s}",
            (p->flags & NP_F_TRUNCATED) ? "true" : "false",
            (p->flags & NP_F_IP_FRAG) ? "true" : "false",
            (p->flags & NP_F_L4_CSUM_BAD) ? "true" : "false",
            (p->flags & NP_F_ETH_PADDED) ? "true" : "false");
    fprintf(o, ",\"events\":[");
    print_events(o, ev, 1);
    fprintf(o, "]}\n");
}

/* ---- Per-packet driver ----------------------------------------------- */

static void handle(struct ctx *c, const np_pcap_rec *r, uint32_t linktype)
{
    np_packet p;
    unsigned popts = c->o.no_csum ? 0 : (NP_OPT_IP_CSUM | NP_OPT_L4_CSUM);
    np_err e;
    if (linktype == NP_LINKTYPE_RAW)
        e = np_parse_ip(r->data, r->caplen, &p, popts);
    else
        e = np_parse_eth(r->data, r->caplen, &p, popts);
    c->npkts++;
    c->errs[e]++;
    unsigned ev = 0;
    uint64_t ts = (uint64_t)r->ts_sec * 1000000000ull + r->ts_nsec;
    if (e == NP_OK)
        np_flow_update(&c->ft, &p, ts, &ev);
    if (c->o.quiet)
        return;
    if (c->o.json)
        print_json(c, &p, e, r, ev);
    else
        print_text(c, &p, e, r, ev);
}

/* ---- Flow summary ---------------------------------------------------- */

static void ep_str(const np_flow *f, int side, char *buf, size_t n)
{
    char a[64];
    if (f->key.family == 4) {
        const uint8_t *x = f->key.addr[side];
        uint32_t v = ((uint32_t)x[0] << 24) | ((uint32_t)x[1] << 16) |
                     ((uint32_t)x[2] << 8) | x[3];
        np_fmt_ipv4(v, a, sizeof a);
        snprintf(buf, n, "%s:%u", a, f->key.port[side]);
    } else {
        np_fmt_ipv6(f->key.addr[side], a, sizeof a);
        snprintf(buf, n, "[%s]:%u", a, f->key.port[side]);
    }
}

static void dir_json(FILE *o, const np_flow_dir *d)
{
    fprintf(o, "{\"packets\":%" PRIu64 ",\"bytes\":%" PRIu64 ",\"payload_bytes\":%" PRIu64
               ",\"retransmits\":%" PRIu32 ",\"out_of_order\":%" PRIu32
               ",\"keepalives\":%" PRIu32 ",\"dup_acks\":%" PRIu32
               ",\"zero_windows\":%" PRIu32 ",\"sack_packets\":%" PRIu32
               ",\"sack_blocks\":%" PRIu32 ",\"syn\":%" PRIu32 ",\"fin\":%" PRIu32
               ",\"rst\":%" PRIu32 ",\"mss\":%u,\"wscale\":%d}",
            d->packets, d->bytes, d->payload_bytes, d->retransmits, d->out_of_order,
            d->keepalives, d->dup_acks, d->zero_windows, d->sack_packets,
            d->sack_blocks, d->syn, d->fin, d->rst, d->mss,
            d->wscale == 0xff ? -1 : (int)d->wscale);
}

static void print_flows(struct ctx *c)
{
    FILE *o = c->out;
    size_t cur = 0;
    np_flow *f;
    if (!c->o.json)
        fprintf(o, "\nFlows: %" PRIu32 "%s\n", c->ft.count,
                c->ft.dropped ? " (table full, some packets not tracked)" : "");
    while ((f = np_flow_next(&c->ft, &cur))) {
        int a = f->initiator, b = a ^ 1;
        char ea[96], eb[96];
        ep_str(f, a, ea, sizeof ea);
        ep_str(f, b, eb, sizeof eb);
        const char *pr = f->key.proto == NP_IPPROTO_TCP ? "tcp" : "udp";
        const np_flow_dir *da = &f->dir[a], *db = &f->dir[b];
        if (c->o.json) {
            fprintf(o, "{\"type\":\"flow\",\"proto\":\"%s\",\"a\":\"%s\",\"b\":\"%s\",\"a_to_b\":",
                    pr, ea, eb);
            dir_json(o, da);
            fprintf(o, ",\"b_to_a\":");
            dir_json(o, db);
            fprintf(o, "}\n");
            continue;
        }
        fprintf(o, "  %s %s <-> %s\n", pr, ea, eb);
        fprintf(o, "      pkts %" PRIu64 "/%" PRIu64 "  bytes %" PRIu64 "/%" PRIu64
                   "  payload %" PRIu64 "/%" PRIu64 "\n",
                da->packets, db->packets, da->bytes, db->bytes, da->payload_bytes,
                db->payload_bytes);
        if (f->key.proto == NP_IPPROTO_TCP)
            fprintf(o, "      retrans %" PRIu32 "/%" PRIu32 "  ooo %" PRIu32 "/%" PRIu32
                       "  dupack %" PRIu32 "/%" PRIu32 "  sack %" PRIu32 "/%" PRIu32
                       " (blocks %" PRIu32 "/%" PRIu32 ")  zwin %" PRIu32 "/%" PRIu32
                       "  syn %" PRIu32 "/%" PRIu32 " fin %" PRIu32 "/%" PRIu32
                       " rst %" PRIu32 "/%" PRIu32 "\n",
                    da->retransmits, db->retransmits, da->out_of_order, db->out_of_order,
                    da->dup_acks, db->dup_acks, da->sack_packets, db->sack_packets,
                    da->sack_blocks, db->sack_blocks, da->zero_windows, db->zero_windows,
                    da->syn, db->syn, da->fin, db->fin, da->rst, db->rst);
    }
}

static void print_summary(struct ctx *c, const char *status)
{
    FILE *o = c->out;
    if (c->o.json) {
        fprintf(o, "{\"type\":\"summary\",\"packets\":%" PRIu64 ",\"flows\":%" PRIu32
                   ",\"status\":\"%s\",\"errors\":{",
                c->npkts, c->ft.count, status);
        int first = 1;
        for (int i = 1; i < NP_ERR__COUNT; i++)
            if (c->errs[i]) {
                fprintf(o, "%s\"%s\":%" PRIu64, first ? "" : ",", np_strerror((np_err)i),
                        c->errs[i]);
                first = 0;
            }
        fprintf(o, "}}\n");
        return;
    }
    uint64_t bad = c->npkts - c->errs[NP_OK];
    fprintf(o, "\n%" PRIu64 " packets, %" PRIu64 " malformed, reader: %s\n", c->npkts,
            bad, status);
    for (int i = 1; i < NP_ERR__COUNT; i++)
        if (c->errs[i])
            fprintf(o, "  %-34s %" PRIu64 "\n", np_strerror((np_err)i), c->errs[i]);
}

/* ---- pcap file ------------------------------------------------------- */

static int run_file(struct ctx *c)
{
    np_pcap_file f;
    np_pcap_err pe = np_pcap_map_file(c->o.file, &f);
    if (pe != NP_PCAP_OK) {
        fprintf(stderr, "netparse: %s: %s\n", c->o.file, strerror(errno));
        return 2;
    }
    np_pcap r;
    pe = np_pcap_open_mem(&r, f.base, f.len);
    if (pe != NP_PCAP_OK) {
        fprintf(stderr, "netparse: %s: %s\n", c->o.file, np_pcap_strerror(pe));
        np_pcap_unmap_file(&f);
        return 2;
    }
    if (r.linktype != NP_LINKTYPE_ETHERNET && r.linktype != NP_LINKTYPE_RAW) {
        fprintf(stderr, "netparse: unsupported linktype %" PRIu32 "\n", r.linktype);
        np_pcap_unmap_file(&f);
        return 2;
    }
    np_pcap_rec rec;
    while (!stop_flag && (c->o.count == 0 || c->npkts < c->o.count) &&
           (pe = np_pcap_next(&r, &rec)) == NP_PCAP_OK)
        handle(c, &rec, r.linktype);
    if (pe == NP_PCAP_OK)
        pe = NP_PCAP_EOF; /* stopped by -c */
    if (!c->o.no_flows)
        print_flows(c);
    print_summary(c, pe == NP_PCAP_EOF ? "ok" : np_pcap_strerror(pe));
    np_pcap_unmap_file(&f);
    return pe == NP_PCAP_EOF ? 0 : 1;
}

/* ---- Live capture: AF_PACKET + TPACKET_V3 ring ----------------------- */

#ifdef __linux__
static int run_live(struct ctx *c)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr, "netparse: socket(AF_PACKET): %s (needs CAP_NET_RAW)\n",
                strerror(errno));
        return 2;
    }
    int ver = TPACKET_V3;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof ver) < 0) {
        fprintf(stderr, "netparse: PACKET_VERSION: %s\n", strerror(errno));
        close(fd);
        return 2;
    }
    struct tpacket_req3 req;
    memset(&req, 0, sizeof req);
    req.tp_block_size = 1u << 20;
    req.tp_block_nr = 16;
    req.tp_frame_size = 2048;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;
    req.tp_retire_blk_tov = 50; /* ms */
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof req) < 0) {
        fprintf(stderr, "netparse: PACKET_RX_RING: %s\n", strerror(errno));
        close(fd);
        return 2;
    }
    size_t ring_len = (size_t)req.tp_block_size * req.tp_block_nr;
    uint8_t *ring = mmap(NULL, ring_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
    if (ring == MAP_FAILED)
        ring = mmap(NULL, ring_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        fprintf(stderr, "netparse: mmap ring: %s\n", strerror(errno));
        close(fd);
        return 2;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)if_nametoindex(c->o.iface);
    if (sll.sll_ifindex == 0 || bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
        fprintf(stderr, "netparse: bind %s: %s\n", c->o.iface, strerror(errno));
        munmap(ring, ring_len);
        close(fd);
        return 2;
    }
    unsigned blk = 0;
    while (!stop_flag && (c->o.count == 0 || c->npkts < c->o.count)) {
        struct tpacket_block_desc *bd =
            (struct tpacket_block_desc *)(void *)(ring + (size_t)blk * req.tp_block_size);
        if (!(__atomic_load_n(&bd->hdr.bh1.block_status, __ATOMIC_ACQUIRE) & TP_STATUS_USER)) {
            struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLERR};
            poll(&pfd, 1, 200);
            continue;
        }
        uint32_t n = bd->hdr.bh1.num_pkts;
        struct tpacket3_hdr *h =
            (struct tpacket3_hdr *)(void *)((uint8_t *)bd + bd->hdr.bh1.offset_to_first_pkt);
        for (uint32_t i = 0; i < n && !stop_flag; i++) {
            np_pcap_rec rec;
            rec.data = (const uint8_t *)h + h->tp_mac; /* zero-copy: kernel ring */
            rec.caplen = h->tp_snaplen;
            rec.origlen = h->tp_len;
            rec.ts_sec = h->tp_sec;
            rec.ts_nsec = h->tp_nsec;
            handle(c, &rec, NP_LINKTYPE_ETHERNET);
            if (c->o.count && c->npkts >= c->o.count)
                break;
            h = (struct tpacket3_hdr *)(void *)((uint8_t *)h + h->tp_next_offset);
        }
        fflush(c->out);
        __atomic_store_n(&bd->hdr.bh1.block_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE);
        blk = (blk + 1) % req.tp_block_nr;
    }
    struct tpacket_stats_v3 st;
    socklen_t sl = sizeof st;
    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &st, &sl) == 0 && !c->o.json)
        fprintf(c->out, "\nkernel: %u packets, %u dropped\n", st.tp_packets, st.tp_drops);
    munmap(ring, ring_len);
    close(fd);
    if (!c->o.no_flows)
        print_flows(c);
    print_summary(c, "ok");
    return 0;
}
#endif

static void usage(FILE *o)
{
    fprintf(o,
            "usage: netparse [-jqFn] [-c count] -r file.pcap\n"
            "       netparse [-jqFn] [-c count] -i iface   (Linux, needs CAP_NET_RAW)\n"
            "  -r FILE  read a classic pcap file (Ethernet or raw IP linktype)\n"
            "  -i IFACE live capture via AF_PACKET TPACKET_V3 ring\n"
            "  -j       JSON lines output\n"
            "  -q       do not print per-packet lines\n"
            "  -F       do not print per-flow statistics\n"
            "  -n       do not verify IP/TCP/UDP checksums\n"
            "  -c N     stop after N packets\n");
}

int main(int argc, char **argv)
{
    static struct ctx c; /* flow table storage lives in .bss */
    static np_flow slots[FLOW_SLOTS];
    int ch;
    while ((ch = getopt(argc, argv, "r:i:jqFnc:h")) != -1) {
        switch (ch) {
        case 'r': c.o.file = optarg; break;
        case 'i': c.o.iface = optarg; break;
        case 'j': c.o.json = 1; break;
        case 'q': c.o.quiet = 1; break;
        case 'F': c.o.no_flows = 1; break;
        case 'n': c.o.no_csum = 1; break;
        case 'c': c.o.count = strtoull(optarg, NULL, 10); break;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (!c.o.file == !c.o.iface) {
        usage(stderr);
        return 2;
    }
    c.out = stdout;
    np_flow_table_init(&c.ft, slots, FLOW_SLOTS);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    if (c.o.file)
        return run_file(&c);
#ifdef __linux__
    return run_live(&c);
#else
    fprintf(stderr, "netparse: live capture is only supported on Linux\n");
    return 2;
#endif
}
