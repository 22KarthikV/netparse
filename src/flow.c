/* SPDX-License-Identifier: MIT */
#include "netparse/flow.h"
#include "load.h"

#include <string.h>

/* Serial-number arithmetic (RFC 1982) on 32-bit sequence numbers. */
static inline int seq_lt(uint32_t a, uint32_t b) { return a != b && ((a - b) >> 31); }
static inline int seq_le(uint32_t a, uint32_t b) { return a == b || ((a - b) >> 31); }
static inline int seq_gt(uint32_t a, uint32_t b) { return seq_lt(b, a); }

int np_flow_table_init(np_flow_table *t, np_flow *storage, size_t nslots)
{
    if (!t || !storage || nslots < 8 || (nslots & (nslots - 1)) ||
        nslots > (1u << 30))
        return -1;
    memset(storage, 0, nslots * sizeof *storage);
    t->slots = storage;
    t->mask = (uint32_t)nslots - 1;
    t->count = 0;
    t->limit = (uint32_t)(nslots - nslots / 8);
    t->dropped = 0;
    t->ooo_threshold_ns = 3000000; /* 3 ms */
    return 0;
}

static uint32_t hash_key(const np_flow_key *k)
{
    /* 40-byte key, five 64-bit words, multiply-xorshift mixing. */
    const uint8_t *p = (const uint8_t *)k;
    uint64_t h = 0x9e3779b97f4a7c15ull;
    for (size_t i = 0; i < sizeof *k; i += 8) {
        uint64_t w;
        memcpy(&w, p + i, 8);
        h ^= w;
        h *= 0xff51afd7ed558ccdull;
        h ^= h >> 32;
    }
    return (uint32_t)h;
}

/* Build the canonical key; return the key side of the packet's sender,
 * or -1 if the packet has no L4 ports we track. */
static int make_key(const np_packet *pkt, np_flow_key *k)
{
    uint16_t sp, dp;
    if (pkt->layers & NP_L_TCP) {
        sp = pkt->tcp.sport;
        dp = pkt->tcp.dport;
    } else if (pkt->layers & NP_L_UDP) {
        sp = pkt->udp.sport;
        dp = pkt->udp.dport;
    } else {
        return -1;
    }
    uint8_t src[16] = {0}, dst[16] = {0};
    if (pkt->layers & NP_L_IPV4) {
        uint32_t s = pkt->ip4.src, d = pkt->ip4.dst;
        for (int i = 0; i < 4; i++) {
            src[i] = (uint8_t)(s >> (24 - 8 * i));
            dst[i] = (uint8_t)(d >> (24 - 8 * i));
        }
        k->family = 4;
    } else {
        memcpy(src, pkt->data + pkt->ip6.src_off, 16);
        memcpy(dst, pkt->data + pkt->ip6.dst_off, 16);
        k->family = 6;
    }
    k->proto = pkt->ip_proto;
    k->_pad = 0;
    int c = memcmp(src, dst, 16);
    int side = (c > 0 || (c == 0 && sp > dp)) ? 1 : 0;
    memcpy(k->addr[side], src, 16);
    memcpy(k->addr[side ^ 1], dst, 16);
    k->port[side] = sp;
    k->port[side ^ 1] = dp;
    return side;
}

static np_flow *find_slot(np_flow_table *t, const np_flow_key *k, uint32_t h,
                          int *found)
{
    uint32_t i = h & t->mask;
    for (;;) {
        np_flow *f = &t->slots[i];
        if (!f->used) {
            *found = 0;
            return f;
        }
        if (f->hash == h && memcmp(&f->key, k, sizeof *k) == 0) {
            *found = 1;
            return f;
        }
        i = (i + 1) & t->mask;
    }
    /* Terminates: occupancy is capped below 100%, so an empty slot exists. */
}

np_flow *np_flow_lookup(np_flow_table *t, const np_packet *pkt)
{
    np_flow_key k;
    if (!t || !pkt || make_key(pkt, &k) < 0)
        return NULL;
    int found;
    np_flow *f = find_slot(t, &k, hash_key(&k), &found);
    return found ? f : NULL;
}

np_flow *np_flow_next(np_flow_table *t, size_t *cursor)
{
    while (*cursor <= t->mask) {
        np_flow *f = &t->slots[(*cursor)++];
        if (f->used)
            return f;
    }
    return NULL;
}

/* ---- Hole bookkeeping ------------------------------------------------ */

static void add_hole(np_flow_dir *d, uint32_t l, uint32_t r, uint64_t ts)
{
    if (d->nholes == NP_FLOW_MAX_HOLES) {
        d->holes_lost++;
        return;
    }
    d->holes[d->nholes].left = l;
    d->holes[d->nholes].right = r;
    d->holes[d->nholes].ts_ns = ts;
    d->nholes++;
}

static void del_hole(np_flow_dir *d, unsigned i)
{
    d->holes[i] = d->holes[--d->nholes];
}

/* Remove [s, e) from every hole. Returns 1 and the hole's timestamp if the
 * range lay entirely inside a single hole. */
static int fill_holes(np_flow_dir *d, uint32_t s, uint32_t e, uint64_t *hole_ts)
{
    int inside = 0;
    unsigned i = 0;
    while (i < d->nholes) {
        np_seq_hole h = d->holes[i];
        if (seq_le(e, h.left) || seq_le(h.right, s)) {
            i++;
            continue;
        }
        if (seq_le(h.left, s) && seq_le(e, h.right)) {
            inside = 1;
            *hole_ts = h.ts_ns;
        }
        int has_l = seq_lt(h.left, s);
        int has_r = seq_lt(e, h.right);
        if (has_l && has_r) {
            d->holes[i].right = s;
            add_hole(d, e, h.right, h.ts_ns);
            i++;
        } else if (has_l) {
            d->holes[i].right = s;
            i++;
        } else if (has_r) {
            d->holes[i].left = e;
            i++;
        } else {
            del_hole(d, i);
        }
    }
    return inside;
}

/* The peer acknowledged everything before `ack`: drop holes below it. */
static void ack_holes(np_flow_dir *d, uint32_t ack)
{
    unsigned i = 0;
    while (i < d->nholes) {
        if (seq_le(d->holes[i].right, ack)) {
            del_hole(d, i);
            continue;
        }
        if (seq_lt(d->holes[i].left, ack))
            d->holes[i].left = ack;
        i++;
    }
}

/* ---- TCP analysis ---------------------------------------------------- */

static unsigned tcp_analyze(np_flow_table *t, np_flow *f, int side,
                            const np_packet *pkt, uint64_t ts)
{
    np_flow_dir *d = &f->dir[side];
    np_flow_dir *peer = &f->dir[side ^ 1];
    unsigned ev = 0;
    uint8_t fl = pkt->tcp.flags;
    uint32_t seq = pkt->tcp.seq;
    uint32_t seglen = pkt->payload_len + ((fl & NP_TCP_SYN) ? 1u : 0u) +
                      ((fl & NP_TCP_FIN) ? 1u : 0u);
    int ctl = (fl & (NP_TCP_SYN | NP_TCP_FIN | NP_TCP_RST)) != 0;

    if (fl & NP_TCP_SYN) {
        d->syn++;
        if (pkt->tcp.opts.present & NP_TCPOPT_WSCALE)
            d->wscale = pkt->tcp.opts.wscale;
        if (pkt->tcp.opts.present & NP_TCPOPT_MSS)
            d->mss = pkt->tcp.opts.mss;
    }
    if (fl & NP_TCP_FIN)
        d->fin++;
    if (fl & NP_TCP_RST)
        d->rst++;

    /* Keep-alive: zero or one byte at max_seq_end - 1. Checked first so a
     * zero-length probe is not mistaken for a duplicate ACK. */
    int keepalive = !ctl && pkt->payload_len <= 1 && d->seq_valid &&
                    seq == d->max_seq_end - 1;
    if (keepalive) {
        d->keepalives++;
        ev |= NP_FEV_KEEPALIVE;
    } else if (seglen > 0 && !(fl & NP_TCP_RST)) {
        /* Sequence-space analysis (RST carries no data sequence). */
        uint32_t end = seq + seglen;
        if (!d->seq_valid) {
            d->max_seq_end = end;
            d->seq_valid = 1;
        } else if (seq == d->max_seq_end) {
            d->max_seq_end = end;
        } else if (seq_gt(seq, d->max_seq_end)) {
            add_hole(d, d->max_seq_end, seq, ts);
            d->max_seq_end = end;
        } else {
            uint64_t hts = 0;
            int inside = fill_holes(d, seq, end, &hts);
            if (inside && ts - hts <= t->ooo_threshold_ns) {
                d->out_of_order++;
                ev |= NP_FEV_OOO;
            } else {
                d->retransmits++;
                ev |= NP_FEV_RETRANS;
            }
            if (seq_gt(end, d->max_seq_end))
                d->max_seq_end = end;
        }
    }

    if (fl & NP_TCP_ACK) {
        uint32_t ack = pkt->tcp.ack;
        uint16_t win = pkt->tcp.window;
        if (pkt->payload_len == 0 && !ctl && !keepalive && d->ack_valid &&
            ack == d->last_ack && win == d->last_win) {
            d->dup_acks++;
            ev |= NP_FEV_DUP_ACK;
        }
        d->last_ack = ack;
        d->last_win = win;
        d->ack_valid = 1;
        if (peer->nholes)
            ack_holes(peer, ack);
    }
    if (pkt->tcp.window == 0 && !ctl) {
        d->zero_windows++;
        ev |= NP_FEV_ZERO_WIN;
    }
    if (pkt->tcp.opts.present & NP_TCPOPT_SACK) {
        d->sack_packets++;
        d->sack_blocks += pkt->tcp.opts.sack_count;
        ev |= NP_FEV_SACK;
    }
    return ev;
}

np_flow *np_flow_update(np_flow_table *t, const np_packet *pkt,
                        uint64_t ts_ns, unsigned *events)
{
    unsigned ev = 0;
    if (events)
        *events = 0;
    if (!t || !pkt)
        return NULL;
    np_flow_key k;
    int side = make_key(pkt, &k);
    if (side < 0)
        return NULL;
    uint32_t h = hash_key(&k);
    int found;
    np_flow *f = find_slot(t, &k, h, &found);
    if (!found) {
        if (t->count >= t->limit) {
            t->dropped++;
            return NULL;
        }
        memset(f, 0, sizeof *f);
        f->key = k;
        f->hash = h;
        f->used = 1;
        f->initiator = (uint8_t)side;
        f->first_ts_ns = ts_ns;
        f->dir[0].wscale = f->dir[1].wscale = 0xff;
        t->count++;
        ev |= NP_FEV_NEW_FLOW;
    }
    f->last_ts_ns = ts_ns;
    np_flow_dir *d = &f->dir[side];
    d->packets++;
    d->bytes += (pkt->layers & NP_L_IPV4) ? pkt->ip4.tot_len
                                          : (uint32_t)pkt->ip6.payload_len + 40u;
    d->payload_bytes += pkt->payload_len;
    if (pkt->layers & NP_L_TCP)
        ev |= tcp_analyze(t, f, side, pkt, ts_ns);
    if (events)
        *events = ev;
    return f;
}
