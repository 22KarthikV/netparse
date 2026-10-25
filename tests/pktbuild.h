/* SPDX-License-Identifier: MIT
 * Test/bench helper: build Ethernet frames with correct checksums. */
#ifndef NP_PKTBUILD_H
#define NP_PKTBUILD_H

#include "netparse/netparse.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct pb_spec {
    int nvlan;
    uint16_t vlan_tpid[3];
    uint16_t vlan_tci[3];
    uint16_t ethertype;          /* 0: derived from ipv6 flag */
    int ipv6;
    uint32_t src4, dst4;
    uint8_t src6[16], dst6[16];
    uint8_t proto;               /* NP_IPPROTO_TCP / UDP / other */
    uint8_t ttl;
    uint16_t ip_id;
    uint16_t frag;               /* raw IPv4 flags+offset field */
    const uint8_t *ipopts;       /* IPv4 options (multiple of 4) */
    size_t ipopts_len;
    const uint8_t *ip6ext;       /* raw IPv6 extension headers */
    size_t ip6ext_len;
    uint8_t ip6ext_first;        /* next header value pointing at ip6ext */
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t tcp_flags;
    uint16_t win;
    const uint8_t *tcpopts;      /* multiple of 4 */
    size_t tcpopts_len;
    size_t payload_len;
};

static inline void pb_put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void pb_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Returns frame length, or 0 if cap is too small. */
static inline size_t pb_build(const struct pb_spec *s, uint8_t *out, size_t cap)
{
    size_t l4hdr = s->proto == NP_IPPROTO_TCP ? 20 + s->tcpopts_len
                 : s->proto == NP_IPPROTO_UDP ? 8 : 0;
    size_t l3hdr = s->ipv6 ? 40 + s->ip6ext_len : 20 + s->ipopts_len;
    size_t need = 14 + 4 * (size_t)s->nvlan + l3hdr + l4hdr + s->payload_len;
    if (need > cap)
        return 0;
    memset(out, 0, need);
    static const uint8_t dmac[6] = {0x02, 0, 0, 0, 0, 0x02};
    static const uint8_t smac[6] = {0x02, 0, 0, 0, 0, 0x01};
    memcpy(out, dmac, 6);
    memcpy(out + 6, smac, 6);
    size_t off = 12;
    for (int i = 0; i < s->nvlan; i++) {
        pb_put16(out + off, s->vlan_tpid[i] ? s->vlan_tpid[i] : NP_ETHERTYPE_VLAN);
        pb_put16(out + off + 2, s->vlan_tci[i]);
        off += 4;
    }
    uint16_t et = s->ethertype ? s->ethertype
                : s->ipv6 ? NP_ETHERTYPE_IPV6 : NP_ETHERTYPE_IPV4;
    pb_put16(out + off, et);
    off += 2;
    size_t l3 = off;
    size_t l4 = l3 + l3hdr;
    size_t l4len = l4hdr + s->payload_len;
    uint8_t *ip = out + l3;
    uint32_t psum;
    if (!s->ipv6) {
        ip[0] = (uint8_t)(0x40 | ((20 + s->ipopts_len) / 4));
        pb_put16(ip + 2, (uint16_t)(l3hdr + l4len));
        pb_put16(ip + 4, s->ip_id);
        pb_put16(ip + 6, s->frag);
        ip[8] = s->ttl ? s->ttl : 64;
        ip[9] = s->proto;
        pb_put32(ip + 12, s->src4);
        pb_put32(ip + 16, s->dst4);
        if (s->ipopts_len)
            memcpy(ip + 20, s->ipopts, s->ipopts_len);
        pb_put16(ip + 10, (uint16_t)~np_csum_fold(np_csum_partial(ip, l3hdr, 0)));
        psum = np_csum_partial(ip + 12, 8, 0);
    } else {
        pb_put32(ip, 0x60000000u);
        pb_put16(ip + 4, (uint16_t)(s->ip6ext_len + l4len));
        ip[6] = s->ip6ext_len ? s->ip6ext_first : s->proto;
        ip[7] = s->ttl ? s->ttl : 64;
        memcpy(ip + 8, s->src6, 16);
        memcpy(ip + 24, s->dst6, 16);
        if (s->ip6ext_len)
            memcpy(ip + 40, s->ip6ext, s->ip6ext_len);
        psum = np_csum_partial(ip + 8, 32, 0);
    }
    psum += s->proto + (uint32_t)l4len;
    uint8_t *t = out + l4;
    for (size_t i = 0; i < s->payload_len; i++)
        t[l4hdr + i] = (uint8_t)(i * 7 + 1);
    if (s->proto == NP_IPPROTO_TCP) {
        pb_put16(t, s->sport);
        pb_put16(t + 2, s->dport);
        pb_put32(t + 4, s->seq);
        pb_put32(t + 8, s->ack);
        t[12] = (uint8_t)(((20 + s->tcpopts_len) / 4) << 4);
        t[13] = s->tcp_flags;
        pb_put16(t + 14, s->win);
        if (s->tcpopts_len)
            memcpy(t + 20, s->tcpopts, s->tcpopts_len);
        pb_put16(t + 16, (uint16_t)~np_csum_fold(np_csum_partial(t, l4len, psum)));
    } else if (s->proto == NP_IPPROTO_UDP) {
        pb_put16(t, s->sport);
        pb_put16(t + 2, s->dport);
        pb_put16(t + 4, (uint16_t)l4len);
        uint16_t c = (uint16_t)~np_csum_fold(np_csum_partial(t, l4len, psum));
        pb_put16(t + 6, c ? c : 0xffff);
    }
    return need;
}

/* A plain IPv4/TCP spec with sensible defaults. */
static inline struct pb_spec pb_tcp4(uint32_t seq, uint32_t ack, uint8_t flags,
                                     size_t payload)
{
    struct pb_spec s;
    memset(&s, 0, sizeof s);
    s.src4 = 0x0a000001; /* 10.0.0.1 */
    s.dst4 = 0x0a000002;
    s.proto = NP_IPPROTO_TCP;
    s.sport = 40000;
    s.dport = 80;
    s.seq = seq;
    s.ack = ack;
    s.tcp_flags = flags;
    s.win = 65535;
    s.payload_len = payload;
    s.frag = 0x4000; /* DF */
    return s;
}

#endif
