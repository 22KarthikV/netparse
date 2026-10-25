/* SPDX-License-Identifier: MIT
 * netparse: zero-copy L2-L4 parser.
 *
 * Bounds-checking convention: every layer function receives `off`, the
 * offset of its header, and works with `avail = limit - off`, where `limit`
 * is the number of bytes that may be read (never more than caplen). A
 * field is read only after a check that proves it lies inside
 * [off, off + avail). All arithmetic is done in size_t or uint32_t on
 * values that are already bounded by 16-bit header fields, so it cannot
 * wrap.
 */
#define _POSIX_C_SOURCE 200809L
#include "netparse/netparse.h"
#include "load.h"

#include <arpa/inet.h>
#include <stdio.h>

static const char *const err_names[NP_ERR__COUNT] = {
    [NP_OK] = "ok",
    [NP_ERR_NULL] = "null argument",
    [NP_ERR_TRUNC_ETH] = "truncated ethernet header",
    [NP_ERR_TRUNC_VLAN] = "truncated vlan tag",
    [NP_ERR_VLAN_DEPTH] = "too many vlan tags",
    [NP_ERR_TRUNC_IPV4] = "truncated ipv4 header",
    [NP_ERR_IPV4_VERSION] = "bad ipv4 version",
    [NP_ERR_IPV4_IHL] = "bad ipv4 ihl",
    [NP_ERR_IPV4_TOTLEN] = "bad ipv4 total length",
    [NP_ERR_IPV4_OPTIONS] = "malformed ipv4 options",
    [NP_ERR_IPV4_FRAG] = "ipv4 fragment exceeds 65535 bytes",
    [NP_ERR_TRUNC_IPV6] = "truncated ipv6 header",
    [NP_ERR_IPV6_VERSION] = "bad ipv6 version",
    [NP_ERR_IPV6_EXTHDR] = "malformed ipv6 extension header",
    [NP_ERR_TRUNC_TCP] = "truncated tcp header",
    [NP_ERR_TCP_DOFF] = "bad tcp data offset",
    [NP_ERR_TCP_OPTIONS] = "malformed tcp options",
    [NP_ERR_TRUNC_UDP] = "truncated udp header",
    [NP_ERR_UDP_LEN] = "bad udp length",
};

const char *np_strerror(np_err e)
{
    if ((unsigned)e >= NP_ERR__COUNT)
        return "unknown error";
    return err_names[e];
}

/* ---- Checksum -------------------------------------------------------- */

uint32_t np_csum_partial(const uint8_t *p, size_t len, uint32_t sum)
{
    uint64_t acc = sum;
    while (len >= 4) {
        acc += np_be32(p);
        p += 4;
        len -= 4;
    }
    if (len >= 2) {
        acc += np_be16(p);
        p += 2;
        len -= 2;
    }
    if (len)
        acc += (uint32_t)p[0] << 8;
    while (acc >> 32)
        acc = (acc & 0xffffffffu) + (acc >> 32);
    return (uint32_t)acc;
}

uint16_t np_csum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)sum;
}

/* ---- L4 -------------------------------------------------------------- */

static np_err parse_tcp_options(const uint8_t *p, size_t n, np_tcp_opts *o)
{
    size_t i = 0;
    while (i < n) {
        uint8_t kind = p[i];
        if (kind == 0) /* EOL */
            break;
        if (kind == 1) { /* NOP */
            i++;
            continue;
        }
        if (n - i < 2)
            return NP_ERR_TCP_OPTIONS;
        uint8_t len = p[i + 1];
        if (len < 2 || len > n - i)
            return NP_ERR_TCP_OPTIONS;
        const uint8_t *v = p + i + 2;
        switch (kind) {
        case 2:
            if (len != 4)
                return NP_ERR_TCP_OPTIONS;
            o->mss = np_be16(v);
            o->present |= NP_TCPOPT_MSS;
            break;
        case 3:
            if (len != 3)
                return NP_ERR_TCP_OPTIONS;
            o->wscale = v[0];
            o->present |= NP_TCPOPT_WSCALE;
            break;
        case 4:
            if (len != 2)
                return NP_ERR_TCP_OPTIONS;
            o->present |= NP_TCPOPT_SACK_OK;
            break;
        case 5: {
            if (len < 10 || ((len - 2) % 8) != 0)
                return NP_ERR_TCP_OPTIONS;
            /* At most 40 option bytes, so at most 4 blocks fit. */
            unsigned nb = (unsigned)(len - 2) / 8;
            for (unsigned b = 0; b < nb; b++) {
                o->sack[b].left = np_be32(v + 8 * b);
                o->sack[b].right = np_be32(v + 8 * b + 4);
            }
            o->sack_count = (uint8_t)nb;
            o->present |= NP_TCPOPT_SACK;
            break;
        }
        case 8:
            if (len != 10)
                return NP_ERR_TCP_OPTIONS;
            o->ts_val = np_be32(v);
            o->ts_ecr = np_be32(v + 4);
            o->present |= NP_TCPOPT_TS;
            break;
        default:
            o->present |= NP_TCPOPT_UNKNOWN;
            break;
        }
        i += len;
    }
    return NP_OK;
}

/* Pseudo-header sum for L4 checksum verification. */
static uint32_t pseudo_sum(const np_packet *pkt, uint32_t l4len)
{
    uint32_t sum;
    if (pkt->layers & NP_L_IPV4) {
        sum = (pkt->ip4.src >> 16) + (pkt->ip4.src & 0xffff) +
              (pkt->ip4.dst >> 16) + (pkt->ip4.dst & 0xffff);
    } else {
        sum = np_csum_partial(pkt->data + pkt->ip6.src_off, 32, 0);
    }
    sum += pkt->ip_proto;
    sum += l4len >> 16;
    sum += l4len & 0xffff;
    return sum;
}

static void verify_l4(np_packet *pkt, uint32_t l4len)
{
    /* Only possible when the whole segment was captured. */
    if (pkt->payload_caplen != pkt->payload_len)
        return;
    uint32_t s = pseudo_sum(pkt, l4len);
    s = np_csum_partial(pkt->data + pkt->l4_off, l4len, s);
    if (np_csum_fold(s) != 0xffff)
        pkt->flags |= NP_F_L4_CSUM_BAD;
}

/* decl: L4 bytes according to the L3 header. cap: bytes actually present
 * (cap <= decl). frag: this is the first fragment of a fragmented
 * datagram, so length fields may describe the reassembled datagram. */
static np_err parse_tcp(np_packet *pkt, size_t off, size_t decl, size_t cap,
                        unsigned opts, int frag)
{
    const uint8_t *b = pkt->data + off;
    if (cap < 20)
        return NP_ERR_TRUNC_TCP;
    uint8_t doff = b[12] >> 4;
    if (doff < 5)
        return NP_ERR_TCP_DOFF;
    size_t hl = (size_t)doff * 4;
    if (hl > decl)
        return NP_ERR_TCP_DOFF;
    if (hl > cap)
        return NP_ERR_TRUNC_TCP;

    pkt->tcp.sport = np_be16(b);
    pkt->tcp.dport = np_be16(b + 2);
    pkt->tcp.seq = np_be32(b + 4);
    pkt->tcp.ack = np_be32(b + 8);
    pkt->tcp.doff = doff;
    pkt->tcp.flags = b[13];
    pkt->tcp.window = np_be16(b + 14);
    pkt->tcp.csum = np_be16(b + 16);
    pkt->tcp.urg = np_be16(b + 18);
    pkt->tcp.opts.present = 0;
    pkt->tcp.opts.sack_count = 0;
    if (hl > 20) {
        np_err e = parse_tcp_options(b + 20, hl - 20, &pkt->tcp.opts);
        if (e != NP_OK)
            return e;
    }
    pkt->l4_off = (uint16_t)off;
    pkt->payload_off = (uint16_t)(off + hl);
    pkt->payload_len = (uint16_t)(decl - hl);
    pkt->payload_caplen = (uint16_t)(cap - hl);
    pkt->layers |= NP_L_TCP;
    if ((opts & NP_OPT_L4_CSUM) && !frag)
        verify_l4(pkt, (uint32_t)decl);
    return NP_OK;
}

static np_err parse_udp(np_packet *pkt, size_t off, size_t decl, size_t cap,
                        unsigned opts, int frag)
{
    const uint8_t *b = pkt->data + off;
    if (cap < 8)
        return NP_ERR_TRUNC_UDP;
    uint16_t ulen = np_be16(b + 4);
    if (ulen < 8)
        return NP_ERR_UDP_LEN;
    if (!frag && ulen > decl)
        return NP_ERR_UDP_LEN;

    pkt->udp.sport = np_be16(b);
    pkt->udp.dport = np_be16(b + 2);
    pkt->udp.len = ulen;
    pkt->udp.csum = np_be16(b + 6);

    size_t plen = frag ? decl - 8 : (size_t)ulen - 8;
    size_t pcap = cap - 8;
    if (pcap > plen)
        pcap = plen;
    pkt->l4_off = (uint16_t)off;
    pkt->payload_off = (uint16_t)(off + 8);
    pkt->payload_len = (uint16_t)plen;
    pkt->payload_caplen = (uint16_t)pcap;
    pkt->layers |= NP_L_UDP;
    if ((opts & NP_OPT_L4_CSUM) && !frag) {
        /* UDP over IPv4 may omit the checksum (0). */
        if (!(pkt->udp.csum == 0 && (pkt->layers & NP_L_IPV4)))
            verify_l4(pkt, ulen);
    }
    return NP_OK;
}

static np_err parse_l4(np_packet *pkt, size_t off, size_t decl, size_t cap,
                       unsigned opts, int frag)
{
    switch (pkt->ip_proto) {
    case NP_IPPROTO_TCP:
        return parse_tcp(pkt, off, decl, cap, opts, frag);
    case NP_IPPROTO_UDP:
        return parse_udp(pkt, off, decl, cap, opts, frag);
    default:
        pkt->l4_off = (uint16_t)off;
        pkt->payload_off = (uint16_t)off;
        pkt->payload_len = (uint16_t)decl;
        pkt->payload_caplen = (uint16_t)cap;
        return NP_OK;
    }
}

/* ---- L3 -------------------------------------------------------------- */

static np_err check_ipv4_options(const uint8_t *p, size_t n)
{
    size_t i = 0;
    while (i < n) {
        uint8_t t = p[i];
        if (t == 0)
            break;
        if (t == 1) {
            i++;
            continue;
        }
        if (n - i < 2)
            return NP_ERR_IPV4_OPTIONS;
        uint8_t l = p[i + 1];
        if (l < 2 || l > n - i)
            return NP_ERR_IPV4_OPTIONS;
        i += l;
    }
    return NP_OK;
}

/* Clamp the L3 datagram to what was captured; record truncation/padding.
 * Returns the number of readable bytes of the datagram. */
static size_t l3_limit(np_packet *pkt, size_t avail, size_t tot)
{
    if (tot > avail) {
        pkt->flags |= NP_F_TRUNCATED;
        return avail;
    }
    if (tot < avail)
        pkt->flags |= NP_F_ETH_PADDED;
    return tot;
}

static np_err parse_ipv4(np_packet *pkt, size_t off, unsigned opts)
{
    const uint8_t *b = pkt->data + off;
    size_t avail = pkt->caplen - off;
    if (avail < 20)
        return NP_ERR_TRUNC_IPV4;
    if ((b[0] >> 4) != 4)
        return NP_ERR_IPV4_VERSION;
    uint8_t ihl = b[0] & 0x0f;
    if (ihl < 5)
        return NP_ERR_IPV4_IHL;
    size_t hl = (size_t)ihl * 4;
    if (hl > avail)
        return NP_ERR_TRUNC_IPV4;
    uint16_t tot = np_be16(b + 2);
    if (tot < hl)
        return NP_ERR_IPV4_TOTLEN;
    uint16_t frag = np_be16(b + 6);
    uint32_t fo = (uint32_t)(frag & 0x1fff) * 8;
    if (fo + (tot - hl) > 65535)
        return NP_ERR_IPV4_FRAG;
    if (hl > 20) {
        np_err e = check_ipv4_options(b + 20, hl - 20);
        if (e != NP_OK)
            return e;
        pkt->flags |= NP_F_IP_OPTIONS;
    }

    pkt->ip4.ihl = ihl;
    pkt->ip4.tos = b[1];
    pkt->ip4.tot_len = tot;
    pkt->ip4.id = np_be16(b + 4);
    pkt->ip4.df = (frag >> 14) & 1;
    pkt->ip4.mf = (frag >> 13) & 1;
    pkt->ip4.frag_off = (uint16_t)fo;
    pkt->ip4.opt_len = (uint8_t)(hl - 20);
    pkt->ip_ttl = b[8];
    pkt->ip_proto = b[9];
    pkt->ip4.csum = np_be16(b + 10);
    pkt->ip4.src = np_be32(b + 12);
    pkt->ip4.dst = np_be32(b + 16);
    pkt->l3_off = (uint16_t)off;
    pkt->layers |= NP_L_IPV4;

    if ((opts & NP_OPT_IP_CSUM) && np_csum_fold(np_csum_partial(b, hl, 0)) != 0xffff)
        pkt->flags |= NP_F_IP_CSUM_BAD;

    size_t lim = l3_limit(pkt, avail, tot);
    size_t decl = tot - hl;
    size_t cap = lim - hl;
    int is_frag = pkt->ip4.mf || fo;
    if (is_frag)
        pkt->flags |= NP_F_IP_FRAG;
    if (fo) {
        pkt->flags |= NP_F_IP_FRAG_LATER;
        pkt->l4_off = pkt->payload_off = (uint16_t)(off + hl);
        pkt->payload_len = (uint16_t)decl;
        pkt->payload_caplen = (uint16_t)cap;
        return NP_OK;
    }
    return parse_l4(pkt, off + hl, decl, cap, opts, is_frag);
}

static int is_ipv6_ext(uint8_t nh)
{
    return nh == 0 || nh == 43 || nh == 44 || nh == 60;
}

static np_err parse_ipv6(np_packet *pkt, size_t off, unsigned opts)
{
    const uint8_t *b = pkt->data + off;
    size_t avail = pkt->caplen - off;
    if (avail < 40)
        return NP_ERR_TRUNC_IPV6;
    if ((b[0] >> 4) != 6)
        return NP_ERR_IPV6_VERSION;
    uint32_t w0 = np_be32(b);
    uint16_t plen = np_be16(b + 4);
    uint8_t nh = b[6];
    pkt->ip6.traffic_class = (uint8_t)(w0 >> 20);
    pkt->ip6.flow_label = w0 & 0xfffff;
    pkt->ip6.payload_len = plen;
    pkt->ip6.src_off = (uint16_t)(off + 8);
    pkt->ip6.dst_off = (uint16_t)(off + 24);
    pkt->ip6.frag_off = 0;
    pkt->ip6.frag_id = 0;
    pkt->ip6.ext_count = 0;
    pkt->ip_ttl = b[7];
    pkt->l3_off = (uint16_t)off;
    pkt->layers |= NP_L_IPV6;

    size_t lim = l3_limit(pkt, avail, (size_t)plen + 40);
    size_t pos = off + 40;
    size_t decl = plen;
    size_t cap = lim - 40;
    int frag = 0;
    while (is_ipv6_ext(nh)) {
        if (pkt->ip6.ext_count == NP_MAX_IPV6_EXT)
            return NP_ERR_IPV6_EXTHDR;
        if (decl < 8)
            return NP_ERR_IPV6_EXTHDR;
        if (cap < 8)
            return NP_ERR_TRUNC_IPV6;
        const uint8_t *e = pkt->data + pos;
        size_t len;
        if (nh == 44) {
            len = 8;
            uint16_t fo = np_be16(e + 2) & 0xfff8;
            pkt->ip6.frag_off = fo;
            pkt->ip6.frag_id = np_be32(e + 4);
            if (fo || (e[3] & 1))
                frag = 1;
            pkt->flags |= NP_F_IP_FRAG;
            if (fo)
                pkt->flags |= NP_F_IP_FRAG_LATER;
        } else {
            len = ((size_t)e[1] + 1) * 8;
        }
        if (len > decl)
            return NP_ERR_IPV6_EXTHDR;
        if (len > cap)
            return NP_ERR_TRUNC_IPV6;
        nh = e[0];
        pos += len;
        decl -= len;
        cap -= len;
        pkt->ip6.ext_count++;
    }
    pkt->ip_proto = nh;
    if (pkt->flags & NP_F_IP_FRAG_LATER) {
        pkt->l4_off = pkt->payload_off = (uint16_t)pos;
        pkt->payload_len = (uint16_t)decl;
        pkt->payload_caplen = (uint16_t)cap;
        return NP_OK;
    }
    return parse_l4(pkt, pos, decl, cap, opts, frag);
}

/* ---- Entry points ---------------------------------------------------- */

static void reset(np_packet *pkt, const uint8_t *buf, size_t caplen)
{
    pkt->data = buf;
    /* Offsets are 16-bit; anything past 64 KiB cannot hold a header we
     * parse, and IP datagrams are at most 65535 + L2 bytes. */
    pkt->caplen = caplen > 0x7fffffffu ? 0x7fffffffu : (uint32_t)caplen;
    pkt->layers = 0;
    pkt->flags = 0;
    pkt->l3_off = pkt->l4_off = pkt->payload_off = 0;
    pkt->payload_len = pkt->payload_caplen = 0;
    pkt->ethertype = 0;
    pkt->vlan_count = 0;
    pkt->ip_proto = 0;
    pkt->ip_ttl = 0;
}

np_err np_parse_eth(const uint8_t *buf, size_t caplen, np_packet *pkt,
                    unsigned opts)
{
    if (NP_UNLIKELY(!buf || !pkt))
        return NP_ERR_NULL;
    reset(pkt, buf, caplen);
    if (NP_UNLIKELY(pkt->caplen < 14))
        return NP_ERR_TRUNC_ETH;
    pkt->layers = NP_L_ETH;
    uint16_t type = np_be16(buf + 12);
    size_t off = 14;
    while (type == NP_ETHERTYPE_VLAN || type == NP_ETHERTYPE_QINQ ||
           type == NP_ETHERTYPE_QINQ_OLD) {
        if (pkt->vlan_count == NP_MAX_VLAN)
            return NP_ERR_VLAN_DEPTH;
        if (pkt->caplen - off < 4)
            return NP_ERR_TRUNC_VLAN;
        pkt->vlan_tpid[pkt->vlan_count] = type;
        pkt->vlan_tci[pkt->vlan_count] = np_be16(buf + off);
        type = np_be16(buf + off + 2);
        pkt->vlan_count++;
        pkt->layers |= NP_L_VLAN;
        off += 4;
    }
    pkt->ethertype = type;
    if (NP_LIKELY(type == NP_ETHERTYPE_IPV4))
        return parse_ipv4(pkt, off, opts);
    if (type == NP_ETHERTYPE_IPV6)
        return parse_ipv6(pkt, off, opts);
    return NP_OK;
}

np_err np_parse_ip(const uint8_t *buf, size_t caplen, np_packet *pkt,
                   unsigned opts)
{
    if (!buf || !pkt)
        return NP_ERR_NULL;
    reset(pkt, buf, caplen);
    if (pkt->caplen < 1)
        return NP_ERR_TRUNC_IPV4;
    if ((buf[0] >> 4) == 6) {
        pkt->ethertype = NP_ETHERTYPE_IPV6;
        return parse_ipv6(pkt, 0, opts);
    }
    pkt->ethertype = NP_ETHERTYPE_IPV4;
    return parse_ipv4(pkt, 0, opts);
}

/* ---- Formatting ------------------------------------------------------ */

int np_fmt_ipv4(uint32_t a, char *out, size_t outlen)
{
    return snprintf(out, outlen, "%u.%u.%u.%u", (a >> 24) & 0xff,
                    (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff);
}

int np_fmt_ipv6(const uint8_t *addr16, char *out, size_t outlen)
{
    char tmp[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, addr16, tmp, sizeof tmp))
        return -1;
    return snprintf(out, outlen, "%s", tmp);
}
