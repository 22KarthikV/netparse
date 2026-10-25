/* SPDX-License-Identifier: MIT
 * netparse - zero-copy Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP parser.
 *
 * The parser never allocates and never copies packet bytes. It fills an
 * np_packet with decoded header fields (host byte order) and byte offsets
 * into the caller's buffer. Every read is bounds checked against the
 * captured length; nothing past buf[caplen - 1] is ever touched.
 */
#ifndef NETPARSE_H
#define NETPARSE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Return codes ---------------------------------------------------- */
typedef enum np_err {
    NP_OK = 0,
    NP_ERR_NULL,            /* NULL buffer or packet */
    NP_ERR_TRUNC_ETH,       /* fewer than 14 bytes */
    NP_ERR_TRUNC_VLAN,      /* VLAN tag cut short */
    NP_ERR_VLAN_DEPTH,      /* more than NP_MAX_VLAN tags */
    NP_ERR_TRUNC_IPV4,      /* IPv4 header (incl. options) cut short */
    NP_ERR_IPV4_VERSION,    /* version field != 4 */
    NP_ERR_IPV4_IHL,        /* IHL < 5 */
    NP_ERR_IPV4_TOTLEN,     /* total length < IHL*4 */
    NP_ERR_IPV4_OPTIONS,    /* malformed IPv4 option TLV */
    NP_ERR_IPV4_FRAG,       /* fragment offset + length overflows 65535 */
    NP_ERR_TRUNC_IPV6,      /* IPv6 header or extension header cut short */
    NP_ERR_IPV6_VERSION,    /* version field != 6 */
    NP_ERR_IPV6_EXTHDR,     /* extension header overruns payload / too many */
    NP_ERR_TRUNC_TCP,       /* TCP header (incl. options) cut short */
    NP_ERR_TCP_DOFF,        /* data offset < 5 or beyond IP payload */
    NP_ERR_TCP_OPTIONS,     /* malformed TCP option */
    NP_ERR_TRUNC_UDP,       /* UDP header cut short */
    NP_ERR_UDP_LEN,         /* UDP length < 8 or > IP payload */
    NP_ERR__COUNT
} np_err;

const char *np_strerror(np_err e);

/* ---- Layers present (np_packet.layers bitmask) ----------------------- */
enum {
    NP_L_ETH  = 1u << 0,
    NP_L_VLAN = 1u << 1,
    NP_L_IPV4 = 1u << 2,
    NP_L_IPV6 = 1u << 3,
    NP_L_TCP  = 1u << 4,
    NP_L_UDP  = 1u << 5
};

/* ---- Informational flags (np_packet.flags) --------------------------- */
enum {
    NP_F_TRUNCATED     = 1u << 0, /* L3 length says more bytes than captured */
    NP_F_IP_FRAG       = 1u << 1, /* IPv4 MF set or offset != 0, or IPv6 frag hdr */
    NP_F_IP_OPTIONS    = 1u << 2, /* IPv4 header carries options */
    NP_F_IP_CSUM_BAD   = 1u << 3, /* IPv4 header checksum mismatch (if verified) */
    NP_F_L4_CSUM_BAD   = 1u << 4, /* TCP/UDP checksum mismatch (if verified) */
    NP_F_ETH_PADDED    = 1u << 5, /* bytes after the L3 datagram (Ethernet pad) */
    NP_F_IP_FRAG_LATER = 1u << 6  /* non-first fragment: no L4 header present */
};

/* ---- Parse options (np_parse opts argument) -------------------------- */
enum {
    NP_OPT_IP_CSUM = 1u << 0,  /* verify IPv4 header checksum */
    NP_OPT_L4_CSUM = 1u << 1   /* verify TCP/UDP checksum (needs full capture) */
};

/* TCP flag bits as in the header */
enum {
    NP_TCP_FIN = 0x01, NP_TCP_SYN = 0x02, NP_TCP_RST = 0x04, NP_TCP_PSH = 0x08,
    NP_TCP_ACK = 0x10, NP_TCP_URG = 0x20, NP_TCP_ECE = 0x40, NP_TCP_CWR = 0x80
};

/* TCP options present (np_tcp_opts.present bitmask) */
enum {
    NP_TCPOPT_MSS     = 1u << 0,
    NP_TCPOPT_WSCALE  = 1u << 1,
    NP_TCPOPT_SACK_OK = 1u << 2,
    NP_TCPOPT_SACK    = 1u << 3,
    NP_TCPOPT_TS      = 1u << 4,
    NP_TCPOPT_UNKNOWN = 1u << 5
};

#define NP_MAX_VLAN       2   /* 802.1Q, or 802.1ad + 802.1Q (QinQ) */
#define NP_MAX_SACK       4
#define NP_MAX_IPV6_EXT   8

#define NP_ETHERTYPE_IPV4  0x0800
#define NP_ETHERTYPE_IPV6  0x86DD
#define NP_ETHERTYPE_VLAN  0x8100
#define NP_ETHERTYPE_QINQ  0x88A8
#define NP_ETHERTYPE_QINQ_OLD 0x9100

#define NP_IPPROTO_TCP 6
#define NP_IPPROTO_UDP 17

typedef struct np_sack_block {
    uint32_t left, right;
} np_sack_block;

typedef struct np_tcp_opts {
    uint8_t  present;       /* NP_TCPOPT_* */
    uint8_t  wscale;
    uint8_t  sack_count;    /* 0..NP_MAX_SACK */
    uint8_t  _pad;
    uint16_t mss;
    uint32_t ts_val, ts_ecr;
    np_sack_block sack[NP_MAX_SACK];
} np_tcp_opts;

typedef struct np_packet {
    const uint8_t *data;     /* caller's buffer (not owned, not copied) */
    uint32_t caplen;         /* bytes available in data */
    uint32_t layers;         /* NP_L_* */
    uint32_t flags;          /* NP_F_* */

    /* Offsets into data. Valid only when the matching layer bit is set. */
    uint16_t l3_off;         /* start of IPv4/IPv6 header */
    uint16_t l4_off;         /* start of TCP/UDP header */
    uint16_t payload_off;    /* start of L4 payload */
    uint16_t ethertype;      /* innermost ethertype after VLAN tags */

    /* L4 payload length according to the headers, and how many of those
     * bytes are actually present in the capture (<= payload_len). */
    uint16_t payload_len;
    uint16_t payload_caplen;

    uint8_t  vlan_count;
    uint8_t  _pad0;
    uint16_t vlan_tpid[NP_MAX_VLAN];
    uint16_t vlan_tci[NP_MAX_VLAN];   /* PCP(3) DEI(1) VID(12) */

    uint8_t  ip_proto;       /* L4 protocol (IPv4 proto / IPv6 final next hdr) */
    uint8_t  ip_ttl;         /* TTL / hop limit */

    struct {
        uint8_t  ihl;        /* in 32-bit words */
        uint8_t  tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;   /* offset in bytes */
        uint8_t  df, mf;
        uint8_t  opt_len;    /* bytes of options */
        uint8_t  _pad;
        uint16_t csum;
        uint32_t src, dst;   /* host byte order */
    } ip4;

    struct {
        uint16_t payload_len;
        uint8_t  traffic_class;
        uint8_t  ext_count;
        uint32_t flow_label;
        uint16_t src_off, dst_off; /* offsets of the 16-byte addresses */
        uint16_t frag_off;
        uint32_t frag_id;
    } ip6;

    struct {
        uint16_t sport, dport;
        uint32_t seq, ack;
        uint8_t  doff;       /* in 32-bit words */
        uint8_t  flags;      /* NP_TCP_* */
        uint16_t window;     /* unscaled */
        uint16_t csum, urg;
        np_tcp_opts opts;
    } tcp;

    struct {
        uint16_t sport, dport, len, csum;
    } udp;
} np_packet;

/* Parse an Ethernet II frame. On error the layers already decoded remain
 * valid (np_packet.layers says which). opts is a mask of NP_OPT_*. */
np_err np_parse_eth(const uint8_t *buf, size_t caplen, np_packet *pkt,
                    unsigned opts);

/* Parse a raw IP packet (LINKTYPE_RAW): version nibble picks IPv4/IPv6. */
np_err np_parse_ip(const uint8_t *buf, size_t caplen, np_packet *pkt,
                   unsigned opts);

/* RFC 1071 Internet checksum over a byte range, returned in host order
 * folded but not complemented. Exposed for tests. */
uint32_t np_csum_partial(const uint8_t *p, size_t len, uint32_t sum);
uint16_t np_csum_fold(uint32_t sum);

/* Format helpers (write NUL-terminated text, return bytes written). */
int np_fmt_ipv4(uint32_t addr, char *out, size_t outlen);
int np_fmt_ipv6(const uint8_t *addr16, char *out, size_t outlen);

#ifdef __cplusplus
}
#endif
#endif /* NETPARSE_H */
