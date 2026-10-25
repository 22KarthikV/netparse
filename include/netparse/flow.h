/* SPDX-License-Identifier: MIT
 * Fixed-size TCP/UDP flow table keyed on the 5-tuple.
 *
 * The caller provides the slot array, so the tracker never allocates.
 * Open addressing with linear probing; both directions of a connection map
 * to the same slot. Once the table reaches 7/8 occupancy new flows are
 * counted in np_flow_table.dropped instead of being inserted.
 *
 * Per-direction TCP analysis (definitions used by this library):
 *   in-order       seq == highest sequence end seen so far (max_seq_end)
 *   gap            seq is after max_seq_end; [max_seq_end, seq) becomes a hole
 *   out-of-order   segment lies entirely inside a recorded hole and arrives
 *                  within ooo_threshold_ns (default 3 ms, as in Wireshark)
 *                  of the packet that opened the hole; later than that it
 *                  is a retransmission of data lost before the capture point
 *   retransmission segment starts before max_seq_end and is not wholly inside
 *                  a hole (covers bytes already seen), excluding keep-alives
 *   keep-alive     payload <= 1, seq == max_seq_end - 1, no SYN/FIN/RST
 *   duplicate ACK  no payload, no SYN/FIN/RST, same ack and window as the
 *                  previous packet in that direction
 *   zero window    window field is 0 on a packet without SYN/FIN/RST
 *   SACK event     packet carries a SACK option (blocks counted separately)
 * Holes are dropped once the reverse direction acknowledges past them.
 */
#ifndef NETPARSE_FLOW_H
#define NETPARSE_FLOW_H

#include "netparse/netparse.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NP_FLOW_MAX_HOLES 8

typedef struct np_flow_key {
    uint8_t addr[2][16];  /* canonical order: side 0 < side 1 */
    uint16_t port[2];
    uint8_t family;       /* 4 or 6 */
    uint8_t proto;
    uint16_t _pad;
} np_flow_key;

typedef struct np_seq_hole {
    uint32_t left, right; /* [left, right) */
    uint64_t ts_ns;       /* when the gap was observed */
} np_seq_hole;

typedef struct np_flow_dir {
    uint64_t packets;
    uint64_t bytes;          /* L3 datagram bytes (IP total length) */
    uint64_t payload_bytes;  /* L4 payload bytes */
    uint32_t retransmits;
    uint32_t out_of_order;
    uint32_t keepalives;
    uint32_t dup_acks;
    uint32_t zero_windows;
    uint32_t sack_packets;
    uint32_t sack_blocks;
    uint32_t syn, fin, rst;
    uint32_t holes_lost;     /* holes discarded because the hole array was full */

    uint32_t max_seq_end;
    uint32_t last_ack;
    uint16_t last_win;
    uint16_t mss;            /* from SYN, 0 if not seen */
    uint8_t  wscale;         /* from SYN, 0xff if not seen */
    uint8_t  seq_valid, ack_valid;
    uint8_t  nholes;
    np_seq_hole holes[NP_FLOW_MAX_HOLES];
} np_flow_dir;

typedef struct np_flow {
    np_flow_key key;
    uint32_t hash;
    uint8_t used;
    uint8_t initiator;       /* key side that sent the first packet */
    uint16_t _pad;
    uint64_t first_ts_ns, last_ts_ns;
    np_flow_dir dir[2];      /* indexed by key side of the sender */
} np_flow;

typedef struct np_flow_table {
    np_flow *slots;
    uint32_t mask;
    uint32_t count;
    uint32_t limit;          /* max flows inserted (7/8 of slots) */
    uint64_t dropped;        /* packets of new flows refused: table full */
    uint64_t ooo_threshold_ns;
} np_flow_table;

/* Per-packet result of np_flow_update (bitmask). */
enum {
    NP_FEV_NEW_FLOW   = 1u << 0,
    NP_FEV_RETRANS    = 1u << 1,
    NP_FEV_OOO        = 1u << 2,
    NP_FEV_DUP_ACK    = 1u << 3,
    NP_FEV_SACK       = 1u << 4,
    NP_FEV_ZERO_WIN   = 1u << 5,
    NP_FEV_KEEPALIVE  = 1u << 6
};

/* nslots must be a power of two >= 8. storage must hold nslots flows. */
int np_flow_table_init(np_flow_table *t, np_flow *storage, size_t nslots);

/* Account one parsed packet. Packets without TCP/UDP are ignored (returns
 * NULL). *events (optional) receives NP_FEV_* bits for this packet. */
np_flow *np_flow_update(np_flow_table *t, const np_packet *pkt,
                        uint64_t ts_ns, unsigned *events);

/* Lookup without modifying. */
np_flow *np_flow_lookup(np_flow_table *t, const np_packet *pkt);

/* Iterate occupied slots: start with *cursor = 0. */
np_flow *np_flow_next(np_flow_table *t, size_t *cursor);

#ifdef __cplusplus
}
#endif
#endif
