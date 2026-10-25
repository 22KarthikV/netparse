/* SPDX-License-Identifier: MIT
 * libFuzzer / AFL++ harness for the packet parser and flow tracker.
 * Byte 0 selects the entry point and options; the rest is the frame.
 * Beyond sanitizer findings, abort() on any broken invariant. */
#include "netparse/flow.h"
#include "netparse/netparse.h"

#include <stdlib.h>
#include <string.h>

static np_flow slots[16];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;
    uint8_t sel = data[0];
    data++;
    size--;
    /* Copy into an exact-size allocation so ASan sees any over-read. */
    uint8_t *buf = malloc(size ? size : 1);
    if (!buf)
        return 0;
    memcpy(buf, data, size);
    unsigned opts = sel & (NP_OPT_IP_CSUM | NP_OPT_L4_CSUM);
    np_packet p;
    np_err e = (sel & 0x80) ? np_parse_ip(buf, size, &p, opts)
                            : np_parse_eth(buf, size, &p, opts);
    if ((unsigned)e >= NP_ERR__COUNT)
        abort();
    if (e == NP_OK && (p.layers & (NP_L_IPV4 | NP_L_IPV6))) {
        if (p.l3_off >= size || p.payload_caplen > p.payload_len ||
            (size_t)p.payload_off + p.payload_caplen > size)
            abort();
        if ((p.layers & NP_L_TCP) &&
            ((size_t)p.l4_off + (size_t)p.tcp.doff * 4 > size || p.tcp.opts.sack_count > NP_MAX_SACK))
            abort();
        if ((p.layers & NP_L_UDP) && (size_t)p.l4_off + 8 > size)
            abort();
        /* Feed the same packet through the flow tracker twice
         * (exercises retransmission paths). */
        np_flow_table t;
        np_flow_table_init(&t, slots, 16);
        unsigned ev;
        np_flow_update(&t, &p, 1, &ev);
        np_flow_update(&t, &p, 2, &ev);
        if (t.count > 1)
            abort();
    }
    free(buf);
    return 0;
}
