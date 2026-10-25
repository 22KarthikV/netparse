/* SPDX-License-Identifier: MIT
 * libFuzzer / AFL++ harness for the pcap reader, feeding every record
 * through the parser and one shared flow table. */
#include "netparse/flow.h"
#include "netparse/netparse.h"
#include "netparse/pcap.h"

#include <stdlib.h>

static np_flow slots[64];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    np_pcap r;
    if (np_pcap_open_mem(&r, data, size) != NP_PCAP_OK)
        return 0;
    np_flow_table t;
    np_flow_table_init(&t, slots, 64);
    np_pcap_rec rec;
    np_pcap_err pe;
    unsigned n = 0;
    while ((pe = np_pcap_next(&r, &rec)) == NP_PCAP_OK) {
        if (rec.data < data || rec.data + rec.caplen > data + size || r.pos > size)
            abort();
        np_packet p;
        np_err e = r.linktype == NP_LINKTYPE_RAW
                       ? np_parse_ip(rec.data, rec.caplen, &p, NP_OPT_IP_CSUM | NP_OPT_L4_CSUM)
                       : np_parse_eth(rec.data, rec.caplen, &p, NP_OPT_IP_CSUM | NP_OPT_L4_CSUM);
        if (e == NP_OK) {
            unsigned ev;
            np_flow_update(&t, &p, (uint64_t)rec.ts_sec * 1000000000ull + rec.ts_nsec, &ev);
        }
        if (++n > 100000)
            abort(); /* the reader must always make progress */
    }
    if (pe != NP_PCAP_EOF && pe != NP_PCAP_ERR_TRUNC_HDR && pe != NP_PCAP_ERR_TRUNC_DATA &&
        pe != NP_PCAP_ERR_CAPLEN)
        abort();
    return 0;
}
