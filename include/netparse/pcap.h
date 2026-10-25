/* SPDX-License-Identifier: MIT
 * Minimal reader for the classic libpcap file format (not pcapng).
 * Handles both byte orders and both microsecond (0xa1b2c3d4) and
 * nanosecond (0xa1b23c4d) timestamp variants. Records are returned as
 * pointers into the caller's buffer; nothing is copied.
 */
#ifndef NETPARSE_PCAP_H
#define NETPARSE_PCAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NP_PCAP_MAX_CAPLEN 262144u  /* same ceiling libpcap uses */

#define NP_LINKTYPE_ETHERNET 1
#define NP_LINKTYPE_RAW      101

typedef enum np_pcap_err {
    NP_PCAP_OK = 0,
    NP_PCAP_EOF,              /* clean end of file */
    NP_PCAP_ERR_NULL,
    NP_PCAP_ERR_SHORT,        /* fewer than 24 bytes of global header */
    NP_PCAP_ERR_MAGIC,        /* unknown magic (pcapng is not supported) */
    NP_PCAP_ERR_VERSION,      /* major version != 2 */
    NP_PCAP_ERR_TRUNC_HDR,    /* record header cut short */
    NP_PCAP_ERR_TRUNC_DATA,   /* record data cut short */
    NP_PCAP_ERR_CAPLEN,       /* incl_len larger than NP_PCAP_MAX_CAPLEN */
    NP_PCAP_ERR_IO            /* open/mmap failure (np_pcap_map_file) */
} np_pcap_err;

const char *np_pcap_strerror(np_pcap_err e);

typedef struct np_pcap {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    uint32_t snaplen;
    uint32_t linktype;   /* low 16 bits of the header field */
    uint16_t ver_major, ver_minor;
    uint8_t swapped;     /* file byte order differs from host */
    uint8_t nsec;        /* nanosecond timestamps */
} np_pcap;

typedef struct np_pcap_rec {
    const uint8_t *data; /* points into the mapped file */
    uint32_t caplen;     /* incl_len */
    uint32_t origlen;    /* orig_len (on-wire length) */
    uint32_t ts_sec;
    uint32_t ts_nsec;    /* always nanoseconds */
} np_pcap_rec;

/* Validate the global header and position at the first record. */
np_pcap_err np_pcap_open_mem(np_pcap *r, const void *buf, size_t len);

/* Return the next record. NP_PCAP_EOF at a clean end of file. Errors are
 * sticky: once a record is malformed the reader stops. */
np_pcap_err np_pcap_next(np_pcap *r, np_pcap_rec *rec);

/* Convenience: read-only mmap of a file (falls back to read() for pipes). */
typedef struct np_pcap_file {
    void *base;
    size_t len;
    int mapped;
} np_pcap_file;

np_pcap_err np_pcap_map_file(const char *path, np_pcap_file *f);
void np_pcap_unmap_file(np_pcap_file *f);

#ifdef __cplusplus
}
#endif
#endif
