/* SPDX-License-Identifier: MIT */
#define _POSIX_C_SOURCE 200809L
#include "netparse/pcap.h"
#include "load.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAGIC_US 0xa1b2c3d4u
#define MAGIC_NS 0xa1b23c4du

const char *np_pcap_strerror(np_pcap_err e)
{
    switch (e) {
    case NP_PCAP_OK: return "ok";
    case NP_PCAP_EOF: return "end of file";
    case NP_PCAP_ERR_NULL: return "null argument";
    case NP_PCAP_ERR_SHORT: return "file shorter than pcap global header";
    case NP_PCAP_ERR_MAGIC: return "not a classic pcap file (bad magic)";
    case NP_PCAP_ERR_VERSION: return "unsupported pcap version";
    case NP_PCAP_ERR_TRUNC_HDR: return "truncated record header";
    case NP_PCAP_ERR_TRUNC_DATA: return "truncated record data";
    case NP_PCAP_ERR_CAPLEN: return "record caplen too large";
    case NP_PCAP_ERR_IO: return "i/o error";
    }
    return "unknown error";
}

/* The file's byte order is fixed by the magic; read fields in that order
 * instead of "host order then swap" so the code is host independent. */
static uint32_t rd32(const np_pcap *r, const uint8_t *p)
{
    return r->swapped ? np_be32(p) : np_le32(p);
}

static uint16_t rd16(const np_pcap *r, const uint8_t *p)
{
    return r->swapped ? np_be16(p) : np_le16(p);
}

np_pcap_err np_pcap_open_mem(np_pcap *r, const void *buf, size_t len)
{
    if (!r || (!buf && len))
        return NP_PCAP_ERR_NULL;
    r->buf = buf;
    r->len = len;
    r->pos = 0;
    if (len < 24)
        return NP_PCAP_ERR_SHORT;
    const uint8_t *p = buf;
    /* "swapped" here means big-endian file. */
    uint32_t le = np_le32(p), be = np_be32(p);
    if (le == MAGIC_US || le == MAGIC_NS) {
        r->swapped = 0;
        r->nsec = le == MAGIC_NS;
    } else if (be == MAGIC_US || be == MAGIC_NS) {
        r->swapped = 1;
        r->nsec = be == MAGIC_NS;
    } else {
        return NP_PCAP_ERR_MAGIC;
    }
    r->ver_major = rd16(r, p + 4);
    r->ver_minor = rd16(r, p + 6);
    if (r->ver_major != 2)
        return NP_PCAP_ERR_VERSION;
    r->snaplen = rd32(r, p + 16);
    r->linktype = rd32(r, p + 20) & 0xffff;
    r->pos = 24;
    return NP_PCAP_OK;
}

np_pcap_err np_pcap_next(np_pcap *r, np_pcap_rec *rec)
{
    if (!r || !rec || !r->buf)
        return NP_PCAP_ERR_NULL;
    size_t left = r->len - r->pos;
    if (left == 0)
        return NP_PCAP_EOF;
    if (left < 16)
        return NP_PCAP_ERR_TRUNC_HDR;
    const uint8_t *h = r->buf + r->pos;
    uint32_t incl = rd32(r, h + 8);
    if (incl > NP_PCAP_MAX_CAPLEN)
        return NP_PCAP_ERR_CAPLEN;
    if (incl > left - 16)
        return NP_PCAP_ERR_TRUNC_DATA;
    rec->ts_sec = rd32(r, h);
    uint32_t frac = rd32(r, h + 4);
    if (r->nsec) {
        rec->ts_nsec = frac;
    } else {
        /* us -> ns. A bogus file can hold frac >= 1e6; clamp rather than wrap. */
        uint64_t ns = (uint64_t)frac * 1000u;
        rec->ts_nsec = ns > 0xffffffffu ? 0xffffffffu : (uint32_t)ns;
    }
    rec->caplen = incl;
    rec->origlen = rd32(r, h + 12);
    rec->data = h + 16;
    r->pos += 16 + (size_t)incl;
    return NP_PCAP_OK;
}

np_pcap_err np_pcap_map_file(const char *path, np_pcap_file *f)
{
    if (!path || !f)
        return NP_PCAP_ERR_NULL;
    f->base = NULL;
    f->len = 0;
    f->mapped = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NP_PCAP_ERR_IO;
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        if (st.st_size == 0) {
            close(fd);
            return NP_PCAP_OK;
        }
        void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (m == MAP_FAILED)
            return NP_PCAP_ERR_IO;
        f->base = m;
        f->len = (size_t)st.st_size;
        f->mapped = 1;
        return NP_PCAP_OK;
    }
    /* Not a regular file (pipe, /dev/stdin): slurp it. */
    size_t cap = 1 << 16, n = 0;
    uint8_t *b = malloc(cap);
    if (!b) {
        close(fd);
        return NP_PCAP_ERR_IO;
    }
    for (;;) {
        if (n == cap) {
            uint8_t *nb = realloc(b, cap * 2);
            if (!nb) {
                free(b);
                close(fd);
                return NP_PCAP_ERR_IO;
            }
            b = nb;
            cap *= 2;
        }
        ssize_t got = read(fd, b + n, cap - n);
        if (got < 0) {
            free(b);
            close(fd);
            return NP_PCAP_ERR_IO;
        }
        if (got == 0)
            break;
        n += (size_t)got;
    }
    close(fd);
    f->base = b;
    f->len = n;
    return NP_PCAP_OK;
}

void np_pcap_unmap_file(np_pcap_file *f)
{
    if (!f || !f->base)
        return;
    if (f->mapped)
        munmap(f->base, f->len);
    else
        free(f->base);
    f->base = NULL;
    f->len = 0;
}
