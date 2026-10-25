/* SPDX-License-Identifier: MIT
 * Internal: alignment-safe big-endian loads. memcpy into a local avoids
 * unaligned-access UB; compilers lower it to a single (movbe/bswap) load. */
#ifndef NP_LOAD_H
#define NP_LOAD_H

#include <stdint.h>
#include <string.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define NP_BSWAP16(x) __builtin_bswap16(x)
#define NP_BSWAP32(x) __builtin_bswap32(x)
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define NP_BSWAP16(x) (x)
#define NP_BSWAP32(x) (x)
#else
#error "unknown byte order"
#endif

static inline uint16_t np_be16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof v);
    return (uint16_t)NP_BSWAP16(v);
}

static inline uint32_t np_be32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof v);
    return (uint32_t)NP_BSWAP32(v);
}

static inline uint16_t np_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint32_t np_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

#if defined(__GNUC__) || defined(__clang__)
#define NP_LIKELY(x)   __builtin_expect(!!(x), 1)
#define NP_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define NP_LIKELY(x)   (x)
#define NP_UNLIKELY(x) (x)
#endif

#endif
