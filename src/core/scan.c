#define _GNU_SOURCE
/*
 * scan.c -- streaming physical memory scan.
 *
 * The classic bug in this kind of code is missing matches that straddle a
 * chunk boundary.  We carry the last (needle_len - 1) bytes of every chunk
 * into the next one, so a pattern is found exactly once no matter where it
 * lands.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>

#define SCAN_CHUNK      (8u * 1024u * 1024u)
#define SCAN_MAX_NEEDLE (1u << 20)

struct vmem_scanner {
    vmem_mem *mem;
    uint64_t end_gpa;
    uint8_t *needle;
    size_t nlen;
    uint8_t *buf;
    size_t buf_len;
    size_t pos;
    uint64_t buf_gpa;
    uint8_t *carry;
    size_t carry_len;
    size_t carry_cap;
    uint64_t cur;
    int loaded;
    int done;
};

vmem_scanner *vmem_scanner_new(vmem_mem *m, uint64_t start_gpa,
                               uint64_t end_gpa, const void *needle,
                               size_t nlen)
{
    vmem_scanner *s;

    if (!m || !needle || nlen == 0 || nlen > SCAN_MAX_NEEDLE) return NULL;
    if (end_gpa == 0 || end_gpa > vmem_max_gpa(m)) end_gpa = vmem_max_gpa(m);
    if (start_gpa > vmem_max_gpa(m)) start_gpa = vmem_max_gpa(m);

    s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->carry_cap = nlen - 1;
    s->needle = malloc(nlen);
    s->buf = malloc(SCAN_CHUNK + s->carry_cap);
    if (s->carry_cap) s->carry = malloc(s->carry_cap);
    if (!s->needle || !s->buf || (s->carry_cap && !s->carry)) {
        free(s->needle);
        free(s->buf);
        free(s->carry);
        free(s);
        return NULL;
    }
    memcpy(s->needle, needle, nlen);
    s->nlen = nlen;
    s->mem = m;
    s->cur = start_gpa;
    s->end_gpa = end_gpa;
    s->done = (start_gpa >= end_gpa);
    return s;
}

void vmem_scanner_free(vmem_scanner *s)
{
    if (!s) return;
    free(s->needle);
    free(s->buf);
    free(s->carry);
    free(s);
}

int vmem_scanner_next(vmem_scanner *s, uint64_t *gpa)
{
    if (!s || !gpa) return VMEM_EINVAL;

    for (;;) {
        if (s->loaded) {
            if (s->pos + s->nlen <= s->buf_len) {
                void *hit = memmem(s->buf + s->pos, s->buf_len - s->pos,
                                   s->needle, s->nlen);
                if (hit) {
                    size_t idx = (size_t)((uint8_t *)hit - s->buf);
                    s->pos = idx + 1;
                    *gpa = s->buf_gpa + (uint64_t)idx;
                    return 1;
                }
            }
            /* keep the tail for patterns crossing into the next chunk */
            {
                size_t keep = s->buf_len < s->carry_cap
                            ? s->buf_len : s->carry_cap;
                if (keep) memmove(s->carry, s->buf + s->buf_len - keep, keep);
                s->carry_len = keep;
            }
            s->loaded = 0;
            continue;
        }

        if (s->cur >= s->end_gpa) {
            s->done = 1;
            return 0;
        }

        {
            const vmem_segment *seg = vmem_seg_for(s->mem, s->cur);
            uint64_t seg_end;
            uint64_t remain;
            size_t toread;
            size_t prefix;

            if (!seg) {
                const vmem_segment *next = vmem_seg_after(s->mem, s->cur);
                if (!next) { s->done = 1; return 0; }
                s->cur = next->gpa;
                s->carry_len = 0;
                continue;
            }

            seg_end = seg->gpa + seg->size;
            if (seg_end > s->end_gpa) seg_end = s->end_gpa;
            if (s->cur >= seg_end) {
                /* moved past this segment; next loop iteration handles it */
                s->cur = seg_end;
                s->carry_len = 0;
                continue;
            }

            remain = seg_end - s->cur;
            toread = remain > SCAN_CHUNK ? SCAN_CHUNK : (size_t)remain;
            prefix = s->carry_len;
            if (prefix) memcpy(s->buf, s->carry, prefix);
            vmem_read_phys(s->mem, s->cur, s->buf + prefix, toread);

            s->buf_len = prefix + toread;
            s->buf_gpa = s->cur - prefix;
            s->pos = 0;
            s->cur += toread;
            s->carry_len = 0;
            s->loaded = 1;
        }
    }
}

int vmem_scan(vmem_mem *m, uint64_t start_gpa, uint64_t end_gpa,
              const void *needle, size_t nlen, vmem_hit_cb cb, void *user)
{
    vmem_scanner *s = vmem_scanner_new(m, start_gpa, end_gpa, needle, nlen);
    uint64_t gpa;
    int rc = 1;

    if (!s) return VMEM_EINVAL;
    while ((rc = vmem_scanner_next(s, &gpa)) == 1) {
        int stop = cb ? cb(user, gpa) : 0;
        if (stop) break;
    }
    vmem_scanner_free(s);
    return rc < 0 ? rc : 0;
}
