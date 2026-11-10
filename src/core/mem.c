/*
 * mem.c -- the guest physical memory object: segment table, reads, typed
 * accessors.  This is the layer every backend feeds into.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- */
/* little endian helpers (guests are x86-64/arm64, both LE)          */
/* ---------------------------------------------------------------- */

uint16_t vmem_le16(const void *p)
{
    const uint8_t *b = p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}

uint32_t vmem_le32(const void *p)
{
    const uint8_t *b = p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

uint64_t vmem_le64(const void *p)
{
    const uint8_t *b = p;
    return (uint64_t)vmem_le32(b) | ((uint64_t)vmem_le32(b + 4) << 32);
}

uint64_t vmem_mask_base(vmem_arch arch, uint64_t base)
{
    switch (arch) {
    case VMEM_ARCH_X86_64:
        return base & 0x000FFFFFFFFFF000ULL;
    case VMEM_ARCH_ARM64:
        /* TTBR0/TTBR1 carry an ASID/CnP in bits 63:48 */
        return base & 0x0000FFFFFFFFF000ULL;
    default:
        return base;
    }
}

/* ---------------------------------------------------------------- */
/* segment lookup                                                    */
/* ---------------------------------------------------------------- */

static int seg_cmp(const void *a, const void *b)
{
    const vmem_segment *x = a, *y = b;
    if (x->gpa < y->gpa) return -1;
    if (x->gpa > y->gpa) return 1;
    return 0;
}

const vmem_segment *vmem_seg_for(const vmem_mem *m, uint64_t gpa)
{
    size_t lo = 0, hi = m->nsegs;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (m->segs[mid].gpa <= gpa) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return NULL;
    {
        const vmem_segment *s = &m->segs[lo - 1];
        if (gpa - s->gpa < s->size) return s;
    }
    return NULL;
}

const vmem_segment *vmem_seg_after(const vmem_mem *m, uint64_t gpa)
{
    size_t lo = 0, hi = m->nsegs;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (m->segs[mid].gpa <= gpa) lo = mid + 1;
        else hi = mid;
    }
    return lo < m->nsegs ? &m->segs[lo] : NULL;
}

int vmem_read_at(vmem_mem *m, uint64_t off, void *buf, size_t len, size_t *got)
{
    if (!m->read_at) {
        *got = 0;
        return VMEM_EIO;
    }
    return m->read_at(m->ctx, off, buf, len, got);
}

/* ---------------------------------------------------------------- */
/* construction / destruction                                        */
/* ---------------------------------------------------------------- */

static vmem_mem *
open_custom_full(vmem_read_at_cb read_at, vmem_write_at_cb write_at,
                 vmem_destroy_cb destroy, void *ctx,
                 const vmem_segment *segs, size_t nsegs,
                 vmem_arch arch, int *err)
{
    vmem_mem *m = calloc(1, sizeof(*m));
    if (!m) { if (err) *err = VMEM_ENOMEM; return NULL; }
    if (nsegs == 0) {
        free(m);
        if (err) *err = VMEM_EINVAL;
        return NULL;
    }
    m->segs = calloc(nsegs, sizeof(*m->segs));
    if (!m->segs) {
        free(m);
        if (err) *err = VMEM_ENOMEM;
        return NULL;
    }
    memcpy(m->segs, segs, nsegs * sizeof(*segs));
    m->nsegs = nsegs;
    qsort(m->segs, nsegs, sizeof(*m->segs), seg_cmp);

    m->arch = arch;
    m->read_at = read_at;
    m->write_at = write_at;
    m->destroy = destroy;
    m->ctx = ctx;

    m->min_gpa = UINT64_MAX;
    for (size_t i = 0; i < nsegs; i++) {
        const vmem_segment *s = &m->segs[i];
        if (s->size == 0) continue;
        if (s->gpa < m->min_gpa) m->min_gpa = s->gpa;
        if (s->size > UINT64_MAX - s->gpa) {
            /* refuse to wrap */
            free(m->segs);
            free(m);
            if (err) *err = VMEM_EINVAL;
            return NULL;
        }
        if (s->gpa + s->size > m->max_gpa) m->max_gpa = s->gpa + s->size;
        m->total_size += s->size;
    }
    if (m->min_gpa == UINT64_MAX) m->min_gpa = 0;
    if (err) *err = VMEM_OK;
    return m;
}

vmem_mem *vmem_open_custom(vmem_read_at_cb read_at, vmem_destroy_cb destroy,
                           void *ctx, const vmem_segment *segs, size_t nsegs,
                           vmem_arch arch, int *err)
{
    return open_custom_full(read_at, NULL, destroy, ctx, segs, nsegs, arch,
                            err);
}

vmem_mem *vmem_open_custom_rw(vmem_read_at_cb read_at,
                              vmem_write_at_cb write_at,
                              vmem_destroy_cb destroy, void *ctx,
                              const vmem_segment *segs, size_t nsegs,
                              vmem_arch arch, int *err)
{
    return open_custom_full(read_at, write_at, destroy, ctx, segs, nsegs, arch,
                            err);
}

int vmem_write_at(vmem_mem *m, uint64_t off, const void *buf, size_t len,
                  size_t *done)
{
    if (!m->write_at) {
        *done = 0;
        return VMEM_ENOTSUP;
    }
    return m->write_at(m->ctx, off, buf, len, done);
}

int vmem_write_phys(vmem_mem *m, uint64_t gpa, const void *buf, size_t len)
{
    const uint8_t *in = buf;
    size_t written = 0;

    while (written < len) {
        uint64_t cur = gpa + written;
        const vmem_segment *s = vmem_seg_for(m, cur);
        size_t in_seg, chunk, done = 0;

        if (!s) return VMEM_EIO;
        in_seg = (size_t)(cur - s->gpa);
        chunk = (size_t)(s->size - in_seg);
        if (chunk > len - written) chunk = len - written;

        /* Direct mmap segments are read-only in this build. */
        if (s->ptr) return VMEM_ENOTSUP;

        if (vmem_write_at(m, s->file_offset + in_seg, in + written, chunk,
                          &done) != VMEM_OK || done != chunk)
            return VMEM_EIO;
        written += chunk;
    }
    return VMEM_OK;
}

void vmem_close(vmem_mem *m)
{
    if (!m) return;
    if (m->destroy) m->destroy(m->ctx);
    free(m->segs);
    free(m);
}

void vmem_set_arch(vmem_mem *m, vmem_arch arch)
{
    if (m && arch != VMEM_ARCH_UNKNOWN) m->arch = arch;
}

vmem_arch vmem_arch_of(const vmem_mem *m) { return m ? m->arch : VMEM_ARCH_UNKNOWN; }
size_t vmem_segment_count(const vmem_mem *m) { return m ? m->nsegs : 0; }
const vmem_segment *vmem_segments(const vmem_mem *m) { return m ? m->segs : NULL; }
uint64_t vmem_min_gpa(const vmem_mem *m) { return m ? m->min_gpa : 0; }
uint64_t vmem_max_gpa(const vmem_mem *m) { return m ? m->max_gpa : 0; }
uint64_t vmem_total_size(const vmem_mem *m) { return m ? m->total_size : 0; }

/* ---------------------------------------------------------------- */
/* physical reads                                                    */
/* ---------------------------------------------------------------- */

size_t vmem_read_phys(vmem_mem *m, uint64_t gpa, void *buf, size_t len)
{
    uint8_t *out = buf;
    size_t done = 0;

    while (done < len) {
        uint64_t cur = gpa + done;
        const vmem_segment *s = vmem_seg_for(m, cur);

        if (!s) {
            size_t zero = len - done;
            const vmem_segment *next = vmem_seg_after(m, cur);
            if (next && next->gpa - cur < zero)
                zero = (size_t)(next->gpa - cur);
            memset(out + done, 0, zero);
            done += zero;
            continue;
        }

        size_t in_seg = (size_t)(cur - s->gpa);
        size_t chunk = (size_t)(s->size - in_seg);
        if (chunk > len - done) chunk = len - done;

        if (s->ptr) {
            memcpy(out + done, s->ptr + in_seg, chunk);
        } else {
            size_t got = 0;
            if (vmem_read_at(m, s->file_offset + in_seg, out + done, chunk,
                             &got) != VMEM_OK)
                got = 0;
            if (got > chunk) got = chunk;
            if (got < chunk) memset(out + done + got, 0, chunk - got);
        }
        done += chunk;
    }
    return done;
}

int vmem_read_phys_exact(vmem_mem *m, uint64_t gpa, void *buf, size_t len)
{
    uint8_t *out = buf;
    size_t done = 0;

    while (done < len) {
        uint64_t cur = gpa + done;
        const vmem_segment *s = vmem_seg_for(m, cur);
        if (!s) return VMEM_EIO;

        size_t in_seg = (size_t)(cur - s->gpa);
        size_t chunk = (size_t)(s->size - in_seg);
        if (chunk > len - done) chunk = len - done;

        if (s->ptr) {
            memcpy(out + done, s->ptr + in_seg, chunk);
        } else {
            size_t got = 0;
            if (vmem_read_at(m, s->file_offset + in_seg, out + done, chunk,
                             &got) != VMEM_OK || got != chunk)
                return VMEM_EIO;
        }
        done += chunk;
    }
    return VMEM_OK;
}

uint8_t vmem_phys_u8(vmem_mem *m, uint64_t gpa)
{
    uint8_t v = 0;
    vmem_read_phys(m, gpa, &v, 1);
    return v;
}

uint16_t vmem_phys_u16(vmem_mem *m, uint64_t gpa)
{
    uint8_t b[2] = {0};
    vmem_read_phys(m, gpa, b, 2);
    return vmem_le16(b);
}

uint32_t vmem_phys_u32(vmem_mem *m, uint64_t gpa)
{
    uint8_t b[4] = {0};
    vmem_read_phys(m, gpa, b, 4);
    return vmem_le32(b);
}

uint64_t vmem_phys_u64(vmem_mem *m, uint64_t gpa)
{
    uint8_t b[8] = {0};
    vmem_read_phys(m, gpa, b, 8);
    return vmem_le64(b);
}
