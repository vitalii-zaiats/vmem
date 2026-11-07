/*
 * arch.c -- virtual address translation and virtual memory access.
 *
 * Two page-table formats, selected by the address space's arch:
 *   x86-64: 4 level, 4 KiB granule, 1 GiB / 2 MiB large pages.
 *   ARM64 : 4 level, 4 KiB granule, TTBR0/TTBR1 split, 1 GiB / 2 MiB blocks.
 *
 * All reads go through the physical read API, so this works identically for
 * a file dump, an ELF core, or live /proc/<pid>/mem.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* physical u64 helper (page tables are always little endian)         */
/* ------------------------------------------------------------------ */

static int read_pte(vmem_mem *m, uint64_t gpa, uint64_t *out)
{
    uint8_t b[8];
    if (vmem_read_phys_exact(m, gpa, b, 8) != VMEM_OK) return -1;
    *out = vmem_le64(b);
    return 0;
}

/* ------------------------------------------------------------------ */
/* x86-64                                                             */
/* ------------------------------------------------------------------ */

int vmem_translate_x86_64(const vmem_space *s, uint64_t va, uint64_t *pa)
{
    uint64_t base = vmem_mask_base(VMEM_ARCH_X86_64, s->base0);
    uint64_t e;

    if (!base) return -1;

    if (read_pte(s->mem, base + ((va >> 39) & 0x1FF) * 8, &e) != 0) return -1;
    if (!(e & 1)) return -1;

    if (read_pte(s->mem, (e & 0x000FFFFFFFFFF000ULL) +
                        ((va >> 30) & 0x1FF) * 8, &e) != 0) return -1;
    if (!(e & 1)) return -1;
    if (e & 0x80) { /* 1 GiB */
        *pa = (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
        return 0;
    }

    if (read_pte(s->mem, (e & 0x000FFFFFFFFFF000ULL) +
                        ((va >> 21) & 0x1FF) * 8, &e) != 0) return -1;
    if (!(e & 1)) return -1;
    if (e & 0x80) { /* 2 MiB */
        *pa = (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
        return 0;
    }

    if (read_pte(s->mem, (e & 0x000FFFFFFFFFF000ULL) +
                        ((va >> 12) & 0x1FF) * 8, &e) != 0) return -1;
    if (!(e & 1)) return -1;

    *pa = (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
    return 0;
}

/* ------------------------------------------------------------------ */
/* ARM64                                                              */
/* ------------------------------------------------------------------ */

#define ARM64_TABLE_MASK 0x0000FFFFFFFFF000ULL
#define ARM64_L2_MASK    0x0000FFFFFFE00000ULL /* 2 MiB block */
#define ARM64_L1_MASK    0x0000FFFFC0000000ULL /* 1 GiB block */

int vmem_translate_arm64(const vmem_space *s, uint64_t va, uint64_t *pa)
{
    uint64_t base;
    uint64_t table;

    /* TTBR1 covers the high half; TTBR0 the low half. */
    base = (s->has_base1 && (va >> 63)) ? s->base1 : s->base0;
    base = vmem_mask_base(VMEM_ARCH_ARM64, base);
    if (!base) return -1;
    table = base;

    for (int level = 0; level <= 3; level++) {
        int shift = 39 - 9 * level;
        uint64_t idx = (va >> shift) & 0x1FF;
        uint64_t d;

        if (read_pte(s->mem, table + idx * 8, &d) != 0) return -1;
        if (!(d & 1)) return -1; /* invalid */

        if (level == 3) {
            if (!(d & 2)) return -1; /* level 3 must be a page */
            *pa = (d & ARM64_TABLE_MASK) | (va & 0xFFFULL);
            return 0;
        }

        if (d & 2) { /* table descriptor */
            table = d & ARM64_TABLE_MASK;
            if (!table) return -1;
            continue;
        }

        /* block descriptor: 1 GiB at level 1, 2 MiB at level 2 */
        if (level == 1) {
            *pa = (d & ARM64_L1_MASK) | (va & 0x3FFFFFFFULL);
            return 0;
        }
        if (level == 2) {
            *pa = (d & ARM64_L2_MASK) | (va & 0x1FFFFFULL);
            return 0;
        }
        return -1; /* level 0 blocks are reserved */
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* spaces                                                             */
/* ------------------------------------------------------------------ */

vmem_space *vmem_space_new(vmem_mem *m, vmem_arch arch, uint64_t base0,
                           uint64_t base1, int has_base1)
{
    vmem_space *s;
    if (!m) return NULL;
    if (arch == VMEM_ARCH_UNKNOWN) arch = m->arch;
    s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->mem = m;
    s->arch = arch;
    s->base0 = base0;
    s->base1 = base1;
    s->has_base1 = has_base1;
    return s;
}

void vmem_space_free(vmem_space *s) { free(s); }

vmem_arch vmem_space_arch(const vmem_space *s) { return s->arch; }
uint64_t vmem_space_base0(const vmem_space *s) { return s->base0; }
uint64_t vmem_space_base1(const vmem_space *s) { return s->base1; }

int vmem_translate(const vmem_space *s, uint64_t va, uint64_t *pa)
{
    if (!s || !s->mem) return -1;
    switch (s->arch) {
    case VMEM_ARCH_X86_64: return vmem_translate_x86_64(s, va, pa);
    case VMEM_ARCH_ARM64:  return vmem_translate_arm64(s, va, pa);
    default:               return -1;
    }
}

size_t vmem_space_read(const vmem_space *s, uint64_t va, void *buf, size_t len)
{
    uint8_t *out = buf;
    size_t done = 0;

    while (done < len) {
        uint64_t cur = va + done;
        size_t page_off = (size_t)(cur & 0xFFF);
        size_t chunk = 0x1000 - page_off;
        uint64_t pa;

        if (chunk > len - done) chunk = len - done;
        if (vmem_translate(s, cur, &pa) != 0)
            memset(out + done, 0, chunk);
        else
            vmem_read_phys(s->mem, pa, out + done, chunk);
        done += chunk;
    }
    return done;
}

int vmem_space_read_exact(const vmem_space *s, uint64_t va, void *buf,
                          size_t len)
{
    uint8_t *out = buf;
    size_t done = 0;

    while (done < len) {
        uint64_t cur = va + done;
        size_t page_off = (size_t)(cur & 0xFFF);
        size_t chunk = 0x1000 - page_off;
        uint64_t pa;

        if (chunk > len - done) chunk = len - done;
        if (vmem_translate(s, cur, &pa) != 0) return VMEM_EIO;
        if (vmem_read_phys_exact(s->mem, pa, out + done, chunk) != VMEM_OK)
            return VMEM_EIO;
        done += chunk;
    }
    return VMEM_OK;
}

/* Fast path: the value is entirely inside one page.  Falls back to the
 * page-crossing loop for the rare unaligned-at-a-boundary case. */
static void space_read_value(const vmem_space *s, uint64_t va, void *buf,
                             size_t len)
{
    if ((va & 0xFFF) + len <= 0x1000) {
        uint64_t pa;
        if (vmem_translate(s, va, &pa) == 0 &&
            vmem_read_phys_exact(s->mem, pa, buf, len) == VMEM_OK)
            return;
        memset(buf, 0, len);
        return;
    }
    vmem_space_read(s, va, buf, len);
}

uint8_t vmem_space_u8(const vmem_space *s, uint64_t va)
{
    uint8_t v = 0;
    space_read_value(s, va, &v, 1);
    return v;
}

uint16_t vmem_space_u16(const vmem_space *s, uint64_t va)
{
    uint8_t b[2];
    space_read_value(s, va, b, 2);
    return vmem_le16(b);
}

uint32_t vmem_space_u32(const vmem_space *s, uint64_t va)
{
    uint8_t b[4];
    space_read_value(s, va, b, 4);
    return vmem_le32(b);
}

uint64_t vmem_space_u64(const vmem_space *s, uint64_t va)
{
    uint8_t b[8];
    space_read_value(s, va, b, 8);
    return vmem_le64(b);
}

/* ------------------------------------------------------------------ */
/* strings                                                            */
/* ------------------------------------------------------------------ */

int vmem_space_cstring(const vmem_space *s, uint64_t va, char *out, size_t cap,
                       size_t *out_len)
{
    size_t i = 0;
    if (!out || cap == 0) return VMEM_EINVAL;

    while (i + 1 < cap) {
        uint64_t cur = va + i;
        size_t chunk = 0x1000 - (size_t)(cur & 0xFFF);
        uint8_t tmp[0x1000];
        size_t got, k;

        if (chunk > cap - 1 - i) chunk = cap - 1 - i;
        got = vmem_space_read(s, cur, tmp, chunk);
        for (k = 0; k < got; k++) {
            out[i + k] = (char)tmp[k];
            if (tmp[k] == 0) {
                if (out_len) *out_len = i + k;
                return VMEM_OK;
            }
        }
        i += got;
        if (got == 0) break;
    }
    out[i] = '\0';
    if (out_len) *out_len = i;
    return VMEM_OK;
}

int vmem_space_wstring(const vmem_space *s, uint64_t va, uint16_t *out,
                       size_t cap, size_t *out_len)
{
    size_t i = 0;
    if (!out || cap == 0) return VMEM_EINVAL;

    while (i < cap) {
        uint64_t cur = va + i * 2;
        size_t page_off = (size_t)(cur & 0xFFF);
        size_t chunk = (0x1000 - page_off) / 2; /* whole UTF-16 units */
        size_t units;
        uint8_t tmp[0x1000];
        size_t got, k;

        if (chunk == 0) chunk = 1; /* split unit at the very end of a page */
        if (chunk > cap - i) chunk = cap - i;
        got = vmem_space_read(s, cur, tmp, chunk * 2);
        units = got / 2;
        for (k = 0; k < units; k++) {
            uint16_t u = vmem_le16(tmp + k * 2);
            if (u == 0) {
                if (out_len) *out_len = i + k;
                return VMEM_OK;
            }
            out[i + k] = u;
        }
        i += units;
        if (units == 0) break;
    }
    if (out_len) *out_len = i;
    return VMEM_OK;
}
