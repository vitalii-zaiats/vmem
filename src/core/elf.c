/*
 * elf.c -- backend for an ELF core dump.
 *
 * QEMU's dump-guest-memory and VirtualBox's dumpvmcore both produce an ELF
 * file whose PT_LOAD segments carry the guest physical address in p_paddr.
 * This is the most faithful way to describe a guest address space: the
 * segment table *is* the firmware memory map, holes included.
 *
 * We parse the ELF header by hand instead of including <elf.h> so the same
 * source builds on macOS and Linux, and bounds-check every field.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>

#define PT_LOAD    1u
#define ET_CORE    4u
#define EM_X86_64  62u
#define EM_AARCH64 183u

static uint16_t rd16(const uint8_t *p) { return vmem_le16(p); }
static uint32_t rd32(const uint8_t *p) { return vmem_le32(p); }
static uint64_t rd64(const uint8_t *p) { return vmem_le64(p); }

static vmem_arch arch_from_machine(uint16_t machine)
{
    switch (machine) {
    case EM_X86_64:  return VMEM_ARCH_X86_64;
    case EM_AARCH64: return VMEM_ARCH_ARM64;
    default:         return VMEM_ARCH_UNKNOWN;
    }
}

vmem_mem *vmem_open_elf(const char *path, vmem_arch arch_override, int *err)
{
    vmem_map_source *src;
    const uint8_t *img;
    uint64_t size;
    uint64_t phoff;
    uint16_t phentsize, phnum;
    vmem_segment *segs = NULL;
    size_t n = 0, cap = 0;
    vmem_arch arch;

    src = vmem_map_source_open(path, err);
    if (!src) return NULL;
    img = vmem_map_source_base(src);
    size = vmem_map_source_size(src);

    if (size < 64 || memcmp(img, "\177ELF", 4) != 0 || img[4] != 2 /* ELFCLASS64 */
        || img[5] != 1 /* little endian */) {
        vmem_map_source_free(src);
        if (err) *err = VMEM_EFORMAT;
        return NULL;
    }

    arch = arch_override != VMEM_ARCH_UNKNOWN
         ? arch_override : arch_from_machine(rd16(img + 18));

    phoff    = rd64(img + 32);
    phentsize = rd16(img + 54);
    phnum    = rd16(img + 56);
    if (phentsize < 56 || phnum == 0 || phoff > size ||
        (uint64_t)phentsize * phnum > size - phoff) {
        vmem_map_source_free(src);
        if (err) *err = VMEM_EFORMAT;
        return NULL;
    }

    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *ph = img + phoff + (uint64_t)i * phentsize;
        uint32_t p_type = rd32(ph + 0);
        uint64_t p_offset = rd64(ph + 8);
        uint64_t p_vaddr  = rd64(ph + 16);
        uint64_t p_paddr  = rd64(ph + 24);
        uint64_t p_filesz = rd64(ph + 32);
        uint64_t gpa;

        if (p_type != PT_LOAD || p_filesz == 0) continue;
        if (p_offset > size || p_filesz > size - p_offset) continue;

        gpa = p_paddr ? p_paddr : p_vaddr;
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 16;
            vmem_segment *ns = realloc(segs, ncap * sizeof(*segs));
            if (!ns) {
                free(segs);
                vmem_map_source_free(src);
                if (err) *err = VMEM_ENOMEM;
                return NULL;
            }
            segs = ns;
            cap = ncap;
        }
        segs[n].gpa = gpa;
        segs[n].size = p_filesz;
        segs[n].file_offset = p_offset;
        segs[n].ptr = vmem_map_source_base(src) + p_offset;
        n++;
    }

    if (n == 0) {
        free(segs);
        vmem_map_source_free(src);
        if (err) *err = VMEM_EFORMAT;
        return NULL;
    }

    {
        vmem_mem *m = vmem_open_custom(vmem_map_source_read_at,
                                       vmem_map_source_destroy, src, segs, n,
                                       arch, err);
        free(segs);
        if (!m) {
            vmem_map_source_free(src);
            if (err) *err = VMEM_ENOMEM;
            return NULL;
        }
        return m;
    }
}
