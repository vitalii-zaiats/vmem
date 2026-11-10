/*
 * vmem.h -- public C API for the vmem core.
 *
 * This header deliberately depends only on <stddef.h> and <stdint.h>.
 * The core library has no dependency on Python or on any host-specific
 * runtime beyond libc/POSIX.  Backends turn "some source of guest physical
 * memory" into a list of (guest physical address -> host offset) segments;
 * everything above that is hypervisor agnostic.
 */
#ifndef VMEM_VMEM_H
#define VMEM_VMEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMEM_VERSION_MAJOR 0
#define VMEM_VERSION_MINOR 1

enum {
    VMEM_OK      =  0,
    VMEM_EINVAL  = -1,
    VMEM_ENOMEM  = -2,
    VMEM_EIO     = -3,
    VMEM_ENOTSUP = -4,
    VMEM_EFORMAT = -5,
    VMEM_ENOENT  = -6,
    VMEM_EBACKEND = -7
};

typedef enum {
    VMEM_ARCH_UNKNOWN = 0,
    VMEM_ARCH_X86_64  = 1,
    VMEM_ARCH_ARM64   = 2
} vmem_arch;

/*
 * One contiguous region of guest physical address space.
 *
 *   ptr != NULL : bytes live at ptr + (gpa - gpa_base) in our address space
 *   ptr == NULL : bytes live at file_offset + (gpa - gpa_base) in the
 *                 backing source (read through the source callback)
 */
typedef struct {
    uint64_t gpa;
    uint64_t size;
    uint64_t file_offset;
    uint8_t *ptr;
} vmem_segment;

typedef struct vmem_mem   vmem_mem;
typedef struct vmem_space vmem_space;
typedef struct vmem_scanner vmem_scanner;

/* ------------------------------------------------------------------ */
/* Constructors                                                       */
/* ------------------------------------------------------------------ */

/*
 * A raw/flat dump: the file is guest physical memory starting at gpa_base.
 * If below_4g != 0 and below_4g < file size, the classic PCI hole layout is
 * assumed: [0, below_4g) comes from file offset 0 and [4GiB, ...) from file
 * offset below_4g.
 */
vmem_mem *vmem_open_flat(const char *path, vmem_arch arch, uint64_t gpa_base,
                         uint64_t below_4g, int *err);

/*
 * An ELF core dump (ET_CORE) with PT_LOAD segments whose p_paddr is the guest
 * physical address.  This is what QEMU's dump-guest-memory and VirtualBox's
 * dumpvmcore produce.  arch_override == VMEM_ARCH_UNKNOWN means "use e_machine".
 */
vmem_mem *vmem_open_elf(const char *path, vmem_arch arch_override, int *err);

/*
 * Live Linux process memory (/proc/<pid>/mem).  The caller supplies the
 * segments; file_offset is interpreted as the host virtual address to read via
 * pread(2).  See vmem_open_procmem_auto() for heuristic detection.
 */
vmem_mem *vmem_open_procmem(int pid, const vmem_segment *segs, size_t nsegs,
                            int *err);
vmem_mem *vmem_open_procmem_auto(int pid, uint64_t below_4g, int *err);

/* Generic source.  read_at() must read `len` bytes at source offset `off`. */
typedef int (*vmem_read_at_cb)(void *ctx, uint64_t off, void *buf, size_t len,
                               size_t *got);
typedef int (*vmem_write_at_cb)(void *ctx, uint64_t off, const void *buf,
                                size_t len, size_t *done);
typedef void (*vmem_destroy_cb)(void *ctx);
vmem_mem *vmem_open_custom(vmem_read_at_cb read_at, vmem_destroy_cb destroy,
                           void *ctx, const vmem_segment *segs, size_t nsegs,
                           vmem_arch arch, int *err);
vmem_mem *vmem_open_custom_rw(vmem_read_at_cb read_at,
                              vmem_write_at_cb write_at,
                              vmem_destroy_cb destroy, void *ctx,
                              const vmem_segment *segs, size_t nsegs,
                              vmem_arch arch, int *err);

void vmem_close(vmem_mem *m);

/* Override the architecture of an already opened memory object (useful for
 * backends that cannot infer it, such as /proc/<pid>/mem). */
void vmem_set_arch(vmem_mem *m, vmem_arch arch);

/* ------------------------------------------------------------------ */
/* Introspection                                                      */
/* ------------------------------------------------------------------ */

vmem_arch vmem_arch_of(const vmem_mem *m);
size_t    vmem_segment_count(const vmem_mem *m);
const vmem_segment *vmem_segments(const vmem_mem *m);
uint64_t  vmem_min_gpa(const vmem_mem *m);
uint64_t  vmem_max_gpa(const vmem_mem *m);
uint64_t  vmem_total_size(const vmem_mem *m);

/* ------------------------------------------------------------------ */
/* Physical memory                                                    */
/* ------------------------------------------------------------------ */

/* Always returns len; holes and unreadable ranges are zero filled. */
size_t vmem_read_phys(vmem_mem *m, uint64_t gpa, void *buf, size_t len);

/* Returns 0 only if every byte was backed and read. */
int vmem_read_phys_exact(vmem_mem *m, uint64_t gpa, void *buf, size_t len);

/* Write to guest physical memory.  Only writable backends support this. */
int vmem_write_phys(vmem_mem *m, uint64_t gpa, const void *buf, size_t len);

uint8_t  vmem_phys_u8 (vmem_mem *m, uint64_t gpa);
uint16_t vmem_phys_u16(vmem_mem *m, uint64_t gpa);
uint32_t vmem_phys_u32(vmem_mem *m, uint64_t gpa);
uint64_t vmem_phys_u64(vmem_mem *m, uint64_t gpa);

/* ------------------------------------------------------------------ */
/* Streaming physical scan (chunk boundaries are handled correctly)   */
/* ------------------------------------------------------------------ */

vmem_scanner *vmem_scanner_new(vmem_mem *m, uint64_t start_gpa,
                               uint64_t end_gpa, const void *needle,
                               size_t nlen);
/* 1 = hit (gpa set), 0 = finished, < 0 = error. */
int  vmem_scanner_next(vmem_scanner *s, uint64_t *gpa);
void vmem_scanner_free(vmem_scanner *s);

typedef int (*vmem_hit_cb)(void *user, uint64_t gpa);
int vmem_scan(vmem_mem *m, uint64_t start_gpa, uint64_t end_gpa,
              const void *needle, size_t nlen, vmem_hit_cb cb, void *user);

/* ------------------------------------------------------------------ */
/* Address spaces                                                     */
/* ------------------------------------------------------------------ */

/*
 * x86-64: base0 is CR3; base1 is ignored.
 * ARM64 : base0 is TTBR0, base1 is TTBR1.  Windows keeps the kernel mapping
 *         in TTBR1, so reading kernel virtual addresses needs base1.
 */
vmem_space *vmem_space_new(vmem_mem *m, vmem_arch arch, uint64_t base0,
                           uint64_t base1, int has_base1);
void vmem_space_free(vmem_space *s);

vmem_arch vmem_space_arch(const vmem_space *s);
uint64_t  vmem_space_base0(const vmem_space *s);
uint64_t  vmem_space_base1(const vmem_space *s);

/* Returns 0 on success, -1 if the virtual address is not mapped. */
int vmem_translate(const vmem_space *s, uint64_t va, uint64_t *pa);

/* Zero fills unmapped pages. */
size_t vmem_space_read(const vmem_space *s, uint64_t va, void *buf, size_t len);
int    vmem_space_read_exact(const vmem_space *s, uint64_t va, void *buf,
                             size_t len);
int    vmem_space_write(const vmem_space *s, uint64_t va, const void *buf,
                        size_t len);

uint8_t  vmem_space_u8 (const vmem_space *s, uint64_t va);
uint16_t vmem_space_u16(const vmem_space *s, uint64_t va);
uint32_t vmem_space_u32(const vmem_space *s, uint64_t va);
uint64_t vmem_space_u64(const vmem_space *s, uint64_t va);

/* NUL terminated ASCII / UTF-16LE.  Returns number of bytes consumed. */
int vmem_space_cstring(const vmem_space *s, uint64_t va, char *out, size_t cap,
                       size_t *out_len);
int vmem_space_wstring(const vmem_space *s, uint64_t va, uint16_t *out,
                       size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif /* VMEM_VMEM_H */
