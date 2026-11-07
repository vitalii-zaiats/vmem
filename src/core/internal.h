/*
 * internal.h -- private definitions shared by the core translation units.
 * Nothing here is exposed to users of the library, and nothing here knows
 * anything about Python.
 */
#ifndef VMEM_INTERNAL_H
#define VMEM_INTERNAL_H

#include "vmem/vmem.h"

typedef int (*vmem_read_at_fn)(void *ctx, uint64_t off, void *buf, size_t len,
                               size_t *got);
typedef void (*vmem_destroy_fn)(void *ctx);

struct vmem_mem {
    vmem_arch arch;
    vmem_segment *segs;
    size_t nsegs;
    uint64_t min_gpa;
    uint64_t max_gpa;
    uint64_t total_size;
    vmem_read_at_fn read_at;
    vmem_destroy_fn destroy;
    void *ctx;
};

struct vmem_space {
    vmem_mem *mem;
    vmem_arch arch;
    uint64_t base0;
    uint64_t base1;
    int has_base1;
};

/* mem.c */
int      vmem_read_at(vmem_mem *m, uint64_t off, void *buf, size_t len,
                      size_t *got);
const vmem_segment *vmem_seg_for(const vmem_mem *m, uint64_t gpa);
const vmem_segment *vmem_seg_after(const vmem_mem *m, uint64_t gpa);
uint64_t vmem_mask_base(vmem_arch arch, uint64_t base);
uint16_t vmem_le16(const void *p);
uint32_t vmem_le32(const void *p);
uint64_t vmem_le64(const void *p);

/* source.c -- memory mapped file source */
typedef struct vmem_map_source vmem_map_source;
vmem_map_source *vmem_map_source_open(const char *path, int *err);
void             vmem_map_source_free(vmem_map_source *s);
uint8_t         *vmem_map_source_base(vmem_map_source *s);
uint64_t         vmem_map_source_size(vmem_map_source *s);
int vmem_map_source_read_at(void *ctx, uint64_t off, void *buf, size_t len,
                            size_t *got);
void vmem_map_source_destroy(void *ctx);

/* arch.c */
int vmem_translate_x86_64(const vmem_space *s, uint64_t va, uint64_t *pa);
int vmem_translate_arm64(const vmem_space *s, uint64_t va, uint64_t *pa);

#endif
