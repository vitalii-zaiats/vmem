/*
 * flat.c -- backend for a raw guest physical memory dump.
 */
#include "internal.h"

#include <stdlib.h>

vmem_mem *vmem_open_flat(const char *path, vmem_arch arch, uint64_t gpa_base,
                         uint64_t below_4g, int *err)
{
    vmem_map_source *src;
    uint64_t size;
    uint8_t *base;
    vmem_segment segs[2];
    size_t n = 0;
    vmem_mem *m;

    src = vmem_map_source_open(path, err);
    if (!src) return NULL;
    size = vmem_map_source_size(src);
    base = vmem_map_source_base(src);

    if (below_4g == 0 || below_4g >= size) {
        segs[n++] = (vmem_segment){ gpa_base, size, 0, base };
    } else {
        segs[n++] = (vmem_segment){ gpa_base, below_4g, 0, base };
        segs[n++] = (vmem_segment){ 0x100000000ULL, size - below_4g,
                                    below_4g, base + below_4g };
    }

    m = vmem_open_custom(vmem_map_source_read_at, vmem_map_source_destroy,
                         src, segs, n, arch, err);
    if (!m) {
        vmem_map_source_free(src);
        if (err) *err = VMEM_ENOMEM;
        return NULL;
    }
    return m;
}
