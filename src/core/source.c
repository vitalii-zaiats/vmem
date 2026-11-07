/*
 * source.c -- a readable, memory mapped file plus a pread fallback.
 *
 * Both the flat-dump backend and the ELF-core backend are "a file with a
 * segment table", so the file handling lives here.
 */
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct vmem_map_source {
    int fd;
    uint8_t *base;
    uint64_t size;
};

vmem_map_source *vmem_map_source_open(const char *path, int *err)
{
    struct stat st;
    vmem_map_source *s = calloc(1, sizeof(*s));
    if (!s) { if (err) *err = VMEM_ENOMEM; return NULL; }
    s->fd = -1;

    s->fd = open(path, O_RDONLY);
    if (s->fd < 0) {
        free(s);
        if (err) *err = VMEM_ENOENT;
        return NULL;
    }
    if (fstat(s->fd, &st) != 0 || st.st_size <= 0) {
        close(s->fd);
        free(s);
        if (err) *err = VMEM_EFORMAT;
        return NULL;
    }
    s->size = (uint64_t)st.st_size;
    s->base = mmap(NULL, (size_t)s->size, PROT_READ, MAP_PRIVATE, s->fd, 0);
    if (s->base == MAP_FAILED) {
        s->base = NULL;
        close(s->fd);
        free(s);
        if (err) *err = VMEM_EIO;
        return NULL;
    }
    if (err) *err = VMEM_OK;
    return s;
}

void vmem_map_source_free(vmem_map_source *s)
{
    if (!s) return;
    if (s->base) munmap(s->base, (size_t)s->size);
    if (s->fd >= 0) close(s->fd);
    free(s);
}

uint8_t *vmem_map_source_base(vmem_map_source *s) { return s->base; }
uint64_t vmem_map_source_size(vmem_map_source *s) { return s->size; }

int vmem_map_source_read_at(void *ctx, uint64_t off, void *buf, size_t len,
                            size_t *got)
{
    vmem_map_source *s = ctx;
    if (off >= s->size) { *got = 0; return VMEM_OK; }
    size_t n = (size_t)(s->size - off);
    if (n > len) n = len;
    memcpy(buf, s->base + off, n);
    *got = n;
    return VMEM_OK;
}

void vmem_map_source_destroy(void *ctx)
{
    vmem_map_source_free((vmem_map_source *)ctx);
}
