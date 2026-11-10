/*
 * procmem.c -- live Linux process memory backend.
 *
 * Two modes:
 *   - an fd that is a real file (QEMU memory-backend-memfd): pread directly.
 *   - anonymous mappings: pread from /proc/<pid>/mem using the host virtual
 *     address as the file offset.
 *
 * NOTE: you cannot mmap() another process's anonymous memory, so this path is
 * always read-based.  On non-Linux platforms the entry points report
 * VMEM_ENOTSUP.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>

#if defined(__linux__)

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    int fd;
} pm_ctx;

static int pm_read_at(void *ctx, uint64_t off, void *buf, size_t len,
                      size_t *got)
{
    pm_ctx *c = ctx;
    size_t total = 0;
    while (total < len) {
        ssize_t n = pread(c->fd, (char *)buf + total, len - total,
                          (off_t)(off + total));
        if (n <= 0) break;
        total += (size_t)n;
    }
    *got = total;
    return VMEM_OK;
}

static int pm_write_at(void *ctx, uint64_t off, const void *buf, size_t len,
                       size_t *done)
{
    pm_ctx *c = ctx;
    size_t total = 0;
    while (total < len) {
        ssize_t n = pwrite(c->fd, (const char *)buf + total, len - total,
                           (off_t)(off + total));
        if (n <= 0) break;
        total += (size_t)n;
    }
    *done = total;
    return total == len ? VMEM_OK : VMEM_EIO;
}

static void pm_destroy(void *ctx)
{
    pm_ctx *c = ctx;
    if (c->fd >= 0) close(c->fd);
    free(c);
}

static vmem_mem *open_with_fd(int fd, const vmem_segment *segs, size_t n,
                              int *err)
{
    pm_ctx *c = calloc(1, sizeof(*c));
    if (!c) { if (err) *err = VMEM_ENOMEM; return NULL; }
    c->fd = fd;
    {
        vmem_mem *m = vmem_open_custom_rw(pm_read_at, pm_write_at, pm_destroy,
                                          c, segs, n, VMEM_ARCH_UNKNOWN, err);
        if (!m) { pm_destroy(c); return NULL; }
        return m;
    }
}

vmem_mem *vmem_open_procmem(int pid, const vmem_segment *segs, size_t nsegs,
                            int *err)
{
    char path[64];
    int fd;
    if (nsegs == 0) { if (err) *err = VMEM_EINVAL; return NULL; }
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    fd = open(path, O_RDWR);
    if (fd < 0) fd = open(path, O_RDONLY); /* read-only fallback */
    if (fd < 0) { if (err) *err = VMEM_ENOENT; return NULL; }
    return open_with_fd(fd, segs, nsegs, err);
}

static int find_memfd(int pid, uint64_t *size_out)
{
    char dirpath[64];
    DIR *d;
    struct dirent *ent;
    int best = -1;
    uint64_t best_size = 0;

    snprintf(dirpath, sizeof(dirpath), "/proc/%d/fd", pid);
    d = opendir(dirpath);
    if (!d) return -1;

    while ((ent = readdir(d)) != NULL) {
        char linkpath[128], target[512];
        ssize_t n;
        struct stat st;

        if (ent->d_name[0] == '.') continue;
        snprintf(linkpath, sizeof(linkpath), "/proc/%d/fd/%s", pid,
                 ent->d_name);
        n = readlink(linkpath, target, sizeof(target) - 1);
        if (n < 0) continue;
        target[n] = '\0';
        if (!strstr(target, "memory-backend-memfd") &&
            !strstr(target, "memfd:"))
            continue;
        /* QEMU also memfd-backs its display surface; don't mistake a 1 MiB
         * framebuffer for 14 GiB of guest RAM. */
        if (stat(linkpath, &st) != 0 || st.st_size < (64LL << 20)) continue;
        if ((uint64_t)st.st_size > best_size) {
            best_size = (uint64_t)st.st_size;
            best = atoi(ent->d_name);
        }
    }
    closedir(d);
    if (best < 0) return -1;
    *size_out = best_size;
    return best;
}

static int find_anon_region(int pid, uint64_t *start_out, uint64_t *size_out)
{
    char path[64];
    FILE *f;
    char line[512];
    uint64_t best_start = 0, best_size = 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        unsigned long long start = 0, end = 0;
        char perms[8];
        int used = 0;

        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %n",
                   &start, &end, perms, &used) < 3)
            continue;
        if (perms[0] != 'r' || perms[1] != 'w') continue;
        /* accept unnamed anon mappings and kernel-named [anon:...] ones */
        if (used > 0 && line[used] != '\n' && line[used] != '\0' &&
            strncmp(line + used, "[anon:", 6) != 0)
            continue;
        if (end <= start) continue;
        if (end - start > best_size) {
            best_size = end - start;
            best_start = start;
        }
    }
    fclose(f);
    if (best_size < 64ULL * 1024 * 1024) return -1;
    *start_out = best_start;
    *size_out = best_size;
    return 0;
}

vmem_mem *vmem_open_procmem_auto(int pid, uint64_t below_4g, int *err)
{
    uint64_t size = 0;
    vmem_segment segs[2];
    size_t n = 0;
    int fd = find_memfd(pid, &size);

    if (fd >= 0) {
        char path[128];
        snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
        fd = open(path, O_RDWR);
        if (fd < 0) fd = open(path, O_RDONLY);
        if (fd < 0) { if (err) *err = VMEM_ENOENT; return NULL; }
        if (below_4g == 0 || below_4g >= size)
            below_4g = (size <= 0xE0000000ULL) ? size : 0x80000000ULL;
        if (below_4g >= size) {
            segs[n++] = (vmem_segment){ 0, size, 0, NULL };
        } else {
            segs[n++] = (vmem_segment){ 0, below_4g, 0, NULL };
            segs[n++] = (vmem_segment){ 0x100000000ULL, size - below_4g,
                                        below_4g, NULL };
        }
        return open_with_fd(fd, segs, n, err);
    }

    {
        uint64_t host_start = 0;
        if (find_anon_region(pid, &host_start, &size) < 0) {
            if (err) *err = VMEM_EBACKEND;
            return NULL;
        }
        if (below_4g == 0 || below_4g >= size)
            below_4g = (size <= 0xE0000000ULL) ? size : 0x80000000ULL;
        if (below_4g >= size) {
            segs[n++] = (vmem_segment){ 0, size, host_start, NULL };
        } else {
            segs[n++] = (vmem_segment){ 0, below_4g, host_start, NULL };
            segs[n++] = (vmem_segment){ 0x100000000ULL, size - below_4g,
                                        host_start + below_4g, NULL };
        }
        return vmem_open_procmem(pid, segs, n, err);
    }
}

#else /* !__linux__ */

vmem_mem *vmem_open_procmem(int pid, const vmem_segment *segs, size_t nsegs,
                            int *err)
{
    (void)pid; (void)segs; (void)nsegs;
    if (err) *err = VMEM_ENOTSUP;
    return NULL;
}

vmem_mem *vmem_open_procmem_auto(int pid, uint64_t below_4g, int *err)
{
    (void)pid; (void)below_4g;
    if (err) *err = VMEM_ENOTSUP;
    return NULL;
}

#endif
