/*
 * test_core.c -- pure C test for the vmem core.  No Python involved.
 *
 * Build and run with `make test-core`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmem/vmem.h"
#include "vmem/vmem_windows.h"

static int failures;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                   \
        }                                                                 \
    } while (0)

/* ------------------------------------------------------------------ */
/* a memory-backed source (stands in for a dump file)                 */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t *buf;
    size_t len;
} memsrc;

static int src_read(void *ctx, uint64_t off, void *buf, size_t len, size_t *got)
{
    memsrc *m = ctx;
    if (off >= m->len) { *got = 0; return VMEM_OK; }
    size_t n = m->len - (size_t)off;
    if (n > len) n = len;
    memcpy(buf, m->buf + (size_t)off, n);
    *got = n;
    return VMEM_OK;
}

static void src_destroy(void *ctx) { free(ctx); }

static void put64(uint8_t *buf, uint64_t off, uint64_t v)
{
    memcpy(buf + off, &v, 8);
}

static void put32(uint8_t *buf, uint64_t off, uint32_t v)
{
    memcpy(buf + off, &v, 4);
}

static vmem_mem *make_memory(uint8_t *img, size_t len, size_t *hint)
{
    memsrc *src = calloc(1, sizeof(*src));
    vmem_segment seg;
    int err = 0;
    src->buf = img;
    src->len = len;
    seg.gpa = 0;
    seg.size = len;
    seg.file_offset = 0;
    seg.ptr = NULL;
    *hint = 0;
    return vmem_open_custom(src_read, src_destroy, src, &seg, 1,
                            VMEM_ARCH_ARM64, &err);
}

/* ------------------------------------------------------------------ */

static uint64_t alloc_pages(uint64_t *next)
{
    uint64_t pa = *next;
    *next += 0x1000;
    return pa;
}

static void arm64_map(uint8_t *img, uint64_t ttbr, uint64_t va, uint64_t pa,
                      uint64_t *next)
{
    uint64_t l1 = alloc_pages(next);
    uint64_t l2 = alloc_pages(next);
    uint64_t l3 = alloc_pages(next);
    put64(img, ttbr + ((va >> 39) & 0x1FF) * 8, l1 | 3);
    put64(img, l1 + ((va >> 30) & 0x1FF) * 8, l2 | 3);
    put64(img, l2 + ((va >> 21) & 0x1FF) * 8, l3 | 3);
    put64(img, l3 + ((va >> 12) & 0x1FF) * 8, (pa & 0x0000FFFFFFFFF000ULL) | 3);
}

/* ARM64 / build 26300 EPROCESS offsets */
#define OFF_DTB   0x028
#define OFF_PID   0x1C0
#define OFF_LINKS 0x1C8
#define OFF_NAME  0x328
#define OFF_VSIZE 0x218
#define OFF_THR   0x370

static void fake_eprocess(uint8_t *img, uint64_t base, const char *name,
                          uint64_t pid, uint64_t dtb)
{
    memset(img + base + OFF_NAME, 0, 15);
    memcpy(img + base + OFF_NAME, name, strlen(name));
    put64(img, base + OFF_PID, pid);
    put64(img, base + OFF_DTB, dtb);
    put64(img, base + OFF_LINKS, 0xFFFF800000001000ULL);
    put32(img, base + OFF_THR, 4);
    put64(img, base + OFF_VSIZE, 0x100000);
}

int main(void)
{
    const size_t len = 24u * 1024u * 1024u;
    uint8_t *img = calloc(1, len);
    size_t hint = 0;
    uint64_t next = 0x1000;
    uint64_t ttbr;
    uint64_t va = 0x00000040001234ULL;
    uint64_t pa = 0x00080000ULL;
    uint64_t got;
    vmem_mem *mem;
    vmem_space *space;
    vmem_scanner *sc;
    vmem_eprocess_offsets off = {
        .directory_table_base = OFF_DTB,
        .unique_process_id = OFF_PID,
        .active_process_links = OFF_LINKS,
        .image_file_name = OFF_NAME,
        .virtual_size = OFF_VSIZE,
        .active_threads = OFF_THR,
        .peb = 0,
    };
    vmem_windows *win;
    vmem_process *procs = NULL;
    size_t nprocs = 0;

    if (!img) return 2;

    /* --- ARM64 translation ---------------------------------------- */
    ttbr = alloc_pages(&next);
    arm64_map(img, ttbr, va, pa, &next);
    memcpy(img + (pa & ~0xFFFULL) + (va & 0xFFF), "hello", 5);
    memcpy(img + 0x800000 - 5, "BOUNDARY", 8);

    /* --- fake process blocks -------------------------------------- */
    fake_eprocess(img, 0x00200000, "System", 4, 0x5000);
    fake_eprocess(img, 0x00210000, "explorer.exe", 1234, 0x6000);

    mem = make_memory(img, len, &hint);
    CHECK(mem != NULL);
    if (!mem) return 2;

    CHECK(vmem_arch_of(mem) == VMEM_ARCH_ARM64);
    CHECK(vmem_max_gpa(mem) == len);

    space = vmem_space_new(mem, VMEM_ARCH_ARM64, ttbr, 0, 0);
    CHECK(space != NULL);
    CHECK(vmem_translate(space, va, &got) == 0);
    CHECK(got == ((pa & ~0xFFFULL) | (va & 0xFFF)));
    CHECK(vmem_space_u32(space, va) == 0x6c6c6568 /* "hell" */);

    /* --- scan across the 8 MiB internal chunk boundary ------------ */
    sc = vmem_scanner_new(mem, 0, 0, "BOUNDARY", 8);
    CHECK(sc != NULL);
    CHECK(vmem_scanner_next(sc, &got) == 1);
    CHECK(got == 0x800000 - 5);
    CHECK(vmem_scanner_next(sc, &got) == 0);
    vmem_scanner_free(sc);

    /* --- Windows enumeration (scan fallback) ---------------------- */
    win = vmem_windows_new(mem, &off, NULL);
    CHECK(win != NULL);
    CHECK(vmem_windows_find_system(win) == VMEM_OK);
    CHECK(vmem_windows_system_pa(win) == 0x00200000);
    CHECK(vmem_windows_processes(win, &procs, &nprocs) == VMEM_OK);
    CHECK(nprocs == 2);
    CHECK(vmem_windows_last_enum_method(win) == VMEM_WIN_FOUND_BY_SCAN);

    {
        vmem_process p;
        CHECK(vmem_windows_find_name(win, "EXPLORER", &p) == VMEM_OK);
        CHECK(p.pid == 1234);
        CHECK(strcmp(p.name, "explorer.exe") == 0);
    }

    vmem_processes_free(procs);
    vmem_windows_free(win);
    vmem_space_free(space);
    vmem_close(mem);
    free(img);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_core: all checks passed\n");
    return 0;
}
