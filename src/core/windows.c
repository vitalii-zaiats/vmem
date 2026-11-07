/*
 * windows.c -- Windows guest process introspection.
 *
 * Two enumeration strategies:
 *
 *  1. ActiveProcessLinks walk.  Exact and fast, but needs a usable kernel
 *     page-table base.  On x86-64 the process CR3 also maps the kernel half,
 *     so System's DirectoryTableBase is enough.  On ARM64 the kernel lives in
 *     TTBR1, which is not necessarily the value stored in EPROCESS, so this
 *     path is attempted and abandoned if translation does not work.
 *
 *  2. Physical scan for EPROCESS blocks.  We look for the 15-byte
 *     ImageFileName field (NUL padded printable ASCII) at the profile's
 *     offset, then validate UniqueProcessId, DirectoryTableBase and
 *     ActiveProcessLinks.  Slower, but it needs no page tables at all and
 *     works on every architecture and hypervisor.
 */
#include "internal.h"
#include "vmem/vmem_windows.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define SCAN_CHUNK (8u * 1024u * 1024u)

struct vmem_windows {
    vmem_mem *mem;
    vmem_eprocess_offsets off;
    uint64_t system_pa;
    uint64_t kernel_base;
    int found;
    int method;
};

static int is_kva(uint64_t v) { return (v >> 48) == 0xFFFF; }

static int name_field_ok(const uint8_t *p)
{
    int n = 0;
    while (n < 15 && p[n] != 0) {
        if (p[n] < 0x20 || p[n] > 0x7E) return 0;
        n++;
    }
    if (n == 0 || n == 15) return 0;
    for (int i = n; i < 15; i++)
        if (p[i] != 0) return 0;
    return 1;
}

static void read_name(vmem_mem *m, uint64_t base, const vmem_eprocess_offsets *o,
                      char out[16])
{
    uint8_t raw[15];
    int n = 0;

    memset(out, 0, 16);
    vmem_read_phys(m, base + o->image_file_name, raw, sizeof(raw));
    while (n < 15 && raw[n]) n++;
    memcpy(out, raw, (size_t)n);
}

/* ------------------------------------------------------------------ */
/* construction                                                       */
/* ------------------------------------------------------------------ */

vmem_windows *vmem_windows_new(vmem_mem *m, const vmem_eprocess_offsets *offs,
                               int *err)
{
    vmem_windows *w;
    if (!m || !offs) { if (err) *err = VMEM_EINVAL; return NULL; }
    w = calloc(1, sizeof(*w));
    if (!w) { if (err) *err = VMEM_ENOMEM; return NULL; }
    w->mem = m;
    w->off = *offs;
    if (err) *err = VMEM_OK;
    return w;
}

void vmem_windows_free(vmem_windows *w) { free(w); }

uint64_t vmem_windows_system_pa(const vmem_windows *w) { return w ? w->system_pa : 0; }
uint64_t vmem_windows_kernel_base(const vmem_windows *w) { return w ? w->kernel_base : 0; }
int vmem_windows_last_enum_method(const vmem_windows *w) { return w ? w->method : 0; }

/* ------------------------------------------------------------------ */
/* finding System (PID 4)                                             */
/* ------------------------------------------------------------------ */

int vmem_windows_find_system(vmem_windows *w)
{
    static const uint8_t needle[15] = {
        'S','y','s','t','e','m',0,0,0,0,0,0,0,0,0
    };
    vmem_scanner *sc;
    uint64_t hit;
    int rc;

    if (!w) return VMEM_EINVAL;
    if (w->found) return VMEM_OK;
    if (w->off.image_file_name == 0 || w->off.unique_process_id == 0)
        return VMEM_EINVAL;

    sc = vmem_scanner_new(w->mem, 0, vmem_max_gpa(w->mem), needle,
                          sizeof(needle));
    if (!sc) return VMEM_ENOMEM;

    while ((rc = vmem_scanner_next(sc, &hit)) == 1) {
        uint64_t base, pid, dtb, flink;

        if (hit < w->off.image_file_name) continue;
        base = hit - w->off.image_file_name;
        if (base & 7) continue;

        pid = vmem_phys_u64(w->mem, base + w->off.unique_process_id);
        if (pid != 4) continue;

        dtb = vmem_phys_u64(w->mem, base + w->off.directory_table_base);
        dtb = vmem_mask_base(vmem_arch_of(w->mem), dtb);
        if (!dtb) continue;

        flink = vmem_phys_u64(w->mem, base + w->off.active_process_links);
        if (!is_kva(flink)) continue;

        w->system_pa = base;
        w->kernel_base = dtb;
        w->found = 1;
        break;
    }
    vmem_scanner_free(sc);
    return w->found ? VMEM_OK : VMEM_ENOENT;
}

/* ------------------------------------------------------------------ */
/* EPROCESS field extraction                                          */
/* ------------------------------------------------------------------ */

static int fill_process(const vmem_windows *w, uint64_t base, uint64_t va,
                        vmem_process *p)
{
    vmem_mem *m = w->mem;
    uint64_t pid, dtb, flink, vsize;
    uint32_t threads;

    pid = vmem_phys_u64(m, base + w->off.unique_process_id);
    if (pid > 0x1000000ULL) return 0;

    dtb = vmem_phys_u64(m, base + w->off.directory_table_base);
    dtb = vmem_mask_base(vmem_arch_of(m), dtb);
    if (!dtb || dtb >= vmem_max_gpa(m)) return 0;

    flink = vmem_phys_u64(m, base + w->off.active_process_links);
    if (!is_kva(flink)) return 0;

    threads = vmem_phys_u32(m, base + w->off.active_threads);
    if (threads > 0x10000u) return 0;

    vsize = vmem_phys_u64(m, base + w->off.virtual_size);

    p->pid = pid;
    p->ppid = w->off.inherited_from_unique_process_id
            ? vmem_phys_u64(m, base + w->off.inherited_from_unique_process_id)
            : 0;
    p->dtb = dtb;
    p->eprocess_pa = base;
    p->eprocess_va = va;
    p->threads = threads;
    p->vsize = vsize;
    read_name(m, base, &w->off, p->name);
    return 1;
}

/* ------------------------------------------------------------------ */
/* strategy 1: ActiveProcessLinks                                     */
/* ------------------------------------------------------------------ */

static int walk_list(vmem_windows *w, vmem_process **out, size_t *count)
{
    vmem_space *ks;
    uint64_t first, cur;
    vmem_process *arr = NULL;
    size_t n = 0, cap = 0;
    int ok = 0;

    if (!w->kernel_base) return VMEM_ENOENT;
    ks = vmem_windows_kernel_space(w);
    if (!ks) return VMEM_ENOMEM;

    first = vmem_phys_u64(w->mem, w->system_pa + w->off.active_process_links);
    cur = first;

    for (int i = 0; i < 4096; i++) {
        uint64_t eproc_va, pa, link_pa, next;

        if (!is_kva(cur) || cur < w->off.active_process_links) break;
        eproc_va = cur - w->off.active_process_links;
        if (vmem_translate(ks, eproc_va, &pa) != 0) break;

        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 64;
            vmem_process *na = realloc(arr, ncap * sizeof(*arr));
            if (!na) { free(arr); vmem_space_free(ks); return VMEM_ENOMEM; }
            arr = na;
            cap = ncap;
        }
        if (fill_process(w, pa, eproc_va, &arr[n])) {
            n++;
            ok = 1;
        }

        if (vmem_translate(ks, cur, &link_pa) != 0) break;
        next = vmem_phys_u64(w->mem, link_pa);
        if (!is_kva(next) || next == first) break;
        cur = next;
    }
    vmem_space_free(ks);

    if (!ok) { free(arr); return VMEM_ENOENT; }
    *out = arr;
    *count = n;
    return VMEM_OK;
}

/* ------------------------------------------------------------------ */
/* strategy 2: physical scan                                          */
/* ------------------------------------------------------------------ */

static int scan_processes(vmem_windows *w, vmem_process **out, size_t *count)
{
    vmem_mem *m = w->mem;
    vmem_process *arr = NULL;
    size_t n = 0, cap = 0;
    uint8_t *buf;
    size_t segs_n = vmem_segment_count(m);
    const vmem_segment *segs = vmem_segments(m);

    buf = malloc(SCAN_CHUNK + 16);
    if (!buf) return VMEM_ENOMEM;

    for (size_t si = 0; si < segs_n; si++) {
        uint64_t gpa = segs[si].gpa;
        uint64_t end = segs[si].gpa + segs[si].size;

        while (gpa < end) {
            uint64_t remain = end - gpa;
            size_t want = remain > SCAN_CHUNK ? SCAN_CHUNK : (size_t)remain;
            size_t extra = 15; /* catch a name crossing the chunk end */
            size_t got;
            size_t i;

            if (extra > (size_t)(end - (gpa + want)))
                extra = (size_t)(end - (gpa + want));
            got = vmem_read_phys(m, gpa, buf, want + extra);

            for (i = 0; i + 15 <= got; i += 8) {
                uint64_t h, base;
                vmem_process cand;
                int dup = 0;

                if (!name_field_ok(buf + i)) continue;
                h = gpa + (uint64_t)i;
                if (h < w->off.image_file_name) continue;
                base = h - w->off.image_file_name;
                if (base & 7) continue;

                if (!fill_process(w, base, 0, &cand)) continue;

                for (size_t j = 0; j < n; j++) {
                    if (arr[j].eprocess_pa == cand.eprocess_pa) { dup = 1; break; }
                }
                if (dup) continue;

                if (n == cap) {
                    size_t ncap = cap ? cap * 2 : 64;
                    vmem_process *na = realloc(arr, ncap * sizeof(*arr));
                    if (!na) { free(arr); free(buf); return VMEM_ENOMEM; }
                    arr = na;
                    cap = ncap;
                }
                arr[n++] = cand;
            }
            gpa += want;
        }
    }
    free(buf);

    if (n == 0) { free(arr); return VMEM_ENOENT; }
    *out = arr;
    *count = n;
    return VMEM_OK;
}

static int cmp_proc(const void *a, const void *b)
{
    const vmem_process *x = a, *y = b;
    if (x->pid < y->pid) return -1;
    if (x->pid > y->pid) return 1;
    return 0;
}

int vmem_windows_processes(vmem_windows *w, vmem_process **out, size_t *count)
{
    int rc;
    if (!w || !out || !count) return VMEM_EINVAL;
    rc = vmem_windows_find_system(w);
    if (rc != VMEM_OK) return rc;

    rc = walk_list(w, out, count);
    if (rc == VMEM_OK) {
        w->method = VMEM_WIN_FOUND_BY_LIST;
        qsort(*out, *count, sizeof(**out), cmp_proc);
        return VMEM_OK;
    }

    rc = scan_processes(w, out, count);
    if (rc != VMEM_OK) return rc;
    w->method = VMEM_WIN_FOUND_BY_SCAN;
    qsort(*out, *count, sizeof(**out), cmp_proc);
    return VMEM_OK;
}

void vmem_processes_free(vmem_process *procs) { free(procs); }

int vmem_windows_find_pid(vmem_windows *w, uint64_t pid, vmem_process *out)
{
    vmem_process *procs = NULL;
    size_t n = 0;
    int rc = vmem_windows_processes(w, &procs, &n);
    if (rc != VMEM_OK) return rc;
    for (size_t i = 0; i < n; i++) {
        if (procs[i].pid == pid) {
            if (out) *out = procs[i];
            vmem_processes_free(procs);
            return VMEM_OK;
        }
    }
    vmem_processes_free(procs);
    return VMEM_ENOENT;
}

int vmem_windows_find_name(vmem_windows *w, const char *name, vmem_process *out)
{
    vmem_process *procs = NULL;
    size_t n = 0;
    size_t nlen;
    int rc;

    if (!name) return VMEM_EINVAL;
    nlen = strlen(name);
    rc = vmem_windows_processes(w, &procs, &n);
    if (rc != VMEM_OK) return rc;

    for (size_t i = 0; i < n; i++) {
        const char *p = procs[i].name;
        size_t plen = strlen(p);
        for (size_t j = 0; j + nlen <= plen; j++) {
            size_t k;
            for (k = 0; k < nlen; k++) {
                int a = tolower((unsigned char)name[k]);
                int b = tolower((unsigned char)p[j + k]);
                if (a != b) break;
            }
            if (k == nlen) {
                if (out) *out = procs[i];
                vmem_processes_free(procs);
                return VMEM_OK;
            }
        }
    }
    vmem_processes_free(procs);
    return VMEM_ENOENT;
}

/* ------------------------------------------------------------------ */
/* address spaces                                                     */
/* ------------------------------------------------------------------ */

vmem_space *vmem_windows_space(vmem_windows *w, const vmem_process *proc)
{
    uint64_t base0, base1 = 0;
    int has_base1 = 0;

    if (!w || !proc) return NULL;
    base0 = vmem_mask_base(vmem_arch_of(w->mem), proc->dtb);
    if (vmem_arch_of(w->mem) == VMEM_ARCH_ARM64 && w->kernel_base) {
        base1 = w->kernel_base;
        has_base1 = 1;
    }
    return vmem_space_new(w->mem, vmem_arch_of(w->mem), base0, base1,
                          has_base1);
}

vmem_space *vmem_windows_kernel_space(vmem_windows *w)
{
    vmem_arch arch;
    if (!w || !w->kernel_base) return NULL;
    arch = vmem_arch_of(w->mem);
    if (arch == VMEM_ARCH_ARM64)
        return vmem_space_new(w->mem, arch, w->kernel_base, w->kernel_base, 1);
    return vmem_space_new(w->mem, arch, w->kernel_base, 0, 0);
}
