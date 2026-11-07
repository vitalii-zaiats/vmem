/*
 * vmem_windows.h -- Windows guest introspection (EPROCESS).
 *
 * Offsets are *data*, not code: different Windows builds and architectures
 * have different layouts, so the caller supplies a profile.  The structures
 * below are intentionally plain and stable so a profile can come from a TOML
 * file, a PDB, or `dt nt!_EPROCESS`.
 */
#ifndef VMEM_VMEM_WINDOWS_H
#define VMEM_VMEM_WINDOWS_H

#include "vmem/vmem.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t directory_table_base; /* EPROCESS.Pcb.DirectoryTableBase */
    uint32_t unique_process_id;
    uint32_t active_process_links;
    uint32_t image_file_name;      /* char[15] */
    uint32_t virtual_size;
    uint32_t active_threads;
    uint32_t peb;
    uint32_t inherited_from_unique_process_id; /* 0 if unknown */
} vmem_eprocess_offsets;

typedef struct {
    uint64_t pid;
    uint64_t ppid;
    char     name[16];
    uint64_t dtb;            /* page table root (masked), 0 if unreadable */
    uint64_t eprocess_pa;    /* physical address of the EPROCESS */
    uint64_t eprocess_va;    /* kernel VA, 0 if not known */
    uint32_t threads;
    uint64_t vsize;
} vmem_process;

enum {
    VMEM_WIN_FOUND_BY_LIST = 1,
    VMEM_WIN_FOUND_BY_SCAN = 2
};

typedef struct vmem_windows vmem_windows;

vmem_windows *vmem_windows_new(vmem_mem *m, const vmem_eprocess_offsets *offs,
                               int *err);
void vmem_windows_free(vmem_windows *w);

/* Locate and validate the System (PID 4) EPROCESS.  Cached after first call. */
int vmem_windows_find_system(vmem_windows *w);

uint64_t vmem_windows_system_pa(const vmem_windows *w);
uint64_t vmem_windows_kernel_base(const vmem_windows *w);
int      vmem_windows_last_enum_method(const vmem_windows *w);

/*
 * Enumerate processes.  Prefers the ActiveProcessLinks walk when a usable
 * kernel page-table base is known, otherwise falls back to a physical scan
 * for EPROCESS blocks (works on any architecture/hypervisor).
 *
 * *out is malloc'd; release with vmem_processes_free().
 */
int vmem_windows_processes(vmem_windows *w, vmem_process **out, size_t *count);
void vmem_processes_free(vmem_process *procs);

/* Returns 0 on success, VMEM_ENOENT if not found. */
int vmem_windows_find_pid(vmem_windows *w, uint64_t pid, vmem_process *out);
int vmem_windows_find_name(vmem_windows *w, const char *name, vmem_process *out);

/* Address space for a process.  Release with vmem_space_free(). */
vmem_space *vmem_windows_space(vmem_windows *w, const vmem_process *proc);
vmem_space *vmem_windows_kernel_space(vmem_windows *w);

#ifdef __cplusplus
}
#endif
#endif /* VMEM_VMEM_WINDOWS_H */
