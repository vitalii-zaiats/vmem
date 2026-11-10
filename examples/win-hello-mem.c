/*
 * win-hello-mem.c -- a deliberately simple target for external memory access.
 *
 * Build (MSVC):   cl /O2 win-hello-mem.c /Fe:hello_mem.exe
 * Build (MinGW):  x86_64-w64-mingw32-gcc -O2 -o hello_mem.exe win-hello-mem.c
 *
 * It prints:
 *   - PID and image base
 *   - absolute virtual address of every buffer
 *   - offset from the image base (useful for the static buffer)
 *   - offset from the allocation/region base (useful for heap/VirtualAlloc)
 * and then re-prints the current contents every 2 seconds, so you can modify
 * them from outside and see the change.
 */
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef _M_X64
#  ifdef _MSC_VER
#    include <intrin.h>
static void *read_teb(void) { return (void *)__readgsqword(0x30); }
static void *read_peb(void) { return (void *)__readgsqword(0x60); }
#  else
static void *read_teb(void) { void *p; __asm__ volatile("movq %%gs:0x30, %0" : "=r"(p)); return p; }
static void *read_peb(void) { void *p; __asm__ volatile("movq %%gs:0x60, %0" : "=r"(p)); return p; }
#  endif
#endif

static char g_static_buf[64] = "Hello World (static)";

static void describe(const char *label, void *p, size_t size, HMODULE image)
{
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t image_off, region_off;

    if (!VirtualQuery(p, &mbi, sizeof(mbi))) {
        printf("%-8s va=%p (VirtualQuery failed: %lu)\n",
               label, p, (unsigned long)GetLastError());
        return;
    }
    image_off = (uintptr_t)p - (uintptr_t)image;
    region_off = (uintptr_t)p - (uintptr_t)mbi.AllocationBase;

    printf("%-8s va=%p  size=0x%-5zx  image_off=+0x%-10" PRIXPTR
           "  region_off=+0x%-8" PRIXPTR
           "  alloc_base=%p  region=0x%-8zx  protect=0x%lx\n",
           label, p, size, image_off, region_off,
           mbi.AllocationBase, mbi.RegionSize, mbi.Protect);
}

int main(void)
{
    HMODULE image = GetModuleHandleA(NULL);
    char path[MAX_PATH] = { 0 };
    const size_t heap_size = 128;
    char *heap_buf, *calloc_buf, *virt_buf;

    setvbuf(stdout, NULL, _IONBF, 0);

    heap_buf = (char *)malloc(heap_size);
    calloc_buf = (char *)calloc(1, 256);
    virt_buf = (char *)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE);
    if (!heap_buf || !calloc_buf || !virt_buf) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    strcpy(heap_buf, "Hello World");
    strcpy(calloc_buf, "Hello World (calloc)");
    strcpy(virt_buf, "Hello World (VirtualAlloc)");

    GetModuleFileNameA(NULL, path, MAX_PATH);

    printf("image      : %s\n", path);
    printf("pid        : %lu\n", (unsigned long)GetCurrentProcessId());
    printf("bitness    : %zu\n", sizeof(void *));
    printf("image_base : %p\n", (void *)image);
    printf("process_heap: %p\n", (void *)GetProcessHeap());
#ifdef _M_X64
    printf("teb        : %p\n", read_teb());
    printf("peb        : %p\n", read_peb());
#endif
    printf("--- buffers ---\n");
    describe("static", g_static_buf, sizeof(g_static_buf), image);
    describe("malloc", heap_buf, heap_size, image);
    describe("calloc", calloc_buf, 256, image);
    describe("virtual", virt_buf, 0x1000, image);
    printf("--- contents ---\n");
    printf("static  @ %p: \"%s\"\n", (void *)g_static_buf, g_static_buf);
    printf("malloc  @ %p: \"%s\"\n", (void *)heap_buf, heap_buf);
    printf("calloc  @ %p: \"%s\"\n", (void *)calloc_buf, calloc_buf);
    printf("virtual @ %p: \"%s\"\n", (void *)virt_buf, virt_buf);
    printf("\nWatching (2 s). Ctrl+C to exit.\n");

    for (;;) {
        printf("[%p] %-26s | [%p] %-26s | [%p] %-26s | [%p] %s\n",
               (void *)heap_buf, heap_buf,
               (void *)calloc_buf, calloc_buf,
               (void *)virt_buf, virt_buf,
               (void *)g_static_buf, g_static_buf);
        Sleep(2000);
    }
}
