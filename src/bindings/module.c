/*
 * module.c -- CPython binding for the vmem core.
 *
 * Deliberately thin: parse arguments, call the C API, convert results.
 * All logic (segments, translation, scanning, EPROCESS walking) lives in
 * src/core, which does not include Python.h.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdlib.h>
#include <string.h>

#include "vmem/vmem.h"
#include "vmem/vmem_windows.h"

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static vmem_arch arch_from_string(const char *s)
{
    if (!s || !*s) return VMEM_ARCH_UNKNOWN;
    if (!strcmp(s, "x86_64") || !strcmp(s, "x64") || !strcmp(s, "amd64"))
        return VMEM_ARCH_X86_64;
    if (!strcmp(s, "arm64") || !strcmp(s, "aarch64"))
        return VMEM_ARCH_ARM64;
    return VMEM_ARCH_UNKNOWN;
}

static const char *arch_to_string(vmem_arch a)
{
    switch (a) {
    case VMEM_ARCH_X86_64: return "x86_64";
    case VMEM_ARCH_ARM64:  return "arm64";
    default:               return "unknown";
    }
}

static void set_error(int err)
{
    const char *msg;
    switch (err) {
    case VMEM_EINVAL:   msg = "invalid argument"; break;
    case VMEM_ENOMEM:   msg = "out of memory"; break;
    case VMEM_EIO:      msg = "i/o error"; break;
    case VMEM_ENOTSUP:  msg = "not supported on this platform"; break;
    case VMEM_EFORMAT:  msg = "bad format"; break;
    case VMEM_ENOENT:   msg = "not found"; break;
    case VMEM_EBACKEND: msg = "no usable memory backend found"; break;
    default:            msg = "vmem error"; break;
    }
    PyErr_SetString(PyExc_RuntimeError, msg);
}

/* Accept str, bytes and os.PathLike for path arguments ("O&" converter). */
static int path_converter(PyObject *obj, void *result)
{
    PyObject *bytes = NULL;
    if (PyUnicode_FSConverter(obj, &bytes) < 0) return 0;
    *(PyObject **)result = bytes;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Python-callback backed physical memory source                      */
/* ------------------------------------------------------------------ */

typedef struct {
    PyObject *fn; /* callable(offset:int, length:int) -> bytes */
} py_read_ctx;

static int py_read_at(void *ctx, uint64_t off, void *buf, size_t len,
                      size_t *got)
{
    py_read_ctx *c = ctx;
    PyObject *res = PyObject_CallFunction(c->fn, "KK",
                                          (unsigned long long)off,
                                          (unsigned long long)len);
    Py_ssize_t n;

    if (!res) {
        /* Treat a failing read as an unmapped page; the core zero-fills. */
        PyErr_Clear();
        *got = 0;
        return VMEM_EIO;
    }
    if (!PyBytes_Check(res)) {
        Py_DECREF(res);
        PyErr_Clear();
        *got = 0;
        return VMEM_EIO;
    }
    n = PyBytes_GET_SIZE(res);
    if ((size_t)n > len) n = (Py_ssize_t)len;
    memcpy(buf, PyBytes_AS_STRING(res), (size_t)n);
    Py_DECREF(res);
    *got = (size_t)n;
    return VMEM_OK;
}

static void py_read_destroy(void *ctx)
{
    py_read_ctx *c = ctx;
    Py_XDECREF(c->fn);
    free(c);
}

/* ------------------------------------------------------------------ */
/* Memory                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    PyObject_HEAD
    vmem_mem *mem;
} MemoryObject;

/* defined after the Space/Scanner type tables */
static PyObject *scanner_from(vmem_scanner *sc, MemoryObject *mem);
static PyObject *space_from(vmem_space *s, MemoryObject *mem);

static void Memory_dealloc(MemoryObject *self)
{
    if (self->mem) vmem_close(self->mem);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyTypeObject MemoryType; /* forward */

static PyObject *memory_from(vmem_mem *m)
{
    MemoryObject *o;
    if (!m) return NULL;
    o = (MemoryObject *)MemoryType.tp_alloc(&MemoryType, 0);
    if (!o) { vmem_close(m); return NULL; }
    o->mem = m;
    return (PyObject *)o;
}

static PyObject *Memory_open_flat(PyObject *cls, PyObject *args, PyObject *kw)
{
    static char *kwlist[] = {"path", "arch", "gpa_base", "below_4g", NULL};
    PyObject *path_obj = NULL;
    const char *arch_s = "x86_64";
    unsigned long long gpa_base = 0, below_4g = 0;
    vmem_arch arch;
    int err = 0;
    vmem_mem *m;

    (void)cls;
    if (!PyArg_ParseTupleAndKeywords(args, kw, "O&|sKK", kwlist,
                                     path_converter, &path_obj, &arch_s,
                                     &gpa_base, &below_4g))
        return NULL;
    arch = arch_from_string(arch_s);
    if (arch == VMEM_ARCH_UNKNOWN) {
        Py_DECREF(path_obj);
        PyErr_SetString(PyExc_ValueError, "arch must be 'x86_64' or 'arm64'");
        return NULL;
    }
    m = vmem_open_flat(PyBytes_AS_STRING(path_obj), arch, gpa_base, below_4g,
                       &err);
    Py_DECREF(path_obj);
    if (!m) { set_error(err); return NULL; }
    return memory_from(m);
}

static PyObject *Memory_open_elf(PyObject *cls, PyObject *args, PyObject *kw)
{
    static char *kwlist[] = {"path", "arch", NULL};
    PyObject *path_obj = NULL;
    const char *arch_s = NULL;
    vmem_arch arch = VMEM_ARCH_UNKNOWN;
    int err = 0;
    vmem_mem *m;

    (void)cls;
    if (!PyArg_ParseTupleAndKeywords(args, kw, "O&|z", kwlist,
                                     path_converter, &path_obj, &arch_s))
        return NULL;
    if (arch_s) {
        arch = arch_from_string(arch_s);
        if (arch == VMEM_ARCH_UNKNOWN) {
            Py_DECREF(path_obj);
            PyErr_SetString(PyExc_ValueError, "arch must be 'x86_64' or 'arm64'");
            return NULL;
        }
    }
    m = vmem_open_elf(PyBytes_AS_STRING(path_obj), arch, &err);
    Py_DECREF(path_obj);
    if (!m) { set_error(err); return NULL; }
    return memory_from(m);
}

static PyObject *Memory_open_procmem(PyObject *cls, PyObject *args,
                                     PyObject *kw)
{
    static char *kwlist[] = {"pid", "below_4g", "arch", NULL};
    int pid;
    unsigned long long below_4g = 0;
    const char *arch_s = "x86_64";
    vmem_arch arch;
    int err = 0;
    vmem_mem *m;

    (void)cls;
    if (!PyArg_ParseTupleAndKeywords(args, kw, "i|Ks", kwlist, &pid,
                                     &below_4g, &arch_s))
        return NULL;
    arch = arch_from_string(arch_s);
    if (arch == VMEM_ARCH_UNKNOWN) {
        PyErr_SetString(PyExc_ValueError, "arch must be 'x86_64' or 'arm64'");
        return NULL;
    }
    m = vmem_open_procmem_auto(pid, below_4g, &err);
    if (!m) { set_error(err); return NULL; }
    vmem_set_arch(m, arch);
    return memory_from(m);
}

static PyObject *Memory_open_callback(PyObject *cls, PyObject *args,
                                      PyObject *kw)
{
    static char *kwlist[] = {"callback", "segments", "arch", NULL};
    PyObject *fn, *seq;
    const char *arch_s;
    vmem_arch arch;
    Py_ssize_t n, i;
    vmem_segment *segs;
    py_read_ctx *ctx;
    vmem_mem *m;
    int err = 0;

    (void)cls;
    if (!PyArg_ParseTupleAndKeywords(args, kw, "OOs", kwlist, &fn, &seq,
                                     &arch_s))
        return NULL;
    if (!PyCallable_Check(fn)) {
        PyErr_SetString(PyExc_TypeError, "callback must be callable");
        return NULL;
    }
    arch = arch_from_string(arch_s);
    if (arch == VMEM_ARCH_UNKNOWN) {
        PyErr_SetString(PyExc_ValueError, "arch must be 'x86_64' or 'arm64'");
        return NULL;
    }
    seq = PySequence_Fast(seq, "segments must be a sequence");
    if (!seq) return NULL;
    n = PySequence_Fast_GET_SIZE(seq);
    segs = calloc((size_t)(n ? n : 1), sizeof(*segs));
    if (!segs) { Py_DECREF(seq); return PyErr_NoMemory(); }

    for (i = 0; i < n; i++) {
        PyObject *item = PySequence_Fast_GET_ITEM(seq, i);
        unsigned long long gpa, size, off;
        if (!PyArg_ParseTuple(item, "KKK", &gpa, &size, &off)) {
            free(segs);
            Py_DECREF(seq);
            return NULL;
        }
        segs[i].gpa = gpa;
        segs[i].size = size;
        segs[i].file_offset = off;
        segs[i].ptr = NULL;
    }
    Py_DECREF(seq);

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) { free(segs); return PyErr_NoMemory(); }
    Py_INCREF(fn);
    ctx->fn = fn;
    m = vmem_open_custom(py_read_at, py_read_destroy, ctx, segs, (size_t)n,
                         arch, &err);
    free(segs);
    if (!m) { py_read_destroy(ctx); set_error(err); return NULL; }
    return memory_from(m);
}

static PyObject *Memory_open_procmem_segments(PyObject *cls, PyObject *args)
{
    int pid;
    PyObject *seq;
    Py_ssize_t n, i;
    vmem_segment *segs;
    const char *arch_s = "x86_64";
    vmem_arch arch;
    int err = 0;
    vmem_mem *m;

    (void)cls;
    if (!PyArg_ParseTuple(args, "iO|s", &pid, &seq, &arch_s)) return NULL;
    arch = arch_from_string(arch_s);
    if (arch == VMEM_ARCH_UNKNOWN) {
        PyErr_SetString(PyExc_ValueError, "arch must be 'x86_64' or 'arm64'");
        return NULL;
    }
    seq = PySequence_Fast(seq, "segments must be a sequence");
    if (!seq) return NULL;
    n = PySequence_Fast_GET_SIZE(seq);
    segs = calloc((size_t)(n ? n : 1), sizeof(*segs));
    if (!segs) { Py_DECREF(seq); return PyErr_NoMemory(); }

    for (i = 0; i < n; i++) {
        PyObject *item = PySequence_Fast_GET_ITEM(seq, i);
        unsigned long long gpa, size, off;
        if (!PyArg_ParseTuple(item, "KKK", &gpa, &size, &off)) {
            free(segs);
            Py_DECREF(seq);
            return NULL;
        }
        segs[i].gpa = gpa;
        segs[i].size = size;
        segs[i].file_offset = off;
        segs[i].ptr = NULL;
    }
    Py_DECREF(seq);
    m = vmem_open_procmem(pid, segs, (size_t)n, &err);
    free(segs);
    if (!m) { set_error(err); return NULL; }
    vmem_set_arch(m, arch);
    return memory_from(m);
}

static PyObject *Memory_read(MemoryObject *self, PyObject *args)
{
    unsigned long long gpa;
    Py_ssize_t n;
    PyObject *b;

    if (!PyArg_ParseTuple(args, "Kn", &gpa, &n)) return NULL;
    if (n < 0) {
        PyErr_SetString(PyExc_ValueError, "length must be >= 0");
        return NULL;
    }
    b = PyBytes_FromStringAndSize(NULL, n);
    if (!b) return NULL;
    if (n) vmem_read_phys(self->mem, gpa, PyBytes_AS_STRING(b), (size_t)n);
    return b;
}

static PyObject *Memory_read_exact(MemoryObject *self, PyObject *args)
{
    unsigned long long gpa;
    Py_ssize_t n;
    PyObject *b;

    if (!PyArg_ParseTuple(args, "Kn", &gpa, &n)) return NULL;
    if (n < 0) {
        PyErr_SetString(PyExc_ValueError, "length must be >= 0");
        return NULL;
    }
    b = PyBytes_FromStringAndSize(NULL, n);
    if (!b) return NULL;
    if (n && vmem_read_phys_exact(self->mem, gpa, PyBytes_AS_STRING(b),
                                  (size_t)n) != VMEM_OK) {
        Py_DECREF(b);
        Py_RETURN_NONE;
    }
    return b;
}

static PyObject *Memory_write(MemoryObject *self, PyObject *args)
{
    unsigned long long gpa;
    Py_buffer view;
    int rc;

    if (!PyArg_ParseTuple(args, "Ky*", &gpa, &view)) return NULL;
    rc = vmem_write_phys(self->mem, gpa, view.buf, (size_t)view.len);
    PyBuffer_Release(&view);
    if (rc != VMEM_OK) { set_error(rc); return NULL; }
    Py_RETURN_NONE;
}
#define MEM_READ_INT(name, ctype, conv)                                  \
    static PyObject *Memory_##name(MemoryObject *self, PyObject *args)   \
    {                                                                    \
        unsigned long long gpa;                                          \
        if (!PyArg_ParseTuple(args, "K", &gpa)) return NULL;             \
        return conv((ctype)vmem_phys_##name(self->mem, gpa));            \
    }

MEM_READ_INT(u8,  uint8_t,  PyLong_FromUnsignedLong)
MEM_READ_INT(u16, uint16_t, PyLong_FromUnsignedLong)
MEM_READ_INT(u32, uint32_t, PyLong_FromUnsignedLong)
MEM_READ_INT(u64, uint64_t, PyLong_FromUnsignedLongLong)

#define MEM_READ_SIGNED(name, from, ctype, conv)                         \
    static PyObject *Memory_##name(MemoryObject *self, PyObject *args)   \
    {                                                                    \
        unsigned long long gpa;                                          \
        if (!PyArg_ParseTuple(args, "K", &gpa)) return NULL;             \
        return conv((ctype)vmem_phys_##from(self->mem, gpa));            \
    }

MEM_READ_SIGNED(i8,  u8,  int8_t,  PyLong_FromLong)
MEM_READ_SIGNED(i16, u16, int16_t, PyLong_FromLong)
MEM_READ_SIGNED(i32, u32, int32_t, PyLong_FromLong)
MEM_READ_SIGNED(i64, u64, int64_t, PyLong_FromLongLong)

static PyObject *Memory_f32(MemoryObject *self, PyObject *args)
{
    unsigned long long gpa;
    uint32_t bits;
    float f;
    if (!PyArg_ParseTuple(args, "K", &gpa)) return NULL;
    bits = vmem_phys_u32(self->mem, gpa);
    memcpy(&f, &bits, sizeof(f));
    return PyFloat_FromDouble((double)f);
}

static PyObject *Memory_f64(MemoryObject *self, PyObject *args)
{
    unsigned long long gpa;
    uint64_t bits;
    double d;
    if (!PyArg_ParseTuple(args, "K", &gpa)) return NULL;
    bits = vmem_phys_u64(self->mem, gpa);
    memcpy(&d, &bits, sizeof(d));
    return PyFloat_FromDouble(d);
}

static PyObject *Memory_scan(MemoryObject *self, PyObject *args, PyObject *kw)
{
    static char *kwlist[] = {"target", "start", "end", NULL};
    Py_buffer view;
    unsigned long long start = 0;
    PyObject *end_obj = Py_None;
    unsigned long long end = 0;
    vmem_scanner *sc;
    PyObject *result;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "y*|KO", kwlist, &view, &start,
                                     &end_obj))
        return NULL;
    if (end_obj != Py_None) {
        end = PyLong_AsUnsignedLongLong(end_obj);
        if (PyErr_Occurred()) { PyBuffer_Release(&view); return NULL; }
    }
    sc = vmem_scanner_new(self->mem, start, end, view.buf, (size_t)view.len);
    PyBuffer_Release(&view);
    if (!sc) {
        PyErr_SetString(PyExc_ValueError, "empty or oversized needle");
        return NULL;
    }
    result = scanner_from(sc, self);
    return result;
}

static PyObject *Memory_space(MemoryObject *self, PyObject *args)
{
    unsigned long long base0, base1 = 0;
    const char *arch_s = NULL;
    vmem_arch arch;
    vmem_space *s;

    if (!PyArg_ParseTuple(args, "K|Kz", &base0, &base1, &arch_s)) return NULL;
    arch = arch_s ? arch_from_string(arch_s) : vmem_arch_of(self->mem);
    if (arch == VMEM_ARCH_UNKNOWN) {
        PyErr_SetString(PyExc_ValueError,
                        "unknown arch; pass arch='x86_64' or 'arm64'");
        return NULL;
    }
    s = vmem_space_new(self->mem, arch, base0, base1, base1 != 0);
    if (!s) return PyErr_NoMemory();
    return space_from(s, self);
}

static PyObject *Memory_get_arch(MemoryObject *self, void *closure)
{
    (void)closure;
    return PyUnicode_FromString(arch_to_string(vmem_arch_of(self->mem)));
}

static PyObject *Memory_get_max_gpa(MemoryObject *self, void *closure)
{
    (void)closure;
    return PyLong_FromUnsignedLongLong(vmem_max_gpa(self->mem));
}

static PyObject *Memory_get_min_gpa(MemoryObject *self, void *closure)
{
    (void)closure;
    return PyLong_FromUnsignedLongLong(vmem_min_gpa(self->mem));
}

static PyObject *Memory_get_size(MemoryObject *self, void *closure)
{
    (void)closure;
    return PyLong_FromUnsignedLongLong(vmem_total_size(self->mem));
}

static PyObject *Memory_get_segments(MemoryObject *self, void *closure)
{
    size_t n = vmem_segment_count(self->mem);
    const vmem_segment *segs = vmem_segments(self->mem);
    PyObject *list = PyList_New(0);
    (void)closure;
    if (!list) return NULL;
    for (size_t i = 0; i < n; i++) {
        PyObject *t = Py_BuildValue("(KKK)", segs[i].gpa, segs[i].size,
                                    segs[i].file_offset);
        if (!t || PyList_Append(list, t) < 0) {
            Py_XDECREF(t);
            Py_DECREF(list);
            return NULL;
        }
        Py_DECREF(t);
    }
    return list;
}

/* ------------------------------------------------------------------ */
/* Scanner                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    PyObject_HEAD
    vmem_scanner *sc;
    MemoryObject *mem;
} ScannerObject;

static PyTypeObject ScannerType;

static void Scanner_dealloc(ScannerObject *self)
{
    if (self->sc) vmem_scanner_free(self->sc);
    Py_XDECREF(self->mem);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *scanner_from(vmem_scanner *sc, MemoryObject *mem)
{
    ScannerObject *o = (ScannerObject *)ScannerType.tp_alloc(&ScannerType, 0);
    if (!o) { vmem_scanner_free(sc); return NULL; }
    Py_INCREF(mem);
    o->sc = sc;
    o->mem = mem;
    return (PyObject *)o;
}

static PyObject *Scanner_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}

static PyObject *Scanner_next(ScannerObject *self)
{
    uint64_t gpa;
    int rc = vmem_scanner_next(self->sc, &gpa);
    if (rc == 1) return PyLong_FromUnsignedLongLong(gpa);
    if (rc == 0) return NULL;
    PyErr_SetString(PyExc_RuntimeError, "scan failed");
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Space                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    PyObject_HEAD
    vmem_space *space;
    MemoryObject *mem;
} SpaceObject;

static PyTypeObject SpaceType;

static void Space_dealloc(SpaceObject *self)
{
    if (self->space) vmem_space_free(self->space);
    Py_XDECREF(self->mem);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *space_from(vmem_space *s, MemoryObject *mem)
{
    SpaceObject *o = (SpaceObject *)SpaceType.tp_alloc(&SpaceType, 0);
    if (!o) { vmem_space_free(s); return NULL; }
    Py_INCREF(mem);
    o->space = s;
    o->mem = mem;
    return (PyObject *)o;
}

static PyObject *Space_translate(SpaceObject *self, PyObject *args)
{
    unsigned long long va;
    uint64_t pa;
    if (!PyArg_ParseTuple(args, "K", &va)) return NULL;
    if (vmem_translate(self->space, va, &pa) != 0) Py_RETURN_NONE;
    return PyLong_FromUnsignedLongLong(pa);
}

static PyObject *Space_read(SpaceObject *self, PyObject *args)
{
    unsigned long long va;
    Py_ssize_t n;
    PyObject *b;
    if (!PyArg_ParseTuple(args, "Kn", &va, &n)) return NULL;
    if (n < 0) {
        PyErr_SetString(PyExc_ValueError, "length must be >= 0");
        return NULL;
    }
    b = PyBytes_FromStringAndSize(NULL, n);
    if (!b) return NULL;
    if (n) vmem_space_read(self->space, va, PyBytes_AS_STRING(b), (size_t)n);
    return b;
}

static PyObject *Space_read_exact(SpaceObject *self, PyObject *args)
{
    unsigned long long va;
    Py_ssize_t n;
    PyObject *b;
    if (!PyArg_ParseTuple(args, "Kn", &va, &n)) return NULL;
    if (n < 0) {
        PyErr_SetString(PyExc_ValueError, "length must be >= 0");
        return NULL;
    }
    b = PyBytes_FromStringAndSize(NULL, n);
    if (!b) return NULL;
    if (n && vmem_space_read_exact(self->space, va, PyBytes_AS_STRING(b),
                                   (size_t)n) != VMEM_OK) {
        Py_DECREF(b);
        Py_RETURN_NONE;
    }
    return b;
}

static PyObject *Space_write(SpaceObject *self, PyObject *args)
{
    unsigned long long va;
    Py_buffer view;
    int rc;

    if (!PyArg_ParseTuple(args, "Ky*", &va, &view)) return NULL;
    rc = vmem_space_write(self->space, va, view.buf, (size_t)view.len);
    PyBuffer_Release(&view);
    if (rc != VMEM_OK) { set_error(rc); return NULL; }
    Py_RETURN_NONE;
}

#define SPACE_READ_INT(name, ctype, conv)                                \
    static PyObject *Space_##name(SpaceObject *self, PyObject *args)     \
    {                                                                    \
        unsigned long long va;                                           \
        if (!PyArg_ParseTuple(args, "K", &va)) return NULL;              \
        return conv((ctype)vmem_space_##name(self->space, va));          \
    }

SPACE_READ_INT(u8,  uint8_t,  PyLong_FromUnsignedLong)
SPACE_READ_INT(u16, uint16_t, PyLong_FromUnsignedLong)
SPACE_READ_INT(u32, uint32_t, PyLong_FromUnsignedLong)
SPACE_READ_INT(u64, uint64_t, PyLong_FromUnsignedLongLong)

#define SPACE_READ_SIGNED(name, from, ctype, conv)                       \
    static PyObject *Space_##name(SpaceObject *self, PyObject *args)     \
    {                                                                    \
        unsigned long long va;                                           \
        if (!PyArg_ParseTuple(args, "K", &va)) return NULL;              \
        return conv((ctype)vmem_space_##from(self->space, va));          \
    }

SPACE_READ_SIGNED(i8,  u8,  int8_t,  PyLong_FromLong)
SPACE_READ_SIGNED(i16, u16, int16_t, PyLong_FromLong)
SPACE_READ_SIGNED(i32, u32, int32_t, PyLong_FromLong)
SPACE_READ_SIGNED(i64, u64, int64_t, PyLong_FromLongLong)

static PyObject *Space_f32(SpaceObject *self, PyObject *args)
{
    unsigned long long va;
    uint32_t bits;
    float f;
    if (!PyArg_ParseTuple(args, "K", &va)) return NULL;
    bits = vmem_space_u32(self->space, va);
    memcpy(&f, &bits, sizeof(f));
    return PyFloat_FromDouble((double)f);
}

static PyObject *Space_f64(SpaceObject *self, PyObject *args)
{
    unsigned long long va;
    uint64_t bits;
    double d;
    if (!PyArg_ParseTuple(args, "K", &va)) return NULL;
    bits = vmem_space_u64(self->space, va);
    memcpy(&d, &bits, sizeof(d));
    return PyFloat_FromDouble(d);
}

static PyObject *Space_cstring(SpaceObject *self, PyObject *args, PyObject *kw)
{
    static char *kwlist[] = {"va", "max_len", NULL};
    unsigned long long va;
    Py_ssize_t max_len = 256;
    char *buf;
    size_t out_len = 0;
    PyObject *r;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "K|n", kwlist, &va, &max_len))
        return NULL;
    if (max_len <= 0) return PyUnicode_FromString("");
    buf = malloc((size_t)max_len + 1);
    if (!buf) return PyErr_NoMemory();
    vmem_space_cstring(self->space, va, buf, (size_t)max_len + 1, &out_len);
    r = PyUnicode_DecodeASCII(buf, (Py_ssize_t)out_len, "replace");
    free(buf);
    return r;
}

static PyObject *Space_wstring(SpaceObject *self, PyObject *args, PyObject *kw)
{
    static char *kwlist[] = {"va", "max_len", NULL};
    unsigned long long va;
    Py_ssize_t max_len = 512;
    uint16_t *buf;
    size_t out_len = 0;
    PyObject *r;
    int byteorder = -1; /* little endian */

    if (!PyArg_ParseTupleAndKeywords(args, kw, "K|n", kwlist, &va, &max_len))
        return NULL;
    if (max_len <= 0) return PyUnicode_FromString("");
    buf = malloc((size_t)max_len * sizeof(*buf));
    if (!buf) return PyErr_NoMemory();
    vmem_space_wstring(self->space, va, buf, (size_t)max_len, &out_len);
    r = PyUnicode_DecodeUTF16((const char *)buf,
                              (Py_ssize_t)(out_len * sizeof(*buf)),
                              "replace", &byteorder);
    free(buf);
    return r;
}

static PyObject *Space_get_base0(SpaceObject *self, void *closure)
{
    (void)closure;
    return PyLong_FromUnsignedLongLong(vmem_space_base0(self->space));
}

static PyObject *Space_get_base1(SpaceObject *self, void *closure)
{
    (void)closure;
    return PyLong_FromUnsignedLongLong(vmem_space_base1(self->space));
}

static PyObject *Space_get_arch(SpaceObject *self, void *closure)
{
    (void)closure;
    return PyUnicode_FromString(arch_to_string(vmem_space_arch(self->space)));
}

/* ------------------------------------------------------------------ */
/* Windows                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    PyObject_HEAD
    vmem_windows *win;
    MemoryObject *mem;
} WindowsObject;

static PyTypeObject WindowsType;

static void Windows_dealloc(WindowsObject *self)
{
    if (self->win) vmem_windows_free(self->win);
    Py_XDECREF(self->mem);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static int Windows_init(WindowsObject *self, PyObject *args, PyObject *kw)
{
    static char *kwlist[] = {"memory", "offsets", "system_pa", "kernel_base",
                             NULL};
    MemoryObject *mem;
    PyObject *dict;
    vmem_eprocess_offsets off = {0};
    unsigned long long system_pa = 0, kernel_base = 0;
    int err = 0;
    struct { const char *key; uint32_t *field; } map[] = {
        {"directory_table_base", &off.directory_table_base},
        {"unique_process_id",    &off.unique_process_id},
        {"active_process_links", &off.active_process_links},
        {"image_file_name",      &off.image_file_name},
        {"virtual_size",         &off.virtual_size},
        {"active_threads",       &off.active_threads},
        {"peb",                  &off.peb},
        {"inherited_from_unique_process_id",
                                 &off.inherited_from_unique_process_id},
    };

    if (!PyArg_ParseTupleAndKeywords(args, kw, "O!O!|KK", kwlist,
                                     &MemoryType, &mem, &PyDict_Type, &dict,
                                     &system_pa, &kernel_base))
        return -1;

    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        PyObject *v = PyDict_GetItemString(dict, map[i].key);
        unsigned long val;
        if (!v) continue;
        val = PyLong_AsUnsignedLong(v);
        if (PyErr_Occurred()) return -1;
        *map[i].field = (uint32_t)val;
    }

    if (self->win) { vmem_windows_free(self->win); self->win = NULL; }
    self->win = vmem_windows_new(mem->mem, &off, &err);
    if (!self->win) { set_error(err); return -1; }
    if (system_pa) {
        int rc = vmem_windows_seed(self->win, system_pa, kernel_base);
        if (rc != VMEM_OK) {
            PyErr_Format(PyExc_ValueError,
                         "system_pa %#llx is not the System EPROCESS",
                         system_pa);
            return -1;
        }
    }
    Py_INCREF(mem);
    Py_XSETREF(self->mem, mem);
    return 0;
}

static PyObject *proc_to_dict(const vmem_process *p)
{
    return Py_BuildValue("{s:K,s:K,s:s,s:K,s:K,s:K,s:i,s:K}",
                         "pid", p->pid,
                         "ppid", p->ppid,
                         "name", p->name,
                         "dtb", p->dtb,
                         "eprocess_pa", p->eprocess_pa,
                         "eprocess_va", p->eprocess_va,
                         "threads", (int)p->threads,
                         "vsize", p->vsize);
}

static PyObject *Windows_find_system(WindowsObject *self, PyObject *Py_UNUSED(a))
{
    int rc = vmem_windows_find_system(self->win);
    if (rc != VMEM_OK) {
        if (rc == VMEM_ENOENT) Py_RETURN_NONE;
        set_error(rc);
        return NULL;
    }
    return PyLong_FromUnsignedLongLong(vmem_windows_system_pa(self->win));
}

static PyObject *Windows_processes(WindowsObject *self, PyObject *Py_UNUSED(a))
{
    vmem_process *procs = NULL;
    size_t n = 0;
    PyObject *list;
    int rc = vmem_windows_processes(self->win, &procs, &n);

    if (rc != VMEM_OK) { set_error(rc); return NULL; }
    list = PyList_New(0);
    if (!list) { vmem_processes_free(procs); return NULL; }
    for (size_t i = 0; i < n; i++) {
        PyObject *d = proc_to_dict(&procs[i]);
        if (!d || PyList_Append(list, d) < 0) {
            Py_XDECREF(d);
            Py_DECREF(list);
            vmem_processes_free(procs);
            return NULL;
        }
        Py_DECREF(d);
    }
    vmem_processes_free(procs);
    return list;
}

static PyObject *Windows_find_pid(WindowsObject *self, PyObject *arg)
{
    unsigned long long pid = PyLong_AsUnsignedLongLong(arg);
    vmem_process p;
    int rc;
    if (PyErr_Occurred()) return NULL;
    rc = vmem_windows_find_pid(self->win, pid, &p);
    if (rc == VMEM_ENOENT) Py_RETURN_NONE;
    if (rc != VMEM_OK) { set_error(rc); return NULL; }
    return proc_to_dict(&p);
}

static PyObject *Windows_find_name(WindowsObject *self, PyObject *arg)
{
    const char *name = PyUnicode_AsUTF8(arg);
    vmem_process p;
    int rc;
    if (!name) return NULL;
    rc = vmem_windows_find_name(self->win, name, &p);
    if (rc == VMEM_ENOENT) Py_RETURN_NONE;
    if (rc != VMEM_OK) { set_error(rc); return NULL; }
    return proc_to_dict(&p);
}

static PyObject *Windows_space(WindowsObject *self, PyObject *arg)
{
    vmem_process p;
    int rc;
    vmem_space *s;

    if (PyLong_Check(arg)) {
        unsigned long long pid = PyLong_AsUnsignedLongLong(arg);
        if (PyErr_Occurred()) return NULL;
        rc = vmem_windows_find_pid(self->win, pid, &p);
    } else if (PyUnicode_Check(arg)) {
        const char *name = PyUnicode_AsUTF8(arg);
        if (!name) return NULL;
        rc = vmem_windows_find_name(self->win, name, &p);
    } else {
        PyErr_SetString(PyExc_TypeError, "expected pid (int) or name (str)");
        return NULL;
    }
    if (rc == VMEM_ENOENT) {
        PyErr_SetString(PyExc_LookupError, "process not found");
        return NULL;
    }
    if (rc != VMEM_OK) { set_error(rc); return NULL; }

    s = vmem_windows_space(self->win, &p);
    if (!s) return PyErr_NoMemory();
    return space_from(s, self->mem);
}

static PyObject *Windows_kernel_space(WindowsObject *self, PyObject *Py_UNUSED(a))
{
    vmem_space *s;
    if (vmem_windows_find_system(self->win) != VMEM_OK) {
        PyErr_SetString(PyExc_RuntimeError, "System EPROCESS not found");
        return NULL;
    }
    s = vmem_windows_kernel_space(self->win);
    if (!s) {
        PyErr_SetString(PyExc_RuntimeError, "no kernel page table base");
        return NULL;
    }
    return space_from(s, self->mem);
}

static PyObject *Windows_get_system_pa(WindowsObject *self, void *c)
{
    (void)c;
    return PyLong_FromUnsignedLongLong(vmem_windows_system_pa(self->win));
}

static PyObject *Windows_get_kernel_base(WindowsObject *self, void *c)
{
    (void)c;
    return PyLong_FromUnsignedLongLong(vmem_windows_kernel_base(self->win));
}

/* ------------------------------------------------------------------ */
/* method / type tables                                               */
/* ------------------------------------------------------------------ */

static PyMethodDef Memory_methods[] = {
    {"open_flat", (PyCFunction)Memory_open_flat, METH_VARARGS | METH_KEYWORDS | METH_STATIC, NULL},
    {"open_elf",  (PyCFunction)Memory_open_elf,  METH_VARARGS | METH_KEYWORDS | METH_STATIC, NULL},
    {"open_procmem", (PyCFunction)Memory_open_procmem, METH_VARARGS | METH_KEYWORDS | METH_STATIC, NULL},
    {"open_procmem_segments", (PyCFunction)Memory_open_procmem_segments, METH_VARARGS | METH_STATIC, NULL},
    {"open_callback", (PyCFunction)Memory_open_callback, METH_VARARGS | METH_KEYWORDS | METH_STATIC, NULL},
    {"read",       (PyCFunction)Memory_read,       METH_VARARGS, NULL},
    {"read_exact", (PyCFunction)Memory_read_exact, METH_VARARGS, NULL},
    {"write",      (PyCFunction)Memory_write,      METH_VARARGS, NULL},
    {"u8",  (PyCFunction)Memory_u8,  METH_VARARGS, NULL},
    {"u16", (PyCFunction)Memory_u16, METH_VARARGS, NULL},
    {"u32", (PyCFunction)Memory_u32, METH_VARARGS, NULL},
    {"u64", (PyCFunction)Memory_u64, METH_VARARGS, NULL},
    {"i8",  (PyCFunction)Memory_i8,  METH_VARARGS, NULL},
    {"i16", (PyCFunction)Memory_i16, METH_VARARGS, NULL},
    {"i32", (PyCFunction)Memory_i32, METH_VARARGS, NULL},
    {"i64", (PyCFunction)Memory_i64, METH_VARARGS, NULL},
    {"f32", (PyCFunction)Memory_f32, METH_VARARGS, NULL},
    {"f64", (PyCFunction)Memory_f64, METH_VARARGS, NULL},
    {"scan", (PyCFunction)Memory_scan, METH_VARARGS | METH_KEYWORDS, NULL},
    {"space", (PyCFunction)Memory_space, METH_VARARGS, NULL},
    {NULL}
};

static PyGetSetDef Memory_getset[] = {
    {"arch",      (getter)Memory_get_arch,     NULL, NULL, NULL},
    {"max_gpa",   (getter)Memory_get_max_gpa,  NULL, NULL, NULL},
    {"min_gpa",   (getter)Memory_get_min_gpa,  NULL, NULL, NULL},
    {"size",      (getter)Memory_get_size,     NULL, NULL, NULL},
    {"segments",  (getter)Memory_get_segments, NULL, NULL, NULL},
    {NULL}
};

static PyTypeObject MemoryType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "vmem._core.Memory",
    .tp_basicsize = sizeof(MemoryObject),
    .tp_dealloc = (destructor)Memory_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_methods = Memory_methods,
    .tp_getset = Memory_getset,
};

static PyMethodDef Scanner_methods[] = {
    {NULL}
};

static PyTypeObject ScannerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "vmem._core.Scanner",
    .tp_basicsize = sizeof(ScannerObject),
    .tp_dealloc = (destructor)Scanner_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_iter = Scanner_iter,
    .tp_iternext = (iternextfunc)Scanner_next,
    .tp_methods = Scanner_methods,
};

static PyMethodDef Space_methods[] = {
    {"translate",  (PyCFunction)Space_translate,  METH_VARARGS, NULL},
    {"read",       (PyCFunction)Space_read,       METH_VARARGS, NULL},
    {"read_exact", (PyCFunction)Space_read_exact, METH_VARARGS, NULL},
    {"write",      (PyCFunction)Space_write,      METH_VARARGS, NULL},
    {"u8",  (PyCFunction)Space_u8,  METH_VARARGS, NULL},
    {"u16", (PyCFunction)Space_u16, METH_VARARGS, NULL},
    {"u32", (PyCFunction)Space_u32, METH_VARARGS, NULL},
    {"u64", (PyCFunction)Space_u64, METH_VARARGS, NULL},
    {"i8",  (PyCFunction)Space_i8,  METH_VARARGS, NULL},
    {"i16", (PyCFunction)Space_i16, METH_VARARGS, NULL},
    {"i32", (PyCFunction)Space_i32, METH_VARARGS, NULL},
    {"i64", (PyCFunction)Space_i64, METH_VARARGS, NULL},
    {"f32", (PyCFunction)Space_f32, METH_VARARGS, NULL},
    {"f64", (PyCFunction)Space_f64, METH_VARARGS, NULL},
    {"cstring", (PyCFunction)Space_cstring, METH_VARARGS | METH_KEYWORDS, NULL},
    {"wstring", (PyCFunction)Space_wstring, METH_VARARGS | METH_KEYWORDS, NULL},
    {NULL}
};

static PyGetSetDef Space_getset[] = {
    {"base0", (getter)Space_get_base0, NULL, NULL, NULL},
    {"base1", (getter)Space_get_base1, NULL, NULL, NULL},
    {"arch",  (getter)Space_get_arch,  NULL, NULL, NULL},
    {NULL}
};

static PyTypeObject SpaceType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "vmem._core.Space",
    .tp_basicsize = sizeof(SpaceObject),
    .tp_dealloc = (destructor)Space_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_methods = Space_methods,
    .tp_getset = Space_getset,
};

static PyMethodDef Windows_methods[] = {
    {"find_system",   (PyCFunction)Windows_find_system,   METH_NOARGS, NULL},
    {"processes",     (PyCFunction)Windows_processes,     METH_NOARGS, NULL},
    {"find_pid",      (PyCFunction)Windows_find_pid,      METH_O, NULL},
    {"find_name",     (PyCFunction)Windows_find_name,     METH_O, NULL},
    {"space",         (PyCFunction)Windows_space,         METH_O, NULL},
    {"kernel_space",  (PyCFunction)Windows_kernel_space,  METH_NOARGS, NULL},
    {NULL}
};

static PyGetSetDef Windows_getset[] = {
    {"system_pa",   (getter)Windows_get_system_pa,   NULL, NULL, NULL},
    {"kernel_base", (getter)Windows_get_kernel_base, NULL, NULL, NULL},
    {NULL}
};

static PyTypeObject WindowsType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "vmem._core.Windows",
    .tp_basicsize = sizeof(WindowsObject),
    .tp_dealloc = (destructor)Windows_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_methods = Windows_methods,
    .tp_getset = Windows_getset,
    .tp_init = (initproc)Windows_init,
    .tp_new = PyType_GenericNew,
};

/* ------------------------------------------------------------------ */
/* module                                                             */
/* ------------------------------------------------------------------ */

static PyModuleDef vmem_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "vmem._core",
    .m_doc = "Hypervisor-agnostic guest physical/virtual memory access.",
    .m_size = -1,
};

PyMODINIT_FUNC PyInit__core(void)
{
    PyObject *m;

    if (PyType_Ready(&MemoryType) < 0) return NULL;
    if (PyType_Ready(&ScannerType) < 0) return NULL;
    if (PyType_Ready(&SpaceType) < 0) return NULL;
    if (PyType_Ready(&WindowsType) < 0) return NULL;

    m = PyModule_Create(&vmem_module);
    if (!m) return NULL;

    Py_INCREF(&MemoryType);
    if (PyModule_AddObject(m, "Memory", (PyObject *)&MemoryType) < 0) goto fail;
    Py_INCREF(&ScannerType);
    if (PyModule_AddObject(m, "Scanner", (PyObject *)&ScannerType) < 0) goto fail;
    Py_INCREF(&SpaceType);
    if (PyModule_AddObject(m, "Space", (PyObject *)&SpaceType) < 0) goto fail;
    Py_INCREF(&WindowsType);
    if (PyModule_AddObject(m, "Windows", (PyObject *)&WindowsType) < 0) goto fail;

    if (PyModule_AddStringConstant(m, "X86_64", "x86_64") < 0) goto fail;
    if (PyModule_AddStringConstant(m, "ARM64", "arm64") < 0) goto fail;
    if (PyModule_AddStringConstant(m, "version", "0.1.0") < 0) goto fail;
    return m;

fail:
    Py_DECREF(m);
    return NULL;
}
