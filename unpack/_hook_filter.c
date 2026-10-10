#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stdlib.h>

typedef int (*stop_callback)(void *);
typedef int (*read_register_callback)(void *, int, void *);
typedef int (*read_memory_callback)(void *, uint64_t, void *, size_t);
typedef struct { uint64_t start, end; } Range;
typedef struct {
    uint64_t start, end;
    Range *ranges;
    size_t range_count;
    uint64_t *points, *targets;
    size_t point_count, target_count;
    unsigned char *written;
    PyObject *owner, *block, *write;
    stop_callback stop;
    uint64_t blocks, block_calls, writes, write_calls;
    int all_blocks;
    uint64_t *copies, stack_start, stack_end;
    size_t copy_count;
    read_register_callback read_register;
    read_memory_callback read_memory;
    int copy_bits, copy_registers[5];
} Filter;

static void callback_error(Filter *f, void *uc) {
    PyObject *type = NULL, *value = NULL, *traceback = NULL, *previous;
    PyErr_Fetch(&type, &value, &traceback);
    PyErr_NormalizeException(&type, &value, &traceback);
    if (value) {
        if (traceback) PyException_SetTraceback(value, traceback);
        previous = PyObject_GetAttrString(f->owner, "_hook_exception");
        if (previous == Py_None) PyObject_SetAttrString(f->owner, "_hook_exception", value);
        Py_XDECREF(previous);
    }
    Py_XDECREF(type); Py_XDECREF(value); Py_XDECREF(traceback);
    PyErr_Clear();
    f->stop(uc);
}

static int compare_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int contains(const uint64_t *values, size_t count, uint64_t value) {
    size_t left = 0, right = count;
    if (!count || value < values[0] || value > values[count - 1]) return 0;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        if (values[middle] == value) return 1;
        if (values[middle] < value) left = middle + 1;
        else right = middle;
    }
    return 0;
}

static int forward_copy(Filter *f, void *uc, uint64_t address) {
    unsigned char code[2];
    uint64_t registers[5] = {0};
    uint64_t count, source, destination;
    int i;
    if (f->read_memory(uc, address, code, sizeof(code)) || code[0] != 0xf3 || code[1] != 0xa4)
        return 1;
    for (i = 0; i < 5; ++i) {
        if (f->copy_bits == 32 || i >= 3) {
            uint32_t value = 0;
            if (f->read_register(uc, f->copy_registers[i], &value)) return 1;
            registers[i] = value;
        } else if (f->read_register(uc, f->copy_registers[i], &registers[i])) return 1;
    }
    if ((registers[3] & 0x100) || (f->copy_bits == 32 && registers[4] == 0x33)) return 1;
    count = registers[0]; source = registers[1]; destination = registers[2];
    return !(registers[3] & 0x400) && count && count <= f->stack_end - f->stack_start &&
           source >= f->stack_start && source <= f->stack_end - count &&
           destination >= f->stack_start && destination <= f->stack_end - count;
}

static void filter_block(void *uc, uint64_t address, uint32_t size, void *user) {
    Filter *f = (Filter *)user;
    int forward = f->all_blocks || address < f->start || address >= f->end;
    size_t i;
    ++f->blocks;
    if ((f->blocks & 65535) == 0) {
        PyGILState_STATE gil = PyGILState_Ensure();
        int interrupted = PyErr_CheckSignals() < 0;
        if (interrupted) callback_error(f, uc);
        PyGILState_Release(gil);
        if (interrupted) return;
    }
    if (!forward) forward = contains(f->points, f->point_count, address);
    for (i = 0; !forward && i < f->range_count; ++i)
        forward = f->ranges[i].start <= address && address < f->ranges[i].end;
    if (!forward && contains(f->copies, f->copy_count, address))
        forward = forward_copy(f, uc, address);
    if (forward) {
        PyGILState_STATE gil = PyGILState_Ensure();
        PyObject *result;
        ++f->block_calls;
        result = PyObject_CallFunction(f->block, "OKIO", f->owner,
                                       (unsigned long long)address, (unsigned int)size, Py_None);
        if (!result) callback_error(f, uc);
        Py_XDECREF(result);
        PyGILState_Release(gil);
    }
}

static void filter_write(void *uc, int access, uint64_t address, int size, int64_t value, void *user) {
    Filter *f = (Filter *)user;
    uint64_t end;
    size_t i;
    int forward;
    ++f->writes;
    if (size <= 0) return;
    end = (uint64_t)size > UINT64_MAX - address ? UINT64_MAX : address + (uint64_t)size;
    forward = (size == 4 || size == 8) && contains(f->targets, f->target_count,
                                                size == 4 ? (uint32_t)value : (uint64_t)value);
    for (i = 0; i < f->range_count; ++i) {
        uint64_t left = address > f->ranges[i].start ? address : f->ranges[i].start;
        uint64_t right = end < f->ranges[i].end ? end : f->ranges[i].end;
        if (left < right) {
            uint64_t page, last = (right - 1 - f->start) >> 12;
            for (page = (left - f->start) >> 12; page <= last; ++page) {
                unsigned char bit = (unsigned char)(1u << (page & 7));
                if (!(f->written[page >> 3] & bit)) {
                    forward = 1;
                }
            }
        }
    }
    if (forward) {
        PyGILState_STATE gil = PyGILState_Ensure();
        PyObject *result;
        ++f->write_calls;
        result = PyObject_CallFunction(f->write, "OiKiLO", f->owner, access,
                                       (unsigned long long)address, size, (long long)value, Py_None);
        if (!result) callback_error(f, uc);
        else {
            for (i = 0; i < f->range_count; ++i) {
                uint64_t left = address > f->ranges[i].start ? address : f->ranges[i].start;
                uint64_t right = end < f->ranges[i].end ? end : f->ranges[i].end;
                if (left < right) {
                    uint64_t page, last = (right - 1 - f->start) >> 12;
                    for (page = (left - f->start) >> 12; page <= last; ++page)
                        f->written[page >> 3] |= (unsigned char)(1u << (page & 7));
                }
            }
        }
        Py_XDECREF(result);
        PyGILState_Release(gil);
    }
}

static void free_filter(Filter *f) {
    if (!f) return;
    free(f->ranges); free(f->points); free(f->targets); free(f->written); free(f->copies); free(f);
}

static void capsule_free(PyObject *capsule) {
    Filter *f = PyCapsule_GetPointer(capsule, "unpack.hook_filter");
    if (f) free_filter(f);
    else PyErr_Clear();
}

static int read_addresses(PyObject *obj, uint64_t **values, size_t *count) {
    PyObject *seq = PySequence_Fast(obj, "expected address sequence");
    Py_ssize_t i, n;
    if (!seq) return 0;
    n = PySequence_Fast_GET_SIZE(seq);
    if ((size_t)n > SIZE_MAX / sizeof(uint64_t)) {
        Py_DECREF(seq); PyErr_NoMemory(); return 0;
    }
    *count = (size_t)n;
    *values = n ? malloc((size_t)n * sizeof(uint64_t)) : NULL;
    if (n && !*values) { Py_DECREF(seq); PyErr_NoMemory(); return 0; }
    for (i = 0; i < n; ++i) {
        (*values)[i] = PyLong_AsUnsignedLongLong(PySequence_Fast_GET_ITEM(seq, i));
        if (PyErr_Occurred()) { Py_DECREF(seq); return 0; }
    }
    Py_DECREF(seq);
    if (n > 1) qsort(*values, (size_t)n, sizeof(uint64_t), compare_u64);
    return 1;
}

static PyObject *create_filter(PyObject *self, PyObject *args) {
    unsigned long long start, end, stop;
    PyObject *ranges, *points, *targets, *owner, *block, *write, *seq = NULL, *capsule;
    Filter *f;
    Py_ssize_t i, n;
    uint64_t pages;
    int all_blocks;
    if (!PyArg_ParseTuple(args, "KKOOOOOOKi", &start, &end, &ranges, &points, &targets,
                          &owner, &block, &write, &stop, &all_blocks)) return NULL;
    if (start >= end || (start & 4095) || !stop || !PyCallable_Check(block) || !PyCallable_Check(write)) {
        PyErr_SetString(PyExc_ValueError, "invalid filter bounds or callback"); return NULL;
    }
    f = calloc(1, sizeof(Filter));
    if (!f) return PyErr_NoMemory();
    f->start = start; f->end = end; f->all_blocks = all_blocks;
    f->owner = owner; f->block = block; f->write = write;
    f->stop = (stop_callback)(uintptr_t)stop;
    pages = ((end - start - 1) >> 12) + 1;
    if ((pages + 7) / 8 > SIZE_MAX) { PyErr_NoMemory(); goto fail; }
    f->written = calloc((size_t)((pages + 7) / 8), 1);
    if (!f->written) { PyErr_NoMemory(); goto fail; }
    if (!read_addresses(points, &f->points, &f->point_count) ||
        !read_addresses(targets, &f->targets, &f->target_count)) goto fail;
    seq = PySequence_Fast(ranges, "expected range sequence");
    if (!seq) goto fail;
    n = PySequence_Fast_GET_SIZE(seq);
    if ((size_t)n > SIZE_MAX / sizeof(Range)) { PyErr_NoMemory(); goto fail; }
    f->range_count = (size_t)n;
    f->ranges = n ? calloc((size_t)n, sizeof(Range)) : NULL;
    if (n && !f->ranges) { PyErr_NoMemory(); goto fail; }
    for (i = 0; i < n; ++i) {
        PyObject *pair = PySequence_Fast(PySequence_Fast_GET_ITEM(seq, i), "expected range pair");
        if (!pair) goto fail;
        if (PySequence_Fast_GET_SIZE(pair) != 2) {
            Py_DECREF(pair); PyErr_SetString(PyExc_ValueError, "expected two range bounds"); goto fail;
        }
        f->ranges[i].start = PyLong_AsUnsignedLongLong(PySequence_Fast_GET_ITEM(pair, 0));
        f->ranges[i].end = PyLong_AsUnsignedLongLong(PySequence_Fast_GET_ITEM(pair, 1));
        Py_DECREF(pair);
        if (PyErr_Occurred()) goto fail;
        if (f->ranges[i].start < start || f->ranges[i].end > end || f->ranges[i].start >= f->ranges[i].end) {
            PyErr_SetString(PyExc_ValueError, "destination range outside image"); goto fail;
        }
    }
    Py_DECREF(seq);
    capsule = PyCapsule_New(f, "unpack.hook_filter", capsule_free);
    if (!capsule) { free_filter(f); return NULL; }
    return Py_BuildValue("NKKK", capsule, (unsigned long long)(uintptr_t)f,
                         (unsigned long long)(uintptr_t)filter_block, (unsigned long long)(uintptr_t)filter_write);
fail:
    Py_XDECREF(seq); free_filter(f); return NULL;
}

static PyObject *block_count(PyObject *self, PyObject *capsule) {
    Filter *f = PyCapsule_GetPointer(capsule, "unpack.hook_filter");
    return f ? PyLong_FromUnsignedLongLong(f->blocks) : NULL;
}

static PyObject *configure_copies(PyObject *self, PyObject *args) {
    PyObject *capsule, *addresses;
    unsigned long long read_register, read_memory, stack_start, stack_end;
    int bits, registers[5];
    uint64_t *copies = NULL;
    size_t count;
    Filter *f;
    if (!PyArg_ParseTuple(args, "OOKKKKi(iiiii)", &capsule, &addresses, &read_register, &read_memory,
                          &stack_start, &stack_end, &bits, &registers[0], &registers[1], &registers[2],
                          &registers[3], &registers[4])) return NULL;
    f = PyCapsule_GetPointer(capsule, "unpack.hook_filter");
    if (!f) return NULL;
    if (!read_register || !read_memory || stack_start >= stack_end || (bits != 32 && bits != 64)) {
        PyErr_SetString(PyExc_ValueError, "invalid copy filter"); return NULL;
    }
    if (!read_addresses(addresses, &copies, &count)) { free(copies); return NULL; }
    free(f->copies);
    f->copies = copies; f->copy_count = count; f->copy_bits = bits;
    f->stack_start = stack_start; f->stack_end = stack_end;
    f->read_register = (read_register_callback)(uintptr_t)read_register;
    f->read_memory = (read_memory_callback)(uintptr_t)read_memory;
    for (int i = 0; i < 5; ++i) f->copy_registers[i] = registers[i];
    Py_RETURN_NONE;
}

static PyObject *statistics(PyObject *self, PyObject *capsule) {
    Filter *f = PyCapsule_GetPointer(capsule, "unpack.hook_filter");
    if (!f) return NULL;
    return Py_BuildValue("{s:K,s:K,s:K,s:K}", "blocks", (unsigned long long)f->blocks,
                         "python_block_callbacks", (unsigned long long)f->block_calls,
                         "image_writes", (unsigned long long)f->writes,
                         "python_write_callbacks", (unsigned long long)f->write_calls);
}

static PyMethodDef methods[] = {
    {"create", create_filter, METH_VARARGS, NULL},
    {"configure_copies", configure_copies, METH_VARARGS, NULL},
    {"block_count", block_count, METH_O, NULL},
    {"statistics", statistics, METH_O, NULL},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "_hook_filter", NULL, -1, methods};
PyMODINIT_FUNC PyInit__hook_filter(void) { return PyModule_Create(&module); }
