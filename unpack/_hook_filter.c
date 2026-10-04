#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stdlib.h>

typedef int (*stop_callback)(void *);
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
    forward = size == 8 && contains(f->targets, f->target_count, (uint64_t)value);
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
    free(f->ranges); free(f->points); free(f->targets); free(f->written); free(f);
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
        PyErr_SetString(PyExc_ValueError, "invalid filter bounds or callbacks"); return NULL;
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
    {"block_count", block_count, METH_O, NULL},
    {"statistics", statistics, METH_O, NULL},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "_hook_filter", NULL, -1, methods};
PyMODINIT_FUNC PyInit__hook_filter(void) { return PyModule_Create(&module); }
