import ctypes

from unicorn import (UcError, UC_HOOK_BLOCK, UC_HOOK_INSN, UC_HOOK_INTR, UC_HOOK_MEM_INVALID,
                     UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE)
import unicorn.x86_const as ux

try:
    from . import _hook_filter
    from unicorn.unicorn_py3 import unicorn as binding
except ImportError:
    _hook_filter = None


class TraceHooks:
    def __init__(self, tracer, peb_base, page_size, native=True):
        self.tracer = tracer
        self.uc = tracer.uc
        self.handles = []
        self.context = None
        self.closed = False
        self.backend = 'native' if native and _hook_filter is not None else 'python'
        try:
            if self.backend == 'native':
                self.install_native()
            else:
                self.handles.append(self.uc.hook_add(UC_HOOK_BLOCK, tracer.on_block))
                self.handles.append(self.uc.hook_add(UC_HOOK_MEM_WRITE, tracer.on_image_write,
                                                    begin=tracer.image_start, end=tracer.image_end - 1))
            self.handles.append(self.uc.hook_add(UC_HOOK_INSN, tracer.on_syscall_instruction,
                                                None, 1, 0, ux.UC_X86_INS_SYSCALL))
            self.handles.append(self.uc.hook_add(UC_HOOK_INSN, tracer.on_cpuid_instruction,
                                                None, 1, 0, ux.UC_X86_INS_CPUID))
            self.handles.append(self.uc.hook_add(UC_HOOK_MEM_INVALID, tracer.on_invalid_memory))
            self.handles.append(self.uc.hook_add(UC_HOOK_INTR, tracer.single_step.interrupt))
            if tracer.diagnostics is not None:
                self.handles.append(self.uc.hook_add(UC_HOOK_MEM_READ, tracer.on_peb_read,
                                                    begin=peb_base, end=peb_base + page_size - 1))
        except BaseException:
            self.close()
            raise

    def install_native(self):
        tracer = self.tracer

        self.callbacks = (tracer.on_block, tracer.on_image_write)
        points = ({tracer.entry_address} | tracer.stack_copy_candidates
                  | set(tracer.discovered_crc_loops)
                  | {address for address in tracer.synthetic_import_targets if tracer.in_module(address)})
        self.context, context_address, block_address, write_address = _hook_filter.create(
            tracer.image_start, tracer.image_end,
            [(start, end) for start, end, _ in tracer.packed_destination_ranges],
            sorted(points), sorted(tracer.synthetic_import_targets),
            self.uc, *self.callbacks, ctypes.cast(binding.uclib.uc_emu_stop, ctypes.c_void_p).value,
            int(tracer.diagnostics is not None))
        tracer.block_counter = self.block_count
        self.add_native(UC_HOOK_BLOCK, block_address, context_address, 1, 0)
        self.add_native(UC_HOOK_MEM_WRITE, write_address, context_address,
                        tracer.image_start, tracer.image_end - 1)

    def add_native(self, kind, callback, context, begin, end):


        handle = binding.uc_hook_h()
        status = binding.uclib.uc_hook_add(self.uc._uch, ctypes.byref(handle), kind,
                                           ctypes.c_void_p(callback), ctypes.c_void_p(context),
                                           ctypes.c_uint64(begin), ctypes.c_uint64(end))
        if status:
            raise UcError(status)
        self.uc._callbacks[handle.value] = self
        self.handles.append(handle.value)

    def block_count(self):
        return _hook_filter.block_count(self.context)

    def close(self):
        if self.closed:
            return
        if self.context is not None:
            self.tracer.sync_counts()
            self.tracer.hook_statistics = {'backend': self.backend, **_hook_filter.statistics(self.context)}
        else:
            self.tracer.hook_statistics = {'backend': self.backend}
        for handle in self.handles:
            self.uc.hook_del(handle)
        self.handles.clear()
        self.tracer.block_counter = None
        self.context = None
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
