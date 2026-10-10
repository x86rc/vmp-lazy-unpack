import struct

from unicorn import UcError
import unicorn.x86_const as ux

from ..api_handlers import ApiHandlers, smbios_table
from ..arch import read_ptr, write_ptr
from ..binary import encode_u32, write_u32
from .memory_32 import MemoryHandlers32
from .file_api_32 import FileHandlers32
from .thread_api_32 import ThreadHandlers32
from .process_api_32 import ProcessHandlers32
from .section_api_32 import SectionHandlers32
from ..pe import align_up


class ApiHandlers32(MemoryHandlers32, FileHandlers32, ThreadHandlers32, ProcessHandlers32,
                    SectionHandlers32, ApiHandlers):
    _argument_base = None

    def stack_slot(self, index):
        if self._argument_base is not None:
            address = self._argument_base + index * self.arch.ptr
            return read_ptr(self.arch, self.uc.mem_read(address, self.arch.ptr))
        return super().stack_slot(index)

    def emulate_import(self, label, *, argument_register=ux.UC_X86_REG_RCX,
                       argument_base=None, call_arch=None):
        previous = self.arch, self._argument_base
        self.arch, self._argument_base = call_arch or self.arch, argument_base
        try:
            return super().emulate_import(label,
                argument_register=None if argument_base is not None else argument_register)
        finally:
            self.arch, self._argument_base = previous

    def _nt_set_information_process(self, symbol, rcx, rdx, r8, r9):
        if (rdx & 0xFFFFFFFF) != 40:
            return super()._nt_set_information_process(symbol, rcx, rdx, r8, r9)
        details = dict(handle=rcx, information_class=40, input_address=r8, input_length=r9)
        size = 8 + self.arch.ptr
        if rcx != self.arch.mask:
            return 0xC0000008, details
        if r9 != size:
            return 0xC0000004, details
        try:
            value = bytes(self.uc.mem_read(r8, size))
        except UcError:
            return 0xC0000005, details
        return (0 if value == bytes(size) else None), details

    def _nt_query_system_information(self, symbol, information_class, output, length, returned):
        if (information_class & 0xFFFFFFFF) == 11 and self.arch.bits == 32:
            details = dict(information_class=11, output_length=length & 0xFFFFFFFF)
            if returned and not self.writable_range(returned, 4):
                return 0xC0000005, details
            self.write_u32_if_mapped(returned, 4)
            if (length & 0xFFFFFFFF) < 4:
                return 0xC0000004, details
            if not self.writable_range(output, 4):
                return 0xC0000005, details
            self.uc.mem_write(output, bytes(4))
            return 0, details
        if (information_class & 0xFFFFFFFF) != 5:
            return super()._nt_query_system_information(symbol, information_class, output, length, returned)
        name = self.module_paths[0].replace('\\', '/').rsplit('/', 1)[-1].encode('utf-16-le')
        header_size, thread_size = (0xB8, 0x40) if self.arch.bits == 32 else (0x100, 0x50)
        name_offset = header_size + thread_size
        required = align_up(name_offset + len(name) + 2, 8)
        length &= 0xFFFFFFFF
        details = dict(information_class=5, output_length=length, required_length=required)
        if returned and not self.writable_range(returned, 4):
            return 0xC0000005, details
        if length < required:
            result = 0xC0000004
        elif not self.writable_range(output, required):
            result = 0xC0000005
        else:
            info = bytearray(required)
            write_u32(info, 4, 1)
            struct.pack_into('<HHI' if self.arch.bits == 32 else '<HH4xQ', info, 0x38,
                             len(name), len(name) + 2, output + name_offset)
            priority = 0x40 if self.arch.bits == 32 else 0x48
            process_id = align_up(priority + 4, self.arch.ptr)
            handle_count = process_id + 2 * self.arch.ptr
            write_u32(info, priority, 8)
            write_ptr(self.arch, info, process_id, 0x1337)
            write_u32(info, handle_count, len(self.files.handles))
            virtual_size = sum(end + 1 - start for start, end, _ in self.uc.mem_regions())
            virtual_offset = 0x58 if self.arch.bits == 32 else 0x70
            write_ptr(self.arch, info, virtual_offset, virtual_size)
            write_ptr(self.arch, info, virtual_offset + self.arch.ptr, virtual_size)
            thread_start = header_size + (0x1C if self.arch.bits == 32 else 0x20)
            write_ptr(self.arch, info, thread_start, self.entry_address)
            write_ptr(self.arch, info, thread_start + self.arch.ptr, 0x1337)
            write_ptr(self.arch, info, thread_start + 2 * self.arch.ptr, 0x7331)
            thread_priority = thread_start + 3 * self.arch.ptr
            write_u32(info, thread_priority, 8)
            write_u32(info, thread_priority + 4, 8)
            write_u32(info, thread_priority + 12, 2)
            info[name_offset:name_offset + len(name)] = name
            self.uc.mem_write(output, bytes(info))
            result = 0
        self.write_u32_if_mapped(returned, required)
        return result, details

    def _get_tick_count64(self, symbol, rcx, rdx, r8, r9):
        result, details = super()._get_tick_count64(symbol, rcx, rdx, r8, r9)
        if self.arch.bits == 32:
            self.uc.reg_write(self.arch.dx, result >> 32)
        return result & self.arch.mask, details

    def _nt_query_virtual_memory(self, symbol, rcx, rdx, r8, r9):
        if (r8 & 0xFFFFFFFF) == 2:
            result = self.query_mapped_filename(rcx, rdx, r9, self.stack_slot(4), self.stack_slot(5))
            return result, dict(memory_address=rdx, information_class=2)
        return super()._nt_query_virtual_memory(symbol, rcx, rdx, r8, r9)

    def query_mapped_filename(self, process, address, output, length, returned):
        if process != self.arch.mask:
            return 0xC0000008
        if self.section_memory.allocation(address) is not None:
            return 0xC0000141
        path = None
        for base, view in self.files.views.items():
            if base <= address < base + view['size']:
                path = self.module_paths.get(base, '\\??\\C:\\Windows\\System32\\' + view['name'])
                break
        if path is None:
            if self.in_module(address):
                path = self.module_paths.get(self.image_start)
            else:
                for base in self.module_bases.values():
                    if base <= address < base + self.arch.emu_module_size:
                        path = self.module_paths.get(base)
                        break
        if path is None:
            return 0xC0000141
        if not path.startswith('\\'):
            path = '\\??\\' + path
        encoded = path.encode('utf-16-le')
        header_size = 16 if self.arch.bits == 64 else 8
        required = header_size + len(encoded) + 2
        if returned and not self.writable_range(returned, self.arch.ptr):
            return 0xC0000005
        self.write_ptr_if_mapped(returned, required)
        if length < required:
            return 0xC0000023
        if not self.writable_range(output, required):
            return 0xC0000005
        descriptor = struct.pack('<HH4xQ' if self.arch.bits == 64 else '<HHI',
                                 len(encoded), len(encoded) + 2, output + header_size)
        self.uc.mem_write(output, descriptor + encoded + b'\0\0')
        return 0

    def _close_handle(self, symbol, rcx, rdx, r8, r9):
        status, details = self._nt_close(symbol, rcx, rdx, r8, r9)
        if status:
            self.last_error = 6
        return int(status == 0), details

    def firmware_buffer(self, data, output, capacity):
        required = len(data)
        if capacity < required:
            self.last_error = 122
            return required, {}
        if not self.writable_range(output, required):
            self.last_error = 998
            return 0, {}
        self.uc.mem_write(output, data)
        return required, {}

    def _enum_system_firmware_tables(self, symbol, rcx, rdx, r8, r9):
        if (rcx & 0xFFFFFFFF) == 0x52534D42:
            return self.firmware_buffer(encode_u32(0), rdx, r8 & 0xFFFFFFFF)
        self.last_error = 1 if (rcx & 0xFFFFFFFF) == 0x4649524D else 87
        return 0, {}

    def _get_system_firmware_table(self, symbol, rcx, rdx, r8, r9):
        if (rcx & 0xFFFFFFFF) == 0x52534D42 and (rdx & 0xFFFFFFFF) == 0:
            return self.firmware_buffer(smbios_table(), r8, r9 & 0xFFFFFFFF)
        self.last_error = 1 if (rcx & 0xFFFFFFFF) == 0x4649524D else 87
        return 0, {}

    _handlers = {
        **ApiHandlers._handlers,
        'ntopenthread': (ThreadHandlers32._nt_open_thread, 4),
        'ntqueryinformationthread': (ThreadHandlers32._nt_query_information_thread, 5),
        'ntsetinformationthread': (ThreadHandlers32._nt_set_information_thread, 4),
        'setthreadaffinitymask': (ThreadHandlers32._set_thread_affinity_mask, 2),
        'ntopenfile': (FileHandlers32._nt_open_file, 6),
        'ntcreatefile': (FileHandlers32._nt_create_file, 11),
        'ntreadfile': (FileHandlers32._nt_read_file, 9),
        'ntqueryinformationfile': (FileHandlers32._nt_query_information_file, 5),
        'ntsetinformationfile': (FileHandlers32._nt_set_information_file, 5),
        'ntqueryattributesfile': (FileHandlers32._nt_query_attributes_file, 2),
        'ntallocatevirtualmemory': (MemoryHandlers32._nt_allocate_virtual_memory, 6),
        'ntfreevirtualmemory': (MemoryHandlers32._nt_free_virtual_memory, 4),
        'ntprotectvirtualmemory': (MemoryHandlers32._nt_protect_virtual_memory, 5),
        'virtualalloc': (MemoryHandlers32._virtual_alloc, 4),
        'virtualfree': (MemoryHandlers32._virtual_free, 3),
        'virtualprotect': (MemoryHandlers32._virtual_protect, 4),
        'closehandle': (_close_handle, 1),
        'ntsetinformationprocess': (_nt_set_information_process, 4),
        'ntquerysysteminformation': (_nt_query_system_information, 4),
        'ntqueryinformationprocess': (ProcessHandlers32._nt_query_information_process, 5),
        'gettickcount64': (_get_tick_count64, 0),
        'ntqueryvirtualmemory': (_nt_query_virtual_memory, 6),
        'ntcreatesection': (SectionHandlers32._nt_create_section, 7),
        'ntmapviewofsection': (SectionHandlers32._nt_map_view_of_section, 10),
        'ntunmapviewofsection': (SectionHandlers32._nt_unmap_view_of_section, 2),
        'enumsystemfirmwaretables': (_enum_system_firmware_tables, 3),
        'getsystemfirmwaretable': (_get_system_firmware_table, 4),
    }


def memory_basic_information(handler, page, region, regions):
    if region is None:
        end = min((start for start, _, _ in regions if start > page), default=handler.arch.user_top)
        info = bytearray(28)
        write_u32(info, 0, page)
        write_u32(info, 12, end - page)
        write_u32(info, 16, 0x10000)
        return bytes(info)
    start, end, permissions = region
    allocation = start
    protection = (1, 2, 4, 4, 0x10, 0x20, 0x40, 0x40)[permissions & 7]
    kind = 0x20000
    if handler.arch.emu_heap_base <= page < handler.arch.emu_heap_base + handler.arch.emu_heap_size:
        allocation, protection = handler.arch.emu_heap_base, 4
    elif handler.in_module(page):
        allocation, kind = handler.image_start, 0x1000000
    elif start in handler.module_bases.values() or start == handler.arch.host_image_base:
        kind = 0x1000000
    elif start in handler.files.views:
        kind = 0x1000000 if handler.files.views[start]["image"] else 0x40000
    info = bytearray(28)
    write_u32(info, 0, page)
    write_u32(info, 4, allocation)
    write_u32(info, 8, protection)
    write_u32(info, 12, end + 1 - page)
    write_u32(info, 16, 0x1000)
    write_u32(info, 20, protection)
    write_u32(info, 24, kind)
    return bytes(info)


def process_information_blob(handler, information_class):
    if information_class == 0:
        return struct.pack('<6I', 0x103, handler.arch.peb_base, handler.process_affinity_mask,
                           8, 0x1337, 0)
    if information_class == 21:
        return encode_u32(handler.process_affinity_mask)
    if information_class in (7, 30, 31):
        return int(information_class == 31).to_bytes(4, 'little')
    return None


def thread_information_blob(handler, information_class):
    if information_class == 0:
        return struct.pack('<7I', 0x103, handler.arch.teb_base, 0x1337, 0x7331,
                           handler.thread_affinity_mask, 8, 8)
    if information_class == 17:
        return bytes([handler.thread_hidden_from_debugger])
    return None


def system_basic_information(handler):
    return struct.pack('<10IB3x', 0, 156250, 0x1000, 0x200000,
                       1, 0x200000, 0x10000, 0x10000, 0x7FFEFFFF,
                       handler.system_affinity_mask, handler.system_affinity_mask.bit_count())
