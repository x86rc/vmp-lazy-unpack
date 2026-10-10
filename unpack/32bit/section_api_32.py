import ctypes
from functools import cached_property

from unicorn import UcError

from ..arch import MODE32
from ..binary import read_u64
from .memory_32 import MemoryStatus, VirtualMemory32
from ..pe import align_up


class SectionHandlers32:
    @cached_property
    def section_memory(self):
        return VirtualMemory32(self.uc)

    def _nt_create_section(self, symbol, output, access, object_attributes, maximum_size):
        attributes = self.stack_slot(5) & 0xFFFFFFFF
        file_handle = self.stack_slot(6)
        protection = self.stack_slot(4) & 0xFFFFFFFF
        details = dict(section_attributes=attributes, file_handle=file_handle,
                       protection=protection, maximum_size_address=hex(maximum_size))
        try:
            size = read_u64(self.uc.mem_read(maximum_size, 8)) if maximum_size else 0
            details['maximum_size'] = size
            if not self.writable_range(output, self.arch.ptr):
                return 0xC0000005, details
            if file_handle:
                handle = self.files.section(file_handle, attributes)
                if handle is None:
                    return 0xC0000008, details
            else:
                if attributes not in (0x08000000, 0x08400000, 0x48000000):
                    return None, details
                if object_attributes:
                    name_offset = 8 if self.arch.bits == 32 else 16
                    if self.read_ptr_mem(object_attributes + name_offset):
                        return None, details
                permissions = self.section_memory.permissions(protection)
                if not permissions:
                    return 0xC0000045, details
                if not size:
                    return 0xC000011E, details
                if size >= 1 << 63:
                    return 0xC000000D, details
                size = align_up(size, 0x1000)
                if size > 512 * 1024 * 1024:
                    return 0xC0000040, details
                backing = ctypes.create_string_buffer(size)
                handle = self.files.handle(dict(kind='section', name='[pagefile]', image=False,
                    backing=backing, size=size, protection=protection, attributes=attributes))
            self.write_ptr_if_mapped(output, handle)
            details['section_handle'] = handle
            return 0, details
        except MemoryStatus as exc:
            return exc.status, details
        except MemoryError:
            return 0xC0000017, details
        except UcError as exc:
            details['memory_error'] = str(exc)
            return 0xC0000005, details

    def _nt_map_view_of_section(self, symbol, handle, process, base_pointer, zero_bits):
        record = self.files.handles.get(handle)
        if record is not None and 'backing' in record:
            return self.map_pagefile_section(handle, record, process, base_pointer, zero_bits)
        if self.read_ptr_mem(base_pointer):
            raise ValueError('invalid address file view')
        offset_pointer = self.stack_slot(5)
        size_pointer = self.stack_slot(6)
        offset = read_u64(self.uc.mem_read(offset_pointer, 8)) if offset_pointer else 0
        size = self.read_ptr_mem(size_pointer) if size_pointer else 0
        view, view_size = self.files.map(handle, offset, size)
        self.write_ptr_if_mapped(base_pointer, view)
        self.write_ptr_if_mapped(size_pointer, view_size)
        details = dict(self.files.views[view])
        if self.diagnostics:
            self.diagnostics.watch_mapping(self.uc, view, view_size, details['name'])
        return 0, details

    def map_pagefile_section(self, handle, record, process, base_pointer, zero_bits):
        details = dict(section_handle=handle)
        try:
            size_pointer = self.stack_slot(6)
            address, size = self.memory_arguments(process, base_pointer, size_pointer)
            offset_pointer = self.stack_slot(5)
            if offset_pointer and not self.writable_range(offset_pointer, 8):
                return 0xC0000005, details
            offset = read_u64(self.uc.mem_read(offset_pointer, 8)) if offset_pointer else 0
            inherit, flags, protection = (self.stack_slot(i) & 0xFFFFFFFF for i in (7, 8, 9))
            details.update(requested_base=address, region_size=size, section_offset=offset,
                           protection=protection, allocation_type=flags)
            if inherit not in (1, 2) or zero_bits > 20:
                return 0xC000000D, details
            if flags & ~0x100000:
                return None, details
            permissions = self.section_memory.permissions(protection)
            if permissions & ~self.section_memory.permissions(record['protection']):
                return 0xC000004E, details
            if address & 0xFFFF or offset & 0xFFFF:
                return 0xC0000220, details
            if offset >= record['size']:
                return 0xC000001F, details
            size = align_up(size, 0x1000) if size else record['size'] - offset
            if offset + size > record['size']:
                return 0xC000001F, details
            if sum(view['size'] for view in self.files.views.values()) + size > 512 * 1024 * 1024:
                return 0xC0000017, details
            limit = min(MODE32.user_top, 1 << (32 - zero_bits))
            if not address:
                address = self.section_memory.free_address(size, limit, bool(flags & 0x100000))
            if address < 0x10000 or address + size > limit or any(
                    address <= end and start < address + size for start, end, _ in self.uc.mem_regions()):
                return 0xC0000018, details
            self.uc.mem_map_ptr(address, size, permissions, ctypes.addressof(record['backing']) + offset)
            protection |= 0x200 if record['attributes'] & 0x400000 else 0
            protection |= 0x400 if record['attributes'] & 0x40000000 else 0
            self.section_memory.allocations[address] = dict(size=size, protection=protection,
                pages=[protection] * (size // 0x1000), kind=0x40000, section=record)
            self.files.views[address] = dict(size=size, name=record['name'], image=False)
            self.write_ptr_if_mapped(base_pointer, address)
            self.write_ptr_if_mapped(size_pointer, size)
            details.update(base_address=address, region_size=size)
            if self.diagnostics:
                self.diagnostics.watch_mapping(self.uc, address, size, record['name'])
            return 0, details
        except MemoryStatus as exc:
            return exc.status, details
        except UcError as exc:
            details['memory_error'] = str(exc)
            return 0xC0000005, details

    def _nt_unmap_view_of_section(self, symbol, process, address, unused1, unused2):
        if process != self.arch.mask:
            return 0xC0000008, {}
        for base, view in self.files.views.items():
            if base <= address < base + view['size']:
                self.uc.mem_unmap(base, view['size'])
                self.section_memory.allocations.pop(base, None)
                del self.files.views[base]
                return 0, {}
        return 0xC0000019, {}
