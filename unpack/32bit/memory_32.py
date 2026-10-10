import struct
from functools import cached_property

from unicorn import UcError

from ..arch import MODE32
from ..pe import align_up


PAGE = 0x1000
PERMISSIONS = {1: 0, 2: 1, 4: 3, 0x10: 4, 0x20: 5, 0x40: 7}


class MemoryStatus(Exception):
    def __init__(self, status):
        self.status = status


class VirtualMemory32:
    def __init__(self, uc):
        self.uc = uc
        self.allocations = {}

    @staticmethod
    def permissions(protection):
        if protection & ~0x6FF or protection & 0x100 or protection & 0xFF not in PERMISSIONS:
            raise MemoryStatus(0xC0000045)
        return PERMISSIONS[protection & 0xFF]

    def allocation(self, address):
        for base, item in self.allocations.items():
            if base <= address < base + item['size']:
                return base, item
        return None

    def free_address(self, size, limit, top_down):
        gaps = []
        cursor = 0x10000
        for start, end, _ in sorted(self.uc.mem_regions()):
            if cursor < min(start, limit):
                gaps.append((cursor, min(start, limit)))
            cursor = max(cursor, end + 1)
        if cursor < limit:
            gaps.append((cursor, limit))
        for start, end in reversed(gaps) if top_down else gaps:
            base = (end - size) & -0x10000 if top_down else align_up(start, 0x10000)
            if start <= base and base + size <= end:
                return base
        raise MemoryStatus(0xC0000017)

    def allocate(self, address, size, zero_bits, flags, protection):
        permissions = self.permissions(protection)
        if not size or flags & ~0x103000 or not flags & 0x3000 or zero_bits > 31:
            raise MemoryStatus(0xC000000D)
        limit = min(MODE32.user_top, 1 << (32 - zero_bits))
        existing = self.allocation(address) if address else None
        if existing and not flags & 0x2000:
            base, item = existing
            start, end = address & -PAGE, align_up(address + size, PAGE)
            if end > base + item['size']:
                raise MemoryStatus(0xC0000018)
            for page in range(start, end, PAGE):
                index = (page - base) // PAGE
                if not item['pages'][index]:
                    self.uc.mem_protect(page, PAGE, permissions)
                    item['pages'][index] = protection
            return start, end - start
        if address and not flags & 0x2000:
            raise MemoryStatus(0xC0000018)
        size = align_up(size + (address & 0xFFFF), PAGE)
        if address:
            base = address & -0x10000
            if base < 0x10000 or base + size > limit:
                raise MemoryStatus(0xC0000017)
            if any(base <= end and start < base + size for start, end, _ in self.uc.mem_regions()):
                raise MemoryStatus(0xC0000018)
        else:
            base = self.free_address(size, limit, bool(flags & 0x100000))
        committed = bool(flags & 0x1000)
        self.uc.mem_map(base, size, permissions if committed else 0)
        self.allocations[base] = dict(size=size, protection=protection,
                                     pages=[protection if committed else 0] * (size // PAGE))
        return base, size

    def free(self, address, size, flags):
        existing = self.allocation(address)
        if existing is None:
            raise MemoryStatus(0xC00000A0)
        base, item = existing
        if flags == 0x8000:
            if size or address != base:
                raise MemoryStatus(0xC000000D)
            self.uc.mem_unmap(base, item['size'])
            del self.allocations[base]
            return base, item['size']
        if flags != 0x4000 or (not size and address != base):
            raise MemoryStatus(0xC000000D)
        start = address & -PAGE
        end = align_up(address + size, PAGE) if size else base + item['size']
        if end > base + item['size']:
            raise MemoryStatus(0xC0000018)
        self.uc.mem_protect(start, end - start, 0)
        for page in range(start, end, PAGE):
            self.uc.mem_write(page, bytes(PAGE))
            item['pages'][(page - base) // PAGE] = 0
        return start, end - start

    def protect(self, address, size, protection):
        permissions = self.permissions(protection)
        existing = self.allocation(address)
        if existing is None or not size:
            raise MemoryStatus(0xC000000D)
        base, item = existing
        if 'section' in item:
            if permissions & ~self.permissions(item['section']['protection']):
                raise MemoryStatus(0xC0000045)
            protection |= item['protection'] & 0x600
        start, end = address & -PAGE, align_up(address + size, PAGE)
        if end > base + item['size']:
            raise MemoryStatus(0xC0000018)
        first, last = (start - base) // PAGE, (end - base) // PAGE
        if not all(item['pages'][first:last]):
            raise MemoryStatus(0xC000002D)
        old = item['pages'][first]
        self.uc.mem_protect(start, end - start, permissions)
        item['pages'][first:last] = [protection] * (last - first)
        return start, end - start, old

    def query(self, address):
        existing = self.allocation(address)
        if existing is None:
            return None
        base, item = existing
        start = address & -PAGE
        first = (start - base) // PAGE
        protection = item['pages'][first]
        last = first + 1
        while last < len(item['pages']) and item['pages'][last] == protection:
            last += 1
        return (start, base, item['protection'], (last - first) * PAGE,
                0x1000 if protection else 0x2000, protection, item.get('kind', 0x20000))


class MemoryHandlers32:
    @cached_property
    def virtual_memory(self):
        return VirtualMemory32(self.uc)

    def memory_manager(self, address):
        if self.section_memory.allocation(address) is not None:
            return self.section_memory
        return self.virtual_memory

    def memory_basic_information(self, address):
        if address >= MODE32.user_top:
            return None
        info = self.memory_manager(address).query(address)
        if info is None:
            return super().memory_basic_information(address)
        if self.arch.bits == 32:
            return struct.pack('<7I', *info)
        base, allocation, allocation_protect, size, state, protect, kind = info
        return struct.pack('<QQIIQIIII', base, allocation, allocation_protect, 0, size, state, protect, kind, 0)

    def memory_arguments(self, process, base, size):
        if process != self.arch.mask:
            raise MemoryStatus(0xC0000008)
        if not all(self.writable_range(p, self.arch.ptr) for p in (base, size)):
            raise MemoryStatus(0xC0000005)
        return self.read_ptr_mem(base), self.read_ptr_mem(size)

    def _nt_allocate_virtual_memory(self, symbol, process, base, zero_bits, size):
        details = {}
        try:
            address, length = self.memory_arguments(process, base, size)
            flags, protection = self.stack_slot(4) & 0xFFFFFFFF, self.stack_slot(5) & 0xFFFFFFFF
            details.update(requested_base=address, region_size=length, allocation_type=flags, protection=protection)
            address, length = self.virtual_memory.allocate(address, length, zero_bits, flags, protection)
            self.write_ptr_if_mapped(base, address)
            self.write_ptr_if_mapped(size, length)
            details.update(base_address=address, region_size=length)
            return 0, details
        except MemoryStatus as exc:
            return exc.status, details
        except UcError:
            return 0xC0000005, details

    def _nt_free_virtual_memory(self, symbol, process, base, size, flags):
        try:
            address, length = self.memory_arguments(process, base, size)
            address, length = self.virtual_memory.free(address, length, flags & 0xFFFFFFFF)
            self.write_ptr_if_mapped(base, address)
            self.write_ptr_if_mapped(size, length)
            return 0, {}
        except MemoryStatus as exc:
            return exc.status, {}
        except UcError:
            return 0xC0000005, {}

    def _nt_protect_virtual_memory(self, symbol, process, base, size, protection):
        try:
            address, length = self.memory_arguments(process, base, size)
            memory = self.memory_manager(address)
            if memory.allocation(address) is None:
                return super()._nt_protect_virtual_memory(symbol, process, base, size, protection)
            old_pointer = self.stack_slot(4)
            if not self.writable_range(old_pointer, 4):
                return 0xC0000005, {}
            address, length, old = memory.protect(address, length, protection & 0xFFFFFFFF)
            self.write_u32_if_mapped(old_pointer, old)
            self.write_ptr_if_mapped(base, address)
            self.write_ptr_if_mapped(size, length)
            return 0, {}
        except MemoryStatus as exc:
            return exc.status, {}
        except UcError:
            return 0xC0000005, {}

    def memory_error(self, status):
        self.last_error = {0xC0000017: 8, 0xC0000018: 487, 0xC00000A0: 487,
                           0xC000002D: 487, 0xC0000005: 998}.get(status, 87)
        return 0, {}

    def _virtual_alloc(self, symbol, address, size, flags, protection):
        try:
            address, size = self.virtual_memory.allocate(address, size, 0, flags & 0xFFFFFFFF, protection & 0xFFFFFFFF)
            return address, dict(allocation_size=size)
        except MemoryStatus as exc:
            return self.memory_error(exc.status)

    def _virtual_free(self, symbol, address, size, flags, unused):
        try:
            self.virtual_memory.free(address, size, flags & 0xFFFFFFFF)
            return 1, {}
        except MemoryStatus as exc:
            return self.memory_error(exc.status)

    def _virtual_protect(self, symbol, address, size, protection, old_pointer):
        memory = self.memory_manager(address)
        if memory.allocation(address) is None:
            return super()._virtual_protect(symbol, address, size, protection, old_pointer)
        if not self.writable_range(old_pointer, 4):
            return self.memory_error(0xC0000005)
        try:
            _, _, old = memory.protect(address, size, protection & 0xFFFFFFFF)
            self.write_u32_if_mapped(old_pointer, old)
            return 1, {}
        except MemoryStatus as exc:
            return self.memory_error(exc.status)
