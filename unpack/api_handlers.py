import struct

from unicorn import UC_PROT_WRITE, UcError
import unicorn.x86_const as ux

from .binary import encode_u32, encode_u64, read_u16, read_u32, read_u64, write_u32, write_u64


PAGE_SIZE = 0x1000
HOST_IMAGE_BASE = 0x00007FF900000000
EMU_HEAP_BASE = 0x0000020000000000
EMU_HEAP_SIZE = 0x1000000
TEB_BASE = 0x7FF700000000
PEB_BASE = 0x7FF710000000


def smbios_table():
    system = (struct.pack('<BBH', 1, 27, 0x100) + bytes((1, 2, 3, 4))
              + bytes.fromhex('00112233445566778899aabbccddeeff') + bytes((6, 5, 6))
              + b'Generic\0Desktop\0' + b'1.0\0' + b'00000000\0Standard\0Desktop\0\0')
    structures = system + struct.pack('<BBH', 127, 4, 0xFFFF) + b'\0\0'
    return struct.pack('<BBBBI', 0, 3, 2, 0, len(structures)) + structures


def normalize_module_name(name):
    normalized = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if normalized and "." not in normalized:
        normalized += ".dll"
    return normalized


def split_import_label(label):
    dll, symbol = label.split("!", 1)
    return normalize_module_name(dll), symbol


class ApiHandlers:
    def memory_basic_information(self, address):
        page = address & -PAGE_SIZE
        if page >= 1 << 47:
            return None
        regions = list(self.uc.mem_regions())
        region = next((r for r in regions if r[0] <= page <= r[1]), None)
        if region is None:
            end = min((r[0] for r in regions if r[0] > page), default=1 << 47)
            info = bytearray(48)
            write_u64(info, 0, page)
            write_u64(info, 24, end - page)
            write_u32(info, 32, 0x10000)
            return bytes(info)
        start, end, permissions = region
        allocation = start
        protection = (1, 2, 4, 4, 0x10, 0x20, 0x40, 0x40)[permissions & 7]
        kind = 0x20000
        if EMU_HEAP_BASE <= page < EMU_HEAP_BASE + EMU_HEAP_SIZE:
            allocation, protection = EMU_HEAP_BASE, 4
        elif self.in_module(page):
            allocation, kind = self.image_start, 0x1000000
        elif start in self.module_bases.values() or start == HOST_IMAGE_BASE:
            kind = 0x1000000
        elif start in self.files.views:
            kind = 0x1000000 if self.files.views[start]["image"] else 0x40000
        info = bytearray(48)
        write_u64(info, 0, page)
        write_u64(info, 8, allocation)
        write_u32(info, 16, protection)
        write_u64(info, 24, end + 1 - page)
        write_u32(info, 32, 0x1000)
        write_u32(info, 36, protection)
        write_u32(info, 40, kind)
        return bytes(info)

    def writable_range(self, address, size):
        end = address + size
        for start, last, permissions in sorted(self.uc.mem_regions()):
            if start <= address <= last:
                if not permissions & UC_PROT_WRITE:
                    return False
                address = min(end, last + 1)
                if address == end:
                    return True
        return False

    def query_process_information(self, handle, information_class, output, length):
        information_class &= 0xFFFFFFFF
        length &= 0xFFFFFFFF
        details = dict(handle=handle, information_class=information_class,
                       output_address=hex(output), output_length=length)
        if information_class == 0:
            info = struct.pack('<I4xQQi4xQQ', 0x103, PEB_BASE, self.process_affinity_mask, 8, 0x1337, 0)
        elif information_class == 21:
            info = encode_u64(self.process_affinity_mask)
        elif information_class in (7, 30, 31):
            info = int(information_class == 31).to_bytes(4 if information_class == 31 else 8, 'little')
        else:
            return None, details
        required = len(info)
        if length and output & 3:
            return 0x80000002, details
        try:
            rsp = self.uc.reg_read(ux.UC_X86_REG_RSP)
            returned = read_u64(self.uc.mem_read(rsp + 0x28, 8))
        except UcError as exc:
            details['memory_error'] = str(exc)
            return 0xC0000005, details
        details['return_length_address'] = hex(returned)
        if returned and not self.writable_range(returned, 4):
            details['memory_error'] = 'return length buffer not writable'
            return 0xC0000005, details
        if length != required:
            return 0xC0000004, details
        if handle != 0xFFFFFFFFFFFFFFFF:
            if handle == 0xFFFFFFFFFFFFFFFE or handle in self.files.handles:
                return 0xC0000024, details
            return 0xC0000008, details
        if not self.writable_range(output, required):
            details['memory_error'] = 'process information buffer not writable'
            return 0xC0000005, details
        self.uc.mem_write(output, info)
        self.write_u32_if_mapped(returned, required)
        return (0xC0000353 if information_class == 30 else 0), details

    def set_process_affinity(self, mask):
        if not mask or mask & ~self.system_affinity_mask:
            return 0xC000000D
        self.process_affinity_mask = mask
        self.thread_affinity_mask &= mask
        if not self.thread_affinity_mask:
            self.thread_affinity_mask = mask
        return 0

    def set_thread_affinity(self, mask):
        if not mask or mask & ~self.process_affinity_mask:
            return 0xC000000D
        self.thread_affinity_mask = mask
        return 0

    def query_firmware_information(self, output, length, returned):
        length &= 0xFFFFFFFF
        details = dict(information_class=0x4C, output_length=length)
        if length < 16:
            return 0xC0000004, details
        try:
            provider, action, table, capacity = struct.unpack('<IIII', self.uc.mem_read(output, 16))
        except UcError:
            return 0xC0000005, details
        details.update(provider_signature=hex(provider), firmware_action=action,
                       table_id=hex(table), table_buffer_length=capacity)
        if provider == 0x4649524D and action == 0:
            data = b''
            result = 0xC0000002
            return_length = 0
        elif provider == 0x52534D42:
            if action == 0:
                data = encode_u32(0)
            elif action == 1 and table == 0:
                data = smbios_table()
            else:
                return None, details
            result = 0
            return_length = 16 + len(data)
        else:
            return None, details
        required = len(data)
        if result == 0 and length < 16 + required:
            result = 0xC0000023
        write_size = 16 + required if result == 0 else 16
        if not self.writable_range(output, write_size) or (returned and not self.writable_range(returned, 4)):
            return 0xC0000005, details
        self.uc.mem_write(output + 12, encode_u32(required))
        if result == 0:
            self.uc.mem_write(output + 16, data)
        self.write_u32_if_mapped(returned, return_length)
        return result, details

    def emulate_import(self, label, *, argument_register=ux.UC_X86_REG_RCX):
        _, symbol = split_import_label(label)
        symbol = symbol.lower()
        if symbol.startswith("zw"):
            symbol = "nt" + symbol[2:]
        handler = self._handlers.get(symbol)
        if handler is None:
            return None, {}
        return handler(self, symbol,
                       self.uc.reg_read(argument_register),
                       self.uc.reg_read(ux.UC_X86_REG_RDX),
                       self.uc.reg_read(ux.UC_X86_REG_R8),
                       self.uc.reg_read(ux.UC_X86_REG_R9))

    def _nt_set_information_thread(self, symbol, rcx, rdx, r8, r9):
        information_class = rdx & 0xFFFFFFFF
        if information_class == 4:
            return self._nt_set_thread_affinity(symbol, rcx, rdx, r8, r9)
        if information_class == 17:
            return self._nt_hide_thread(symbol, rcx, rdx, r8, r9)
        return None, {}

    def _get_version(self, symbol, rcx, rdx, r8, r9):
        version = self.catalog.windows
        result = (version["build"] << 16) | (version["minor"] << 8) | version["major"]
        return result, {}

    def _get_version_info(self, symbol, rcx, rdx, r8, r9):
        version = self.catalog.windows
        size = read_u32(self.uc.mem_read(rcx, 4))
        wide = symbol != "getversionexa"
        basic, extended = (276, 284) if wide else (148, 156)
        if size not in (basic, extended):
            result = 0xC000000D if symbol == "rtlgetversion" else 0
        else:
            info = bytearray(size)
            struct.pack_into("<IIIII", info, 0, size, version["major"], version["minor"],
                             version["build"], version["platform_id"])
            if size == extended:
                struct.pack_into("<HHHBB", info, basic, version["service_pack_major"],
                                 version["service_pack_minor"], version["suite_mask"], version["product_type"], 0)
            self.uc.mem_write(rcx, bytes(info))
            result = 0 if symbol == "rtlgetversion" else 1
        return result, {}

    def _module_handle_a(self, symbol, rcx, rdx, r8, r9):
        details = {}
        requested = normalize_module_name(self.read_ascii(rcx))
        result = self.module_bases.get(requested, 0)
        details["requested_module"] = requested
        return result, details

    def _module_handle_w(self, symbol, rcx, rdx, r8, r9):
        details = {}
        requested = normalize_module_name(self.read_utf16(rcx))
        result = self.module_bases.get(requested, 0)
        details["requested_module"] = requested
        return result, details

    def _get_module_filename_w(self, symbol, rcx, rdx, r8, r9):
        details = {}
        path = self.module_paths.get(rcx)
        capacity = r8 & 0xFFFFFFFF
        if not capacity:
            result = 0
        elif path is None:
            self.last_error = 126
            result = 0
        else:
            encoded = path.encode("utf-16-le")
            length = len(encoded) // 2
            self.uc.mem_write(rdx, encoded[:(capacity - 1) * 2] + b"\0\0")
            result = length if length < capacity else capacity
            if length >= capacity:
                self.last_error = 122
            details["module_path"] = path
        return result, details

    def _get_proc_address(self, symbol, rcx, rdx, r8, r9):
        details = {}
        if rdx <= 0xFFFF:
            requested = rdx
        else:
            requested = self.read_ascii(rdx).lower()
        result = self.export_lookup.get((rcx, requested), 0)
        details["requested_export"] = requested
        return result, details

    def _get_process_heap(self, symbol, rcx, rdx, r8, r9):
        return EMU_HEAP_BASE, {}

    def _local_alloc(self, symbol, rcx, rdx, r8, r9):
        details = dict(allocation_size=rdx, allocation_flags=rcx & 0xFFFFFFFF)
        if rcx & 0xFFFFFFFF & ~0xF70:
            return None, details
        try:
            result = self.heap_allocate(rdx)
        except MemoryError:
            self.last_error = 8
            result = 0
        if result:
            self.local_allocations.add(result)
        return result, details

    def _local_free(self, symbol, rcx, rdx, r8, r9):
        if not rcx:
            result = 0
        elif rcx in self.local_allocations:
            self.local_allocations.remove(rcx)
            self.heap_allocations.pop(rcx)
            result = 0
        else:
            self.last_error = 6
            result = rcx
        return result, {}

    def _heap_alloc(self, symbol, rcx, rdx, r8, r9):
        details = {}
        result = self.heap_allocate(r8)
        details["allocation_size"] = r8
        return result, details

    def _heap_realloc(self, symbol, rcx, rdx, r8, r9):
        details = {}
        result = self.heap_allocate(r9)
        details["allocation_size"] = r9
        return result, details

    def _heap_size(self, symbol, rcx, rdx, r8, r9):
        result = self.heap_allocations.get(r8, 0xFFFFFFFFFFFFFFFF)
        return result, {}

    def _return_success(self, symbol, rcx, rdx, r8, r9):
        return 1, {}

    def _virtual_alloc(self, symbol, rcx, rdx, r8, r9):
        details = {}
        result = self.heap_allocate(rdx)
        details["allocation_size"] = rdx
        return result, details

    def _virtual_protect(self, symbol, rcx, rdx, r8, r9):
        self.write_u32_if_mapped(r9, 0x40)
        return 1, {}

    def _nt_protect_virtual_memory(self, symbol, rcx, rdx, r8, r9):
        details = {}
        rsp = self.uc.reg_read(ux.UC_X86_REG_RSP)
        try:
            old_protection = read_u64(self.uc.mem_read(rsp + 0x28, 8))
            self.write_u32_if_mapped(old_protection, 0x20)
        except UcError:
            return 0xC0000005, details
        return 0, details

    def _nt_set_information_process(self, symbol, rcx, rdx, r8, r9):
        details = dict(handle=rcx, information_class=rdx & 0xFFFFFFFF,
                       input_address=r8, input_length=r9 & 0xFFFFFFFF)
        if (rdx & 0xFFFFFFFF) == 21:
            if (r9 & 0xFFFFFFFF) != 8:
                return 0xC0000004, details
            if rcx != 0xFFFFFFFFFFFFFFFF:
                return 0xC0000008, details
            try:
                mask = read_u64(self.uc.mem_read(r8, 8))
            except UcError:
                return 0xC0000005, details
            details['affinity_mask'] = hex(mask)
            return self.set_process_affinity(mask), details
        if rcx != 0xFFFFFFFFFFFFFFFF or (rdx & 0xFFFFFFFF) != 0x28 or (r9 & 0xFFFFFFFF) != 16:
            return None, details
        try:
            if bytes(self.uc.mem_read(r8, 16)) != bytes(16):
                return None, details
        except UcError:
            return None, details
        return 0, details

    def _nt_query_information_process(self, symbol, rcx, rdx, r8, r9):
        return self.query_process_information(rcx, rdx, r8, r9)

    def _nt_query_virtual_memory(self, symbol, rcx, rdx, r8, r9):
        details = dict(memory_address=rdx, information_class=r8 & 0xFFFFFFFF)
        if r8 & 0xFFFFFFFF:
            return None, details
        rsp = self.uc.reg_read(ux.UC_X86_REG_RSP)
        length = read_u64(self.uc.mem_read(rsp + 0x28, 8))
        returned = read_u64(self.uc.mem_read(rsp + 0x30, 8))
        if rcx != 0xFFFFFFFFFFFFFFFF:
            result = 0xC0000008
        elif length < 48:
            result = 0xC0000004
        else:
            info = self.memory_basic_information(rdx)
            if info is None:
                result = 0xC000000D
            else:
                self.uc.mem_write(r9, info)
                self.write_u64_if_mapped(returned, len(info))
                result = 0
        return result, details

    def _nt_set_thread_affinity(self, symbol, rcx, rdx, r8, r9):
        details = dict(handle=rcx, information_class=4, input_address=r8, input_length=r9 & 0xFFFFFFFF)
        if (r9 & 0xFFFFFFFF) != 8:
            return 0xC0000004, details
        if rcx != 0xFFFFFFFFFFFFFFFE:
            return 0xC0000008, details
        try:
            mask = read_u64(self.uc.mem_read(r8, 8))
        except UcError:
            return 0xC0000005, details
        details['affinity_mask'] = hex(mask)
        return self.set_thread_affinity(mask), details

    def _nt_hide_thread(self, symbol, rcx, rdx, r8, r9):
        details = dict(handle=rcx, information_class=17, input_address=r8, input_length=r9)
        if (r9 & 0xFFFFFFFF) != 0:
            result = 0xC0000004
        elif rcx != 0xFFFFFFFFFFFFFFFE:
            result = 0xC0000008
        else:
            self.thread_hidden_from_debugger = True
            result = 0
        return result, details

    def _nt_close(self, symbol, rcx, rdx, r8, r9):
        details = dict(handle=rcx, known_handle=rcx in self.files.handles)
        if details['known_handle']:
            del self.files.handles[rcx]
            result = 0
        else:
            result = 3221225480
        return result, details

    def _return_zero(self, symbol, rcx, rdx, r8, r9):
        return 0, {}

    def _nt_open_file(self, symbol, rcx, rdx, r8, r9):
        details = {}
        if r8:
            object_name = read_u64(self.uc.mem_read(r8 + 16, 8))
            if object_name:
                length = read_u16(self.uc.mem_read(object_name, 2))
                buffer = read_u64(self.uc.mem_read(object_name + 8, 8))
                details["requested_file"] = bytes(self.uc.mem_read(buffer, min(length, 4096))).decode("utf-16-le", errors="replace")
        handle = self.files.open(details.get("requested_file", ""))
        result = 0 if handle is not None else 0xC0000034
        if handle is not None:
            self.write_u64_if_mapped(rcx, handle)
        if r9:
            self.uc.mem_write(r9, struct.pack("<QQ", result, 0))
        return result, details

    def _nt_raise_hard_error(self, symbol, rcx, rdx, r8, r9):
        details = {}
        details["guest_hard_error"] = True
        details["status"] = rcx
        details["unicode_parameters"] = []
        for index in range(min(rdx, 8)):
            if r8 & (1 << index):
                descriptor = read_u64(self.uc.mem_read(r9 + index * 8, 8))
                length = read_u16(self.uc.mem_read(descriptor, 2))
                buffer = read_u64(self.uc.mem_read(descriptor + 8, 8))
                details["unicode_parameters"].append(bytes(self.uc.mem_read(buffer, min(length, 16384))).decode("utf-16-le", errors="replace"))
        return None, details

    def _nt_create_section(self, symbol, rcx, rdx, r8, r9):
        details = {}
        rsp = self.uc.reg_read(ux.UC_X86_REG_RSP)
        attributes = read_u32(self.uc.mem_read(rsp + 0x30, 4))
        file_handle = read_u64(self.uc.mem_read(rsp + 0x38, 8))
        handle = self.files.section(file_handle, attributes)
        result = 0 if handle is not None else 0xC0000008
        if handle is not None:
            self.write_u64_if_mapped(rcx, handle)
        details["section_attributes"] = attributes
        return result, details

    def _nt_map_view_of_section(self, symbol, rcx, rdx, r8, r9):
        details = {}
        rsp = self.uc.reg_read(ux.UC_X86_REG_RSP)
        def qword(address):
            return read_u64(self.uc.mem_read(address, 8))
        if qword(r8):
            raise ValueError("fixed address file views not supported")
        offset_pointer = qword(rsp + 0x30)
        size_pointer = qword(rsp + 0x38)
        view, view_size = self.files.map(rcx, qword(offset_pointer) if offset_pointer else 0,
                                         qword(size_pointer) if size_pointer else 0)
        self.write_u64_if_mapped(r8, view)
        self.write_u64_if_mapped(size_pointer, view_size)
        details["view"] = view
        details.update(self.files.views[view])
        if self.diagnostics:
            self.diagnostics.watch_mapping(self.uc, view, view_size, self.files.views[view]['name'])
        return 0, details

    def _nt_open_section(self, symbol, rcx, rdx, r8, r9):
        return 0xC0000022, {}

    def _nt_query_information_thread(self, symbol, rcx, rdx, r8, r9):
        information_class = rdx & 0xFFFFFFFF
        details = dict(handle=rcx, information_class=information_class,
                       output_address=r8, output_length=r9)

        try:
            rsp = self.uc.reg_read(ux.UC_X86_REG_RSP)
            return_length = read_u64(self.uc.mem_read(rsp + 0x28, 8))
            details["return_length_address"] = return_length
        except UcError as exc:
            details["return_length_address_error"] = str(exc)
            return 0xC0000005, details
        result = 0
        if information_class == 0:
            info = struct.pack('<I4xQQQQii', 0x103, TEB_BASE, 0x1337, 0x7331,
                               self.thread_affinity_mask, 8, 8)
        elif information_class == 17:
            info = bytes([self.thread_hidden_from_debugger])
        else:
            return None, details
        if (r9 & 0xFFFFFFFF) != len(info):
            result = 0xC0000004
        elif rcx != 0xFFFFFFFFFFFFFFFE:
            result = 0xC0000008
        elif not self.writable_range(r8, len(info)) or (return_length and not self.writable_range(return_length, 4)):
            result = 0xC0000005
        else:
            self.uc.mem_write(r8, info)
            self.write_u32_if_mapped(return_length, len(info))
        return result, details

    def _nt_query_system_information(self, symbol, rcx, rdx, r8, r9):
        details = {}
        information_class = rcx & 0xFFFFFFFF
        details.update(information_class=information_class, output_length=r8 & 0xFFFFFFFF)
        if information_class == 0x4C:
            return self.query_firmware_information(rdx, r8, r9)
        elif information_class == 0:
            info = struct.pack('<7I4xQQQB7x', 0, 156250, PAGE_SIZE, 0x200000,
                               1, 0x200000, 0x10000, 0x10000, 0x7FFFFFFEFFFF,
                               self.system_affinity_mask, self.system_affinity_mask.bit_count())
        elif information_class == 0x23:
            info = b"\x00\x01"
        elif information_class == 0x0B:
            info = bytes(8)
        else:
            return None, details
        if r9 and not self.writable_range(r9, 4):
            result = 0xC0000005
        else:
            self.write_u32_if_mapped(r9, len(info))
            if ((r8 & 0xFFFFFFFF) != len(info) if information_class == 0
                    else (r8 & 0xFFFFFFFF) < len(info)):
                result = 0xC0000004
            elif not self.writable_range(rdx, len(info)):
                result = 0xC0000005
            else:
                self.uc.mem_write(rdx, info)
                result = 0
        return result, details

    def _get_current_process(self, symbol, rcx, rdx, r8, r9):
        return 0xFFFFFFFFFFFFFFFF, {}

    def _get_process_affinity_mask(self, symbol, rcx, rdx, r8, r9):
        if rcx != 0xFFFFFFFFFFFFFFFF:
            self.last_error = 6
            result = 0
        elif not rdx or not r8:
            self.last_error = 87
            result = 0
        else:
            self.write_u64_if_mapped(rdx, self.process_affinity_mask)
            self.write_u64_if_mapped(r8, self.system_affinity_mask)
            result = 1
        return result, {}

    def _get_current_thread(self, symbol, rcx, rdx, r8, r9):
        return 0xFFFFFFFFFFFFFFFE, {}

    def _set_affinity_mask(self, symbol, rcx, rdx, r8, r9):
        handle = 0xFFFFFFFFFFFFFFFF if symbol == "setprocessaffinitymask" else 0xFFFFFFFFFFFFFFFE
        if rcx != handle:
            self.last_error = 6
            result = 0
        elif symbol == "setprocessaffinitymask":
            result = int(self.set_process_affinity(rdx) == 0)
            if not result:
                self.last_error = 87
        else:
            previous = self.thread_affinity_mask
            if self.set_thread_affinity(rdx):
                self.last_error = 87
                result = 0
            else:
                result = previous
        return result, {}

    def _get_current_process_id(self, symbol, rcx, rdx, r8, r9):
        return 0x1337, {}

    def _get_current_thread_id(self, symbol, rcx, rdx, r8, r9):
        return 0x7331, {}

    def _query_performance_counter(self, symbol, rcx, rdx, r8, r9):
        self.write_u64_if_mapped(rcx, self.blocks)
        return 1, {}

    def _get_tick_count64(self, symbol, rcx, rdx, r8, r9):
        return 0x12345678, {}

    def _sleep(self, symbol, rcx, rdx, r8, r9):
        details = {}
        details["milliseconds"] = rcx & 0xFFFFFFFF
        if details["milliseconds"]:
            return None, details
        return 0, details

    def _get_system_time_as_file_time(self, symbol, rcx, rdx, r8, r9):
        self.write_u64_if_mapped(rcx, 0x01D9000000000000)
        return 0, {}

    def _set_last_error(self, symbol, rcx, rdx, r8, r9):
        self.last_error = rcx & 0xFFFFFFFF
        return 0, {}

    def _get_last_error(self, symbol, rcx, rdx, r8, r9):
        result = self.last_error
        return result, {}

    _handlers = {
        'getversion': _get_version,
        'rtlgetversion': _get_version_info,
        'getversionexa': _get_version_info,
        'getversionexw': _get_version_info,
        'getmodulehandlea': _module_handle_a,
        'loadlibrarya': _module_handle_a,
        'getmodulehandlew': _module_handle_w,
        'loadlibraryw': _module_handle_w,
        'loadlibraryexw': _module_handle_w,
        'getmodulefilenamew': _get_module_filename_w,
        'getprocaddress': _get_proc_address,
        'getprocessheap': _get_process_heap,
        'localalloc': _local_alloc,
        'localfree': _local_free,
        'heapalloc': _heap_alloc,
        'heaprealloc': _heap_realloc,
        'heapsize': _heap_size,
        'heapfree': _return_success,
        'virtualfree': _return_success,
        'freelibrary': _return_success,
        'closehandle': _return_success,
        'virtualalloc': _virtual_alloc,
        'virtualprotect': _virtual_protect,
        'ntprotectvirtualmemory': _nt_protect_virtual_memory,
        'ntsetinformationprocess': _nt_set_information_process,
        'ntqueryinformationprocess': _nt_query_information_process,
        'ntqueryvirtualmemory': _nt_query_virtual_memory,
        'ntsetinformationthread': _nt_set_information_thread,
        'ntclose': _nt_close,
        'ntdelayexecution': _return_zero,
        'ntopenfile': _nt_open_file,
        'ntraiseharderror': _nt_raise_hard_error,
        'ntcreatesection': _nt_create_section,
        'ntmapviewofsection': _nt_map_view_of_section,
        'ntunmapviewofsection': _return_zero,
        'ntopensection': _nt_open_section,
        'ntqueryinformationthread': _nt_query_information_thread,
        'ntquerysysteminformation': _nt_query_system_information,
        'getcurrentprocess': _get_current_process,
        'getprocessaffinitymask': _get_process_affinity_mask,
        'getcurrentthread': _get_current_thread,
        'setprocessaffinitymask': _set_affinity_mask,
        'setthreadaffinitymask': _set_affinity_mask,
        'getcurrentprocessid': _get_current_process_id,
        'getcurrentthreadid': _get_current_thread_id,
        'disablethreadlibrarycalls': _return_success,
        'freeenvironmentstringsw': _return_success,
        'queryperformancecounter': _query_performance_counter,
        'gettickcount64': _get_tick_count64,
        'sleep': _sleep,
        'getsystemtimeasfiletime': _get_system_time_as_file_time,
        'deletecriticalsection': _return_success,
        'entercriticalsection': _return_success,
        'leavecriticalsection': _return_success,
        'initializecriticalsection': _return_success,
        'initializecriticalsectionandspincount': _return_success,
        'initializecriticalsectionex': _return_success,
        'releasesrwlockexclusive': _return_success,
        'acquiresrwlockexclusive': _return_success,
        'setlasterror': _set_last_error,
        'getlasterror': _get_last_error,
        'isdebuggerpresent': _return_zero,
    }
