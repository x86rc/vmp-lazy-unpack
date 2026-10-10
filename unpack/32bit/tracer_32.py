import struct

import unicorn.x86_const as ux
from unicorn import Uc, UcError, UC_ARCH_X86, UC_PROT_ALL

from .api_handlers_32 import ApiHandlers32
from ..arch import MODE32, MODE64
from ..binary import encode_u16, encode_u32, read_u32, write_u16, write_u32
from .single_step_32 import SingleStep32
from .tls_32 import initialize_tls
from ..tracer import Tracer, register_state
from ..pe import (align_up, memory_image, write_pe_structure, IMAGE_FILE_HEADER,
                 IMAGE_OPTIONAL_HEADER32, IMAGE_SECTION_HEADER)
from ..records import ModuleImage


FAST_CALL = MODE32.return_sentinel + 0x100
FAST_RETURN = MODE32.return_sentinel + 0x110
WOW64_CALL = MODE32.return_sentinel + 0x120
BOOTSTRAP = MODE32.return_sentinel + 0x200


def create_engine(catalog):
    return Uc(UC_ARCH_X86, MODE64.uc_mode if catalog.wow64 else MODE32.uc_mode)


def patch_ntdll_stubs(blob, assignments, stubs_rva, catalog):
    special = {'KiFastSystemCall': b'\x8b\xd4\x0f\x34',
               'KiFastSystemCallRet': b'\xc3', 'Wow64Transition': encode_u32(WOW64_CALL)}
    for symbol, index in assignments.items():
        offset = stubs_rva + index * 16
        code = special.get(symbol)
        if code is None and symbol.startswith(('Nt', 'Zw')) and blob[offset] == 0xB8:
            entry = ApiHandlers32._handlers.get(ApiHandlers32.import_symbol('ntdll.dll!' + symbol))
            if entry is not None:
                call = b'\x64\xff\x15\xc0\0\0\0' if catalog.wow64 else b'\xff\x15\x00\x03\xfe\x7f'
                code = bytes(blob[offset:offset + 5]) + call + b'\xc2' + encode_u16(entry[1] * 4)
        if code is not None:
            blob[offset:offset + len(code)] = code


class Tracer32(ApiHandlers32, Tracer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.wow64 = self.uc._mode == MODE64.uc_mode
        initialize_tls(self, args[4] if len(args) > 4 else kwargs['pe'])

    def make_single_step(self, pe):
        return SingleStep32(self)

    def stop_event(self, event):
        self.single_step.close()
        super().stop_event(event)

    def on_block(self, uc, address, size, user_data):
        label = self.synthetic_import_targets.get(address, '').lower()
        if address in (FAST_CALL, FAST_RETURN, WOW64_CALL) or label in (
                'ntdll.dll!kifastsystemcall', 'ntdll.dll!kifastsystemcallret',
                'ntdll.dll!wow64transition'):
            if self.block_counter is None:
                self.blocks += 1
            else:
                self.sync_counts()
            if address == WOW64_CALL or label == 'ntdll.dll!wow64transition':
                sp = uc.reg_read(MODE32.sp)
                result = self.handle_trap(uc, None, argument_base=sp + 8, convention='wow64')
                if result is not None:
                    uc.reg_write(MODE32.ip, read_u32(uc.mem_read(sp, 4)))
                    uc.reg_write(MODE32.sp, sp + 4)
            elif label == 'ntdll.dll!kifastsystemcall':
                uc.reg_write(MODE32.ip, FAST_CALL)
            elif label == 'ntdll.dll!kifastsystemcallret':
                uc.reg_write(MODE32.ip, FAST_RETURN)
            return
        if self.single_step.active and label == 'ntdll.dll!rtlunwind':
            if self.block_counter is None:
                self.blocks += 1
            else:
                self.sync_counts()
            if self.import_log is not None:
                self.import_log.begin(uc, address, self.synthetic_import_targets[address], self.blocks)
            self.single_step.unwind()
            if self.import_log is not None:
                self.import_log.finish('stopped' if self.stop_reason else 'unwind',
                                       target=hex(uc.reg_read(self.arch.ip)))
            return
        super().on_block(uc, address, size, user_data)

    def on_sysenter_instruction(self, uc, user_data):
        frame = uc.reg_read(MODE32.dx)
        result = self.handle_trap(uc, None, argument_base=frame + 8, convention='sysenter')
        if result is not None:
            uc.reg_write(MODE32.sp, frame)
            uc.reg_write(MODE32.cx, frame)
            uc.reg_write(MODE32.dx, FAST_RETURN)
            uc.reg_write(MODE32.ip, FAST_RETURN - 2)

    def on_interrupt(self, uc, number, user_data):
        if number == 0x2E:
            self.handle_trap(uc, None, uc.reg_read(MODE32.ip) - 2,
                             argument_base=uc.reg_read(MODE32.dx), convention='int2e')
        else:
            self.single_step.interrupt(uc, number, user_data)

    def on_syscall_instruction(self, uc, user_data):
        if self.wow64 and uc.reg_read(ux.UC_X86_REG_CS) == 0x33:
            self.handle_trap(uc, ux.UC_X86_REG_R10, call_arch=MODE64, convention='32bit')
        else:
            self.stop('unsupported_syscall_mode', uc.reg_read(MODE32.ip))

    def handle_trap(self, uc, argument_register, address=None, *, argument_base=None,
                    call_arch=MODE32, convention='sysenter'):
        if address is None:
            address = uc.reg_read(call_arch.ip)
        number = uc.reg_read(call_arch.ax) & 0xFFFFFFFF
        names = self.syscall_catalog.get(number, [])
        result = None
        details = dict(convention=convention, argument_base=argument_base)
        flags = uc.reg_read(ux.UC_X86_REG_EFLAGS)
        if self.diagnostics:
            self.diagnostics.record('syscall_enter', syscall_number=number, syscall_names=names,
                                    blocks=self.blocks, **self.diagnostics.snapshot(uc))
        if names:
            try:
                result, extra = self.emulate_import('ntdll.dll!' + names[0],
                    argument_register=argument_register, argument_base=argument_base, call_arch=call_arch)
                details.update(extra)
            except (UcError, ValueError, OverflowError) as exc:
                details['error'] = str(exc)
        if result is None or result & 0x80000000:
            details['registers'] = register_state(uc, call_arch)
            frame = argument_base if argument_base is not None else uc.reg_read(call_arch.sp)
            try:
                details['argument_bytes'] = bytes(uc.mem_read(frame, 64)).hex()
            except UcError:
                details['argument_bytes'] = None
        self.add_event('syscall', address, syscall_number=number, syscall_names=names,
                       action='model' if result is not None else 'unsupported', result=result, **details)
        if result is None:
            self.stop_event(self.events[-1])
            return None
        uc.reg_write(call_arch.ax, result)
        if call_arch.bits == 64:
            uc.reg_write(ux.UC_X86_REG_RCX, address + 2)
            uc.reg_write(ux.UC_X86_REG_R11, flags)
        if self.diagnostics:
            self.diagnostics.record('syscall_return', syscall_number=number, blocks=self.blocks,
                                    **self.diagnostics.snapshot(uc))
        return result


def write_unicode_string(uc, descriptor, string_address, value):
    encoded = value.encode("utf-16-le")
    uc.mem_write(string_address, encoded + b"\x00\x00")
    uc.mem_write(
        descriptor,
        struct.pack("<HH", len(encoded), len(encoded) + 2) +
        encode_u32(string_address),
    )


def build_process_host():
    data = bytearray(0x400)
    write_u16(data, 0, 0x5A4D)
    write_u32(data, 0x3C, 0x80)
    write_u32(data, 0x80, 0x4550)
    write_pe_structure(data, 0x84, IMAGE_FILE_HEADER,
                       Machine=MODE32.machine, NumberOfSections=1,
                       SizeOfOptionalHeader=MODE32.optional_size, Characteristics=0x22)
    write_pe_structure(data, 0x98, IMAGE_OPTIONAL_HEADER32,
                       Magic=MODE32.magic, ImageBase=MODE32.host_image_base,
                       AddressOfEntryPoint=0x1000, BaseOfCode=0x1000, BaseOfData=0x1000, SizeOfCode=0x200,
                       SectionAlignment=0x1000, FileAlignment=0x200,
                       SizeOfImage=0x2000, SizeOfHeaders=0x200, Subsystem=3,
                       NumberOfRvaAndSizes=16)
    write_pe_structure(data, 0x178, IMAGE_SECTION_HEADER,
                       Name=b".text", Misc_VirtualSize=1, VirtualAddress=0x1000,
                       SizeOfRawData=0x200, PointerToRawData=0x200, Characteristics=0x60000020)
    data[0x200] = 0xCC
    return memory_image(bytes(data))


def map_peb_loader_data(uc, module_bases, process_image):
    uc.mem_map(MODE32.peb_ldr_base, MODE32.peb_ldr_size, UC_PROT_ALL)
    uc.mem_write(MODE32.peb_ldr_base, b"\x00" * MODE32.peb_ldr_size)
    uc.mem_write(MODE32.peb_ldr_base + 0x00, encode_u32(0x28))
    uc.mem_write(MODE32.peb_ldr_base + 0x04, encode_u32(1))

    modules = [process_image]
    for name, base in sorted(module_bases.items(), key=lambda item: item[1]):
        modules.append(ModuleImage(name, base, MODE32.emu_module_size, 0, f"C:\\Windows\\System32\\{name}"))

    entries = [MODE32.peb_ldr_base + 0x100 + index * 0x100 for index in range(len(modules))]
    string_cursor = MODE32.peb_ldr_base + 0x8000
    list_offsets = (0x00, 0x08, 0x10)
    head_offsets = (0x0C, 0x14, 0x1C)
    for link_offset, head_offset in zip(list_offsets, head_offsets):
        head = MODE32.peb_ldr_base + head_offset
        first = entries[0] + link_offset
        last = entries[-1] + link_offset
        uc.mem_write(head, struct.pack("<II", first, last))
        for index, entry in enumerate(entries):
            current = entry + link_offset
            previous_link = head if index == 0 else entries[index - 1] + link_offset
            next_link = head if index + 1 == len(entries) else entries[index + 1] + link_offset
            uc.mem_write(current, struct.pack("<II", next_link, previous_link))

    for entry, module in zip(entries, modules):
        name, base, image_size, entry_point, full_name = module
        uc.mem_write(entry + 0x18, encode_u32(base))
        uc.mem_write(entry + 0x1C, encode_u32(entry_point))
        uc.mem_write(entry + 0x20, encode_u32(image_size))
        full_address = string_cursor
        string_cursor += align_up(len(full_name.encode("utf-16-le")) + 2, 4)
        base_address = string_cursor
        string_cursor += align_up(len(name.encode("utf-16-le")) + 2, 4)
        if string_cursor > MODE32.peb_ldr_base + MODE32.peb_ldr_size:
            raise MemoryError("loader strings exceed mapped memory")
        write_unicode_string(uc, entry + 0x24, full_address, full_name)
        write_unicode_string(uc, entry + 0x2C, base_address, name)
    return entries


def map_synthetic_process_state(uc, module_bases, process_image, version, kuser_shared_data_base, page_size, wow64=False):
    windows_build = version["build"]
    uc.mem_map(MODE32.stack_base, MODE32.stack_size, UC_PROT_ALL)
    uc.mem_map(kuser_shared_data_base, page_size, UC_PROT_ALL)
    uc.mem_write(kuser_shared_data_base + 0x260, encode_u32(windows_build))
    uc.mem_write(kuser_shared_data_base + 0x26C, encode_u32(version["major"]))
    uc.mem_write(kuser_shared_data_base + 0x270, encode_u32(version["minor"]))
    if process_image is None:
        host_blob = build_process_host()
        uc.mem_map(MODE32.host_image_base, len(host_blob), UC_PROT_ALL)
        uc.mem_write(MODE32.host_image_base, host_blob)
        process_image = ModuleImage("host.exe", MODE32.host_image_base, len(host_blob),
                                    MODE32.return_sentinel, "C:\\host.exe")
    uc.mem_map(MODE32.return_sentinel, page_size, UC_PROT_ALL)
    uc.mem_write(MODE32.return_sentinel, b"\xcc")
    uc.mem_write(FAST_CALL, b'\x8b\xd4\x0f\x34')
    uc.mem_write(FAST_RETURN, b'\xc3')
    uc.mem_write(WOW64_CALL, b'\xcc')
    uc.mem_write(kuser_shared_data_base + 0x300, encode_u32(FAST_CALL))
    uc.mem_write(kuser_shared_data_base + 0x304, encode_u32(FAST_RETURN))
    uc.mem_map(MODE32.emu_heap_base, MODE32.emu_heap_size, UC_PROT_ALL)

    uc.mem_map(MODE32.teb_base, page_size, UC_PROT_ALL)
    uc.mem_map(MODE32.peb_base, page_size, UC_PROT_ALL)
    gdt = MODE32.teb_base + 0x800
    uc.mem_write(gdt + 0x10, struct.pack('<HHBBBB', 0xFFFF, 0, 0, 0x93, 0xCF, 0))
    uc.mem_write(gdt + 0x20, struct.pack('<HHBBBB', 0xFFFF, 0, 0, 0xFB, 0xCF, 0))
    uc.mem_write(gdt + 0x28, struct.pack('<HHBBBB', 0xFFFF, 0, 0, 0xF3, 0xCF, 0))
    uc.mem_write(gdt + 0x30, struct.pack('<HHBBBB', 0xFFFF, 0, 0, 0xFB, 0xAF, 0))
    uc.mem_write(gdt + 0x50, struct.pack("<HHBBBB", 0xFFFF, MODE32.teb_base & 0xFFFF,
                                      (MODE32.teb_base >> 16) & 0xFF, 0xF3, 0xCF,
                                      (MODE32.teb_base >> 24) & 0xFF))
    uc.reg_write(ux.UC_X86_REG_GDTR, (0, gdt, 0x100, 0))
    esp = MODE32.stack_base + MODE32.stack_size - 0x1008
    code = (b'\x6a\x2b\x68' + encode_u32(esp) + b'\x68\x02\x02\x00\x00\x6a\x23\x68' +
            encode_u32(BOOTSTRAP + 0x40) + (b'\x48\xcf' if wow64 else b'\xcf'))
    uc.mem_write(BOOTSTRAP, code)
    if wow64:
        uc.reg_write(ux.UC_X86_REG_RSP, esp)
    else:
        uc.reg_write(ux.UC_X86_REG_SS, 0x10)
        uc.reg_write(MODE32.sp, esp)
    uc.emu_start(BOOTSTRAP, BOOTSTRAP + 0x40, count=6)
    uc.reg_write(ux.UC_X86_REG_DS, 0x2B)
    uc.reg_write(ux.UC_X86_REG_ES, 0x2B)
    uc.reg_write(ux.UC_X86_REG_FS, 0x53)
    uc.mem_write(MODE32.teb_base, encode_u32(0xFFFFFFFF))
    if wow64:
        uc.mem_write(MODE32.teb_base + 0xC0, encode_u32(WOW64_CALL))
    stack_base = MODE32.stack_base + MODE32.stack_size
    stack_limit = MODE32.stack_base
    uc.mem_write(MODE32.teb_base + 0x04, encode_u32(stack_base))
    uc.mem_write(MODE32.teb_base + 0x08, encode_u32(stack_limit))
    uc.mem_write(MODE32.teb_base + 0x18, encode_u32(MODE32.teb_base))
    uc.mem_write(MODE32.teb_base + 0x20, encode_u32(0x1337))
    uc.mem_write(MODE32.teb_base + 0x24, encode_u32(0x7331))
    uc.mem_write(MODE32.teb_base + 0x30, encode_u32(MODE32.peb_base))
    uc.mem_write(MODE32.peb_base + 0x08, encode_u32(process_image.base))
    map_peb_loader_data(uc, module_bases, process_image)
    uc.mem_write(MODE32.peb_base + 0x0C, encode_u32(MODE32.peb_ldr_base))
    uc.mem_write(MODE32.peb_base + 0x18, encode_u32(MODE32.emu_heap_base))
    uc.mem_write(MODE32.peb_base + 0xA4, encode_u32(version["major"]))
    uc.mem_write(MODE32.peb_base + 0xA8, encode_u32(version["minor"]))
    uc.mem_write(MODE32.peb_base + 0xAC, encode_u16(windows_build & 0xFFFF))
    uc.mem_write(MODE32.peb_base + 0xB0, encode_u32(version["platform_id"]))
    uc.mem_write(kuser_shared_data_base + 0x264, encode_u32(version["product_type"]))
    uc.mem_write(kuser_shared_data_base + 0x268, b"\x01")
    uc.mem_write(esp, encode_u32(MODE32.return_sentinel))
    return esp
