import argparse
import hashlib
import json
import struct
import time
from collections import Counter, deque
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path

import pefile
from .binary import (
    encode_u16, encode_u32, encode_u64,
    read_u16, read_u32, read_u64,
    write_u16, write_u32, write_u64,
)
from .catalog import Catalog, find_or_capture_catalog
from .dump import dump_pe
from .reconstruct import reconstruct_imports
from .loader_crc import discover_crc_loops, accelerate_crc
from .file_model import FileModel
from .encoded_imports import recover_encoded_imports
from .discover import recover_keys
from .progress import watch_run, log_line
from .diagnostics import Diagnostics
from .hooks import TraceHooks
from .import_calls import ImportCallLog
from .imports import import_address_metadata
from .single_step import SingleStep
from .records import ModuleImage, ImportWrite, Event, format_report
from .pe import (write_pe_structure, memory_image, IMAGE_FILE_HEADER, IMAGE_EXPORT_DIRECTORY,
                 IMAGE_DATA_DIRECTORY, IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER)

ACTIVE_CATALOG = None


def require_catalog():
    if ACTIVE_CATALOG is None:
        raise ValueError("DLL catalog not initialized")
    return ACTIVE_CATALOG

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_BLOCK,
    UC_HOOK_INSN,
    UC_HOOK_MEM_INVALID,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_MODE_64,
    UC_PROT_ALL,
    Uc,
    UcError,
)
import unicorn.x86_const as ux


PAGE_SIZE = 0x1000
STACK_BASE = 0x60000000
STACK_SIZE = 0x200000
RETURN_SENTINEL = 0x00007FF900001000
HOST_IMAGE_BASE = 0x00007FF900000000
EMU_MODULE_BASE = 0x00007FFA00000000
EMU_MODULE_STRIDE = 0x200000
EMU_MODULE_SIZE = 0x80000
EMU_HEAP_BASE = 0x0000020000000000
EMU_HEAP_SIZE = 0x1000000
EMU_FILE_VIEW_BASE = 0x0000030000000000
TEB_BASE = 0x7FF700000000
PEB_BASE = 0x7FF710000000
PEB_LDR_BASE = 0x7FF720000000
PEB_LDR_SIZE = 0x10000
KUSER_SHARED_DATA_BASE = 0x7FFE0000

EXTRA_EMU_EXPORTS = {
    "ntdll.dll": {
        "NtClose",
        "NtAllocateVirtualMemory",
        "NtCreateSection",
        "NtDelayExecution",
        "NtFreeVirtualMemory",
        "NtMapViewOfSection",
        "NtOpenFile",
        "NtOpenSection",
        "NtProtectVirtualMemory",
        "NtQueryInformationProcess",
        "NtQueryInformationThread",
        "NtQuerySystemInformation",
        "NtQueryVirtualMemory",
        "NtRaiseHardError",
        "NtSetInformationProcess",
        "NtSetInformationThread",
        "NtUnmapViewOfSection",
    },
    "kernel32.dll": {
        "GetCurrentThread",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "GetProcAddress",
        "LoadLibraryA",
        "LoadLibraryExW",
        "LoadLibraryW",
    },
}

SYSTEM_EXPORT_MODULES = (
    "kernel32.dll",
    "kernelbase.dll",
    "ntdll.dll",
    "user32.dll",
)

GPR_REGS = (
    ("rax", ux.UC_X86_REG_RAX),
    ("rbx", ux.UC_X86_REG_RBX),
    ("rcx", ux.UC_X86_REG_RCX),
    ("rdx", ux.UC_X86_REG_RDX),
    ("rsi", ux.UC_X86_REG_RSI),
    ("rdi", ux.UC_X86_REG_RDI),
    ("rbp", ux.UC_X86_REG_RBP),
    ("rsp", ux.UC_X86_REG_RSP),
    ("r8", ux.UC_X86_REG_R8),
    ("r9", ux.UC_X86_REG_R9),
    ("r10", ux.UC_X86_REG_R10),
    ("r11", ux.UC_X86_REG_R11),
    ("r12", ux.UC_X86_REG_R12),
    ("r13", ux.UC_X86_REG_R13),
    ("r14", ux.UC_X86_REG_R14),
    ("r15", ux.UC_X86_REG_R15),
    ("rip", ux.UC_X86_REG_RIP),
)


def align_up(value, alignment=PAGE_SIZE):
    return (value + alignment - 1) & ~(alignment - 1)


def register_state(uc):
    state = {name: uc.reg_read(reg) for name, reg in GPR_REGS}
    state["rflags"] = uc.reg_read(ux.UC_X86_REG_EFLAGS)
    return state


def collect_imports(pe):
    slots = {}
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace")
        for imported in descriptor.imports:
            if not imported.import_by_ordinal:
                symbol = imported.name.decode("ascii", errors="replace")
            else:
                symbol = f"ordinal_{imported.ordinal}"
            label = f"{dll}!{symbol}"
            slot = imported.address
            slots[slot] = label
    return slots


def normalize_module_name(name):
    normalized = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if normalized and "." not in normalized:
        normalized += ".dll"
    return normalized


def split_import_label(label):
    dll, symbol = label.split("!", 1)
    return normalize_module_name(dll), symbol


def load_system_export_catalog(module_name):
    result = set()
    for record in require_catalog().exports(module_name):
        result.add(f"ordinal_{record['ordinal']}")
        if record["name"]:
            result.add(record["name"])
    return result


def load_system_syscall_catalog():
    return require_catalog().syscall_catalog()


def build_emu_module_blob(module_name, symbols, module_base):
    named = sorted(
        symbol for symbol in symbols if not symbol.lower().startswith("ordinal_")
    )
    records = require_catalog().exports(module_name)
    by_name = {record["name"]: record["ordinal"] for record in records if record["name"]}
    ordinals = {record["ordinal"] for record in records}
    assignments = {}
    for symbol in sorted(symbols):
        ordinal = int(symbol.split("_", 1)[1], 0) if symbol.startswith("ordinal_") else by_name.get(symbol)
        if ordinal not in ordinals or ordinal < 1:
            raise ValueError(f"export not in captured catalog: {module_name}!{symbol}")
        assignments[symbol] = ordinal - 1
    used_indexes = set(assignments.values())
    function_count = max(used_indexes, default=0) + 1
    export_rva = 0x1000
    functions_rva = 0x1100
    names_rva = align_up(functions_rva + function_count * 4, 4)
    ordinals_rva = align_up(names_rva + len(named) * 4, 4)
    strings_rva = align_up(ordinals_rva + len(named) * 2, 4)
    stubs_rva = 0x40000

    string_size = len(module_name.encode("ascii")) + 1 + sum(len(name.encode("ascii")) + 1 for name in named)
    if strings_rva + string_size > stubs_rva or stubs_rva + function_count * 16 > EMU_MODULE_SIZE:
        raise ValueError(f"captured export table exceeds synthetic module capacity: {module_name}")

    blob = bytearray(EMU_MODULE_SIZE)
    write_u16(blob, 0x00, 0x5A4D)
    write_u32(blob, 0x3C, 0x80)
    write_u32(blob, 0x80, 0x00004550)
    write_pe_structure(blob, 0x84, IMAGE_FILE_HEADER,
                       Machine=0x8664, SizeOfOptionalHeader=0xF0, Characteristics=0x2022)
    optional = 0x98
    write_u16(blob, optional, 0x20B)
    write_u64(blob, optional + 0x18, module_base)
    write_u32(blob, optional + 0x38, EMU_MODULE_SIZE)
    write_u32(blob, optional + 0x3C, 0x400)
    write_u32(blob, optional + 0x6C, 16)
    write_pe_structure(blob, optional + 0x70, IMAGE_DATA_DIRECTORY,
                       VirtualAddress=export_rva, Size=0x8000)

    cursor = strings_rva
    module_name_bytes = module_name.encode("ascii") + b"\x00"
    module_name_rva = cursor
    blob[cursor:cursor + len(module_name_bytes)] = module_name_bytes
    cursor += len(module_name_bytes)

    for index in used_indexes:
        write_u32(blob, functions_rva + index * 4, stubs_rva + index * 0x10)
        blob[stubs_rva + index * 0x10:stubs_rva + index * 0x10 + 3] = b"\x31\xC0\xC3"

    for name_index, symbol in enumerate(named):
        encoded = symbol.encode("ascii") + b"\x00"
        symbol_rva = cursor
        blob[cursor:cursor + len(encoded)] = encoded
        cursor += len(encoded)
        write_u32(blob, names_rva + name_index * 4, symbol_rva)
        write_u16(blob, ordinals_rva + name_index * 2, assignments[symbol])

    if module_name == "ntdll.dll":
        for symbol, function_index in assignments.items():
            if not symbol.lower().startswith(("nt", "zw")):
                continue
            stub = stubs_rva + function_index * 0x10
            matches = [record["syscall"] for record in require_catalog().exports("ntdll.dll")
                       if record["name"] == symbol and "syscall" in record]
            if not matches:
                continue
            syscall_number = matches[0]
            blob[stub:stub + 11] = (
                b"\x4C\x8B\xD1\xB8" + encode_u32(syscall_number) +
                b"\x0F\x05\xC3"
            )

    write_pe_structure(blob, export_rva, IMAGE_EXPORT_DIRECTORY,
                       Name=module_name_rva,
                       Base=1,
                       NumberOfFunctions=function_count,
                       NumberOfNames=len(named),
                       AddressOfFunctions=functions_rva,
                       AddressOfNames=names_rva,
                       AddressOfNameOrdinals=ordinals_rva)
    return bytes(blob), assignments, stubs_rva


def map_emu_windows_modules(uc, import_slots):
    catalog = {}
    for label in import_slots.values():
        module_name, symbol = split_import_label(label)
        catalog.setdefault(module_name, set()).add(symbol)
    for module_name, symbols in EXTRA_EMU_EXPORTS.items():
        catalog.setdefault(module_name, set()).update(symbols)
    ntdll_symbols = catalog.setdefault("ntdll.dll", set())
    ntdll_symbols.update(
        "Zw" + symbol[2:]
        for symbol in tuple(ntdll_symbols)
        if symbol.startswith("Nt")
    )
    for module_name in set(SYSTEM_EXPORT_MODULES) | set(catalog):
        catalog.setdefault(module_name, set()).update(
            load_system_export_catalog(module_name)
        )

    module_bases = {}
    target_labels = {}
    symbol_targets = {}
    export_lookup = {}
    for module_index, module_name in enumerate(sorted(catalog)):
        module_base = EMU_MODULE_BASE + module_index * EMU_MODULE_STRIDE
        blob, assignments, stubs_rva = build_emu_module_blob(
            module_name, catalog[module_name], module_base
        )
        uc.mem_map(module_base, EMU_MODULE_SIZE, UC_PROT_ALL)
        uc.mem_write(module_base, blob)
        module_bases[module_name] = module_base
        for symbol, function_index in assignments.items():
            target = module_base + stubs_rva + function_index * 0x10
            label = f"{module_name}!{symbol}"
            if target not in target_labels or not symbol.startswith("ordinal_"):
                target_labels[target] = label
            symbol_targets[(module_name, symbol.lower())] = target
            if symbol.lower().startswith("ordinal_"):
                ordinal = int(symbol.split("_", 1)[1], 0)
                export_lookup[(module_base, ordinal)] = target
            else:
                export_lookup[(module_base, symbol.lower())] = target

    for slot, label in import_slots.items():
        module_name, symbol = split_import_label(label)
        target = symbol_targets[(module_name, symbol.lower())]
        uc.mem_write(slot, encode_u64(target))
    return module_bases, target_labels, export_lookup


def raw_syscall_candidates(pe):
    candidates = []
    image_base = pe.OPTIONAL_HEADER.ImageBase
    execute_flag = pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
    for section in pe.sections:
        if not section.Characteristics & execute_flag:
            continue
        data = section.get_data()
        offset = 0
        while True:
            offset = data.find(b"\x0f\x05", offset)
            if offset < 0:
                break
            candidates.append(image_base + section.VirtualAddress + offset)
            offset += 2
    return candidates


def map_pe(uc, pe):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    image_size = align_up(pe.OPTIONAL_HEADER.SizeOfImage)
    uc.mem_map(image_base, image_size, UC_PROT_ALL)

    header_size = min(pe.OPTIONAL_HEADER.SizeOfHeaders, len(pe.__data__))
    uc.mem_write(image_base, pe.__data__[:header_size])
    for section in pe.sections:
        data = section.get_data()
        if not data:
            continue
        destination = image_base + section.VirtualAddress
        maximum = image_size - section.VirtualAddress
        if maximum <= 0:
            continue
        uc.mem_write(destination, data[:maximum])
    return image_base, image_base + image_size


def pe_memory_image(pe):
    image = bytearray(align_up(pe.OPTIONAL_HEADER.SizeOfImage))
    header_size = min(pe.OPTIONAL_HEADER.SizeOfHeaders, len(pe.__data__))
    image[:header_size] = pe.__data__[:header_size]
    for section in pe.sections:
        data = section.get_data()
        start = section.VirtualAddress
        end = min(len(image), start + len(data))
        if start < len(image):
            image[start:end] = data[:end - start]
    return bytes(image)


def summarize_mapped_sections(uc, pe):
    summaries = []
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        size = section.Misc_VirtualSize
        data = bytes(uc.mem_read(image_base + section.VirtualAddress, size))
        summaries.append({
            "name": section.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
            "rva": section.VirtualAddress,
            "virtual_size": size,
            "raw_size": section.SizeOfRawData,
            "nonzero_bytes": sum(value != 0 for value in data),
            "sha256": hashlib.sha256(data).hexdigest().upper(),
        })
    return summaries


def build_resolved_import_report(
        uc, tracer, module_bases, import_slots, image_base):
    target_to_label = dict(tracer.synthetic_import_targets)
    restored_imports = []
    for slot, record in sorted(tracer.resolved_import_writes.items()):
        module, symbol = split_import_label(tracer.synthetic_import_targets[record.target])
        restored_imports.append({
            "slot_va": slot, "slot_rva": slot - image_base,
            "section": tracer.section_for_address(slot), "module": module, "symbol": symbol,
            "emu_address": record.target, "write_count": record.write_count,
            "last_writer_va": record.writer, "last_block_count": record.block_count,
        })

    bootstrap_imports = []
    for slot, label in sorted(import_slots.items()):
        module_name, symbol = split_import_label(label)
        module_base = module_bases[module_name]
        if symbol.lower().startswith("ordinal_"):
            requested = int(symbol.split("_", 1)[1], 0)
        else:
            requested = symbol.lower()
        target = tracer.export_lookup[(module_base, requested)]
        bootstrap_imports.append({
            "slot_va": slot,
            "slot_rva": slot - image_base,
            "module": module_name,
            "symbol": symbol,
            "emu_address": target,
        })


        target_to_label[target] = label

    final_image_matches = []
    bootstrap_slots = set(import_slots)
    restored_slots = set(tracer.resolved_import_writes)
    for start, end, section_name in tracer.image_section_ranges:
        data = bytes(uc.mem_read(start, end - start))
        for offset in range(0, len(data) - 7, 8):
            target = read_u64(data, offset)
            label = target_to_label.get(target)
            if label is None:
                continue
            module_name, symbol = split_import_label(label)
            slot = start + offset
            if slot in restored_slots:
                source = "resolved_write"
            elif slot in bootstrap_slots:
                source = "bootstrap_iat"
            else:
                source = "final_scan_only"
            final_image_matches.append({
                "slot_va": slot,
                "slot_rva": slot - image_base,
                "section": section_name,
                "source": source,
                "module": module_name,
                "symbol": symbol,
                "emu_address": target,
            })

    recovered_iat = [
        record for record in final_image_matches
        if record["source"] == "final_scan_only"
    ]
    import_key = lambda record: (
        record["module"], record["emu_address"]
    )
    recovered_iat_matches_bootstrap = (
        Counter(map(import_key, recovered_iat)) ==
        Counter(map(import_key, bootstrap_imports))
    )
    recovered_iat_modules = {}
    for record in recovered_iat:
        module = recovered_iat_modules.setdefault(record["module"], {
            "count": 0,
            "first_slot_rva": record["slot_rva"],
            "last_slot_rva": record["slot_rva"],
        })
        module["count"] += 1
        module["last_slot_rva"] = record["slot_rva"]
    encoded = {"tables": [], "imports": []}
    if getattr(tracer, "encoded_string_keys", ()):
        encoded = recover_encoded_imports(bytes(uc.mem_read(image_base, tracer.image_end - image_base)),
                                         image_base, module_bases, require_catalog(), tracer.encoded_string_keys)
    return {
        "image_base": image_base,
        "encoded_import_tables": encoded["tables"],
        "encoded_imports": encoded["imports"],
        "encoded_import_slot_count": len(encoded["imports"]),
        "stop_reason": tracer.stop_reason,
        "emu_modules": {
            name: {
                "base": base,
                "size": EMU_MODULE_SIZE,
            }
            for name, base in sorted(module_bases.items())
        },
        "bootstrap_iat_count": len(bootstrap_imports),
        "bootstrap_iat": bootstrap_imports,
        "resolved_write_count": tracer.resolved_write_count,
        "resolved_slot_count": len(restored_imports),
        "resolved_imports": restored_imports,
        "recovered_iat_count": len(recovered_iat),
        "recovered_iat_matches_bootstrap": recovered_iat_matches_bootstrap,
        "recovered_iat_modules": dict(sorted(recovered_iat_modules.items())),
        "recovered_iat": recovered_iat,
        "final_image_match_count": len(final_image_matches),
        "final_image_matches": final_image_matches,
    }


def write_unicode_string(uc, descriptor, string_address, value):
    encoded = value.encode("utf-16-le")
    uc.mem_write(string_address, encoded + b"\x00\x00")
    uc.mem_write(
        descriptor,
        struct.pack("<HHI", len(encoded), len(encoded) + 2, 0) +
        encode_u64(string_address),
    )


def build_process_host():
    data = bytearray(0x400)
    write_u16(data, 0, 0x5A4D)
    write_u32(data, 0x3C, 0x80)
    write_u32(data, 0x80, 0x4550)
    write_pe_structure(data, 0x84, IMAGE_FILE_HEADER,
                       Machine=0x8664, NumberOfSections=1,
                       SizeOfOptionalHeader=0xF0, Characteristics=0x22)
    write_pe_structure(data, 0x98, IMAGE_OPTIONAL_HEADER64,
                       Magic=0x20B, ImageBase=HOST_IMAGE_BASE,
                       AddressOfEntryPoint=0x1000, BaseOfCode=0x1000, SizeOfCode=0x200,
                       SectionAlignment=0x1000, FileAlignment=0x200,
                       SizeOfImage=0x2000, SizeOfHeaders=0x200, Subsystem=3,
                       NumberOfRvaAndSizes=16)
    write_pe_structure(data, 0x188, IMAGE_SECTION_HEADER,
                       Name=b".text", Misc_VirtualSize=1, VirtualAddress=0x1000,
                       SizeOfRawData=0x200, PointerToRawData=0x200, Characteristics=0x60000020)
    data[0x200] = 0xCC
    return memory_image(bytes(data))


def map_peb_loader_data(uc, module_bases, process_image):
    uc.mem_map(PEB_LDR_BASE, PEB_LDR_SIZE, UC_PROT_ALL)
    uc.mem_write(PEB_LDR_BASE, b"\x00" * PEB_LDR_SIZE)
    uc.mem_write(PEB_LDR_BASE + 0x00, encode_u32(0x58))
    uc.mem_write(PEB_LDR_BASE + 0x04, encode_u32(1))

    modules = [process_image]
    for name, base in sorted(module_bases.items(), key=lambda item: item[1]):
        modules.append(ModuleImage(name, base, EMU_MODULE_SIZE, 0, f"C:\\Windows\\System32\\{name}"))

    entries = [PEB_LDR_BASE + 0x100 + index * 0x100 for index in range(len(modules))]
    string_cursor = PEB_LDR_BASE + 0x8000
    list_offsets = (0x00, 0x10, 0x20)
    head_offsets = (0x10, 0x20, 0x30)
    for link_offset, head_offset in zip(list_offsets, head_offsets):
        head = PEB_LDR_BASE + head_offset
        first = entries[0] + link_offset
        last = entries[-1] + link_offset
        uc.mem_write(head, struct.pack("<QQ", first, last))
        for index, entry in enumerate(entries):
            current = entry + link_offset
            previous_link = head if index == 0 else entries[index - 1] + link_offset
            next_link = head if index + 1 == len(entries) else entries[index + 1] + link_offset
            uc.mem_write(current, struct.pack("<QQ", next_link, previous_link))

    for entry, module in zip(entries, modules):
        name, base, image_size, entry_point, full_name = module
        uc.mem_write(entry + 0x30, encode_u64(base))
        uc.mem_write(entry + 0x38, encode_u64(entry_point))
        uc.mem_write(entry + 0x40, encode_u32(image_size))
        full_address = string_cursor
        string_cursor += align_up(len(full_name.encode("utf-16-le")) + 2, 8)
        base_address = string_cursor
        string_cursor += align_up(len(name.encode("utf-16-le")) + 2, 8)
        if string_cursor > PEB_LDR_BASE + PEB_LDR_SIZE:
            raise MemoryError("synthetic PEB loader strings exceed mapping")
        write_unicode_string(uc, entry + 0x48, full_address, full_name)
        write_unicode_string(uc, entry + 0x58, base_address, name)
    return entries


def map_synthetic_process_state(uc, module_bases, process_image=None):
    version = require_catalog().windows
    windows_build = version["build"]
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    uc.mem_map(KUSER_SHARED_DATA_BASE, PAGE_SIZE, UC_PROT_ALL)
    uc.mem_write(KUSER_SHARED_DATA_BASE + 0x260, encode_u32(windows_build))
    uc.mem_write(KUSER_SHARED_DATA_BASE + 0x26C, encode_u32(version["major"]))
    uc.mem_write(KUSER_SHARED_DATA_BASE + 0x270, encode_u32(version["minor"]))
    if process_image is None:
        host_blob = build_process_host()
        uc.mem_map(HOST_IMAGE_BASE, len(host_blob), UC_PROT_ALL)
        uc.mem_write(HOST_IMAGE_BASE, host_blob)
        process_image = ModuleImage("host.exe", HOST_IMAGE_BASE, len(host_blob),
                                    RETURN_SENTINEL, "C:\\host.exe")
    else:
        uc.mem_map(RETURN_SENTINEL, PAGE_SIZE, UC_PROT_ALL)
        uc.mem_write(RETURN_SENTINEL, b"\xcc")
    uc.mem_map(EMU_HEAP_BASE, EMU_HEAP_SIZE, UC_PROT_ALL)

    uc.mem_map(TEB_BASE, PAGE_SIZE, UC_PROT_ALL)
    uc.mem_map(PEB_BASE, PAGE_SIZE, UC_PROT_ALL)
    uc.reg_write(ux.UC_X86_REG_GS_BASE, TEB_BASE)
    stack_base = STACK_BASE + STACK_SIZE
    stack_limit = STACK_BASE
    uc.mem_write(TEB_BASE + 0x08, encode_u64(stack_base))
    uc.mem_write(TEB_BASE + 0x10, encode_u64(stack_limit))
    uc.mem_write(TEB_BASE + 0x30, encode_u64(TEB_BASE))
    uc.mem_write(TEB_BASE + 0x40, encode_u64(0x1337))
    uc.mem_write(TEB_BASE + 0x48, encode_u64(0x7331))
    uc.mem_write(TEB_BASE + 0x60, encode_u64(PEB_BASE))
    uc.mem_write(PEB_BASE + 0x10, encode_u64(process_image.base))
    map_peb_loader_data(uc, module_bases, process_image)
    uc.mem_write(PEB_BASE + 0x18, encode_u64(PEB_LDR_BASE))
    uc.mem_write(PEB_BASE + 0x30, encode_u64(EMU_HEAP_BASE))
    uc.mem_write(PEB_BASE + 0x118, encode_u32(version["major"]))
    uc.mem_write(PEB_BASE + 0x11C, encode_u32(version["minor"]))
    uc.mem_write(PEB_BASE + 0x120, encode_u16(windows_build & 0xFFFF))

    uc.mem_write(PEB_BASE + 0x124, encode_u32(version["platform_id"]))
    uc.mem_write(KUSER_SHARED_DATA_BASE + 0x264, encode_u32(version["product_type"]))
    uc.mem_write(KUSER_SHARED_DATA_BASE + 0x268, b"\x01")
    rsp = STACK_BASE + STACK_SIZE - 0x1008
    uc.mem_write(rsp, encode_u64(RETURN_SENTINEL))
    return rsp


class Tracer:
    def __init__(self, uc, image_start, image_end, synthetic_import_targets,
                 pe, module_bases, export_lookup, progress=None, diagnostics=None):
        self.uc = uc
        self.progress = progress
        self.diagnostics = diagnostics
        self.import_log = None
        self.cpuid_engine = None
        self.last_progress_time = time.monotonic()
        self.recent_blocks = deque(maxlen=32)
        self.ordinary_blocks = set()
        self.entry_address = image_start + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.section_headers = {
            image_start + section.VirtualAddress: {
                "raw_size": section.SizeOfRawData,
                "raw_offset": section.PointerToRawData,
                "virtual_size": section.Misc_VirtualSize,
            } for section in pe.sections
        }
        self.image_start = image_start
        self.image_end = image_end
        self.single_step = SingleStep(self, pe)
        self.synthetic_import_targets = synthetic_import_targets
        self.events = []
        self.instructions = 0
        self.stop_reason = None
        self.stop_registers = None
        self.module_bases = module_bases
        self.module_paths = {}
        self.last_error = 0
        self.thread_hidden_from_debugger = False
        self.export_lookup = export_lookup
        self.heap_cursor = EMU_HEAP_BASE + 0x1000
        self.heap_allocations = {}
        self.local_allocations = set()
        self.emu_file_size = len(pe.__data__)
        self.files = FileModel(uc, {"sample.exe": bytes(pe.__data__)})
        self.blocks = 0
        self.block_counter = None
        self.hook_statistics = {}
        self.crc_accelerations = []
        self.resolved_import_writes = {}
        self.resolved_write_count = 0
        self.syscall_catalog = {}
        self.written_destination_pages = set()
        self.stack_copy_count = 0
        self.stack_copy_bytes = 0
        self.stack_copy_candidates = set()
        if progress:
            progress("Discovering CRC loops")
        self.discovered_crc_loops = discover_crc_loops(pe)
        for section in pe.sections:
            raw = section.get_data()
            cursor = 0
            while (cursor := raw.find(b"\xf3\xa4", cursor)) >= 0:
                self.stack_copy_candidates.add(image_start + section.VirtualAddress + cursor)
                cursor += 1

        discovery = {
            "crc_candidates": [{"address": address, "kind": candidate.get('kind', 'crc')}
                               for address, candidate in self.discovered_crc_loops.items()],
            "stack_copy_candidates": sorted(self.stack_copy_candidates),
        }
        if diagnostics:
            diagnostics.record('accelerator_discovery', **discovery)
            for address, candidate in self.discovered_crc_loops.items():
                ranges = candidate.get('code_ranges', [(address, candidate['bytes'])])
                diagnostics.register_candidate('crc', address,
                                               [(start, start + len(raw)) for start, raw in ranges])
        if progress:
            progress(f"crc {len(self.discovered_crc_loops)} "
                     f"stack copies {len(self.stack_copy_candidates)}")

        sections = sorted(pe.sections, key=lambda section: section.VirtualAddress)
        self.image_section_ranges = []
        self.packed_destination_ranges = []
        for index, section in enumerate(sections):
            start = image_start + section.VirtualAddress
            if index + 1 < len(sections):
                end = image_start + sections[index + 1].VirtualAddress
            else:
                end = image_end
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            self.image_section_ranges.append((start, end, name))
            if section.SizeOfRawData != 0 or section.Misc_VirtualSize == 0:
                continue
            self.packed_destination_ranges.append((
                start,
                end,
                name,
            ))

    def in_module(self, address):
        return self.image_start <= address < self.image_end

    def sync_counts(self):
        if self.block_counter is not None:
            self.blocks = self.block_counter()
            self.instructions = self.blocks

    def add_event(self, kind, address, **details):
        self.sync_counts()
        event = Event(kind, address, self.instructions, details)
        self.events.append(event)
        if self.diagnostics:
            self.diagnostics.record('event', event=event)
        return event

    def stop_event(self, event):
        self.stop_reason = event
        self.stop_registers = register_state(self.uc)
        self.uc.emu_stop()
        if self.diagnostics:
            self.diagnostics.checkpoint(self.uc, blocks=self.blocks, stop_reason=event,
                                        recent_blocks=list(self.recent_blocks))
        if self.progress:
            self.progress(f"stop {event.kind}")

    def stop(self, kind, address, **details):
        self.stop_event(self.add_event(kind, address, **details))

    def read_ascii(self, address, limit=512):
        if not address:
            return ""
        result = bytearray()
        for index in range(limit):
            value = self.uc.mem_read(address + index, 1)[0]
            if value == 0:
                break
            result.append(value)
        return result.decode("ascii", errors="replace")


    def packed_destination_for(self, address):
        for start, end, name in self.packed_destination_ranges:
            if start <= address < end:
                return start, end, name
        return None

    def section_for_address(self, address):
        for start, end, name in self.image_section_ranges:
            if start <= address < end:
                return name
        return None


    def read_utf16(self, address, limit=512):
        if not address:
            return ""
        result = bytearray()
        for index in range(limit):
            pair = bytes(self.uc.mem_read(address + index * 2, 2))
            if pair == b"\x00\x00":
                break
            result.extend(pair)
        return result.decode("utf-16-le", errors="replace")


    def heap_allocate(self, size):
        size = max(1, int(size))
        address = align_up(self.heap_cursor, 0x10)
        end = address + align_up(size, 0x10)
        if end > EMU_HEAP_BASE + EMU_HEAP_SIZE:
            raise MemoryError(f"synthetic heap exhausted by 0x{size:X}-byte allocation")
        self.heap_cursor = end
        self.heap_allocations[address] = size
        self.uc.mem_write(address, b"\x00" * size)
        return address

    def write_u32_if_mapped(self, address, value):
        if address:
            self.uc.mem_write(address, encode_u32(value & 0xFFFFFFFF))

    def write_u64_if_mapped(self, address, value):
        if address:
            self.uc.mem_write(address, encode_u64(value & 0xFFFFFFFFFFFFFFFF))

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

    def emulate_import(self, label):
        module_name, symbol = split_import_label(label)
        symbol_lower = symbol.lower()
        canonical_symbol = (
            "nt" + symbol_lower[2:] if symbol_lower.startswith("zw") else symbol_lower
        )
        rcx = self.uc.reg_read(ux.UC_X86_REG_RCX)
        rdx = self.uc.reg_read(ux.UC_X86_REG_RDX)
        r8 = self.uc.reg_read(ux.UC_X86_REG_R8)
        r9 = self.uc.reg_read(ux.UC_X86_REG_R9)
        details = {}

        version = require_catalog().windows
        if symbol_lower == "getversion":
            result = (version["build"] << 16) | (version["minor"] << 8) | version["major"]
        elif symbol_lower in ("rtlgetversion", "getversionexa", "getversionexw"):
            size = read_u32(self.uc.mem_read(rcx, 4))
            wide = symbol_lower != "getversionexa"
            basic, extended = (276, 284) if wide else (148, 156)
            if size not in (basic, extended):
                result = 0xC000000D if symbol_lower == "rtlgetversion" else 0
            else:
                info = bytearray(size)
                struct.pack_into("<IIIII", info, 0, size, version["major"], version["minor"],
                                 version["build"], version["platform_id"])
                if size == extended:
                    struct.pack_into("<HHHBB", info, basic, version["service_pack_major"],
                                     version["service_pack_minor"], version["suite_mask"], version["product_type"], 0)
                self.uc.mem_write(rcx, bytes(info))
                result = 0 if symbol_lower == "rtlgetversion" else 1
            details["catalog_windows"] = version
        elif symbol_lower in ("getmodulehandlea", "loadlibrarya"):
            requested = normalize_module_name(self.read_ascii(rcx))
            result = self.module_bases.get(requested, 0)
            details["requested_module"] = requested
        elif symbol_lower in ("getmodulehandlew", "loadlibraryw", "loadlibraryexw"):
            requested = normalize_module_name(self.read_utf16(rcx))
            result = self.module_bases.get(requested, 0)
            details["requested_module"] = requested
        elif symbol_lower == "getmodulefilenamew":
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
        elif symbol_lower == "getprocaddress":
            if rdx <= 0xFFFF:
                requested = int(rdx)
            else:
                requested = self.read_ascii(rdx).lower()
            result = self.export_lookup.get((rcx, requested), 0)
            details["requested_export"] = requested
        elif symbol_lower == "getprocessheap":
            result = EMU_HEAP_BASE
        elif symbol_lower == "localalloc":
            details.update(allocation_size=int(rdx), allocation_flags=rcx & 0xFFFFFFFF)
            if rcx & 0xFFFFFFFF & ~0xF70:
                return None, details
            try:
                result = self.heap_allocate(rdx)
            except MemoryError:
                self.last_error = 8
                result = 0
            if result:
                self.local_allocations.add(result)
        elif symbol_lower == "localfree":
            if not rcx:
                result = 0
            elif rcx in self.local_allocations:
                self.local_allocations.remove(rcx)
                self.heap_allocations.pop(rcx)
                result = 0
            else:
                self.last_error = 6
                result = rcx
        elif symbol_lower == "heapalloc":
            result = self.heap_allocate(r8)
            details["allocation_size"] = int(r8)
        elif symbol_lower == "heaprealloc":
            result = self.heap_allocate(r9)
            details["allocation_size"] = int(r9)
        elif symbol_lower == "heapsize":
            result = self.heap_allocations.get(r8, 0xFFFFFFFFFFFFFFFF)
        elif symbol_lower in ("heapfree", "virtualfree", "freelibrary", "closehandle"):
            result = 1
        elif symbol_lower == "virtualalloc":
            result = self.heap_allocate(rdx)
            details["allocation_size"] = int(rdx)
        elif symbol_lower == "virtualprotect":
            self.write_u32_if_mapped(r9, 0x40)
            result = 1
        elif canonical_symbol == "ntprotectvirtualmemory":
            result = 0
        elif canonical_symbol == "ntqueryvirtualmemory":
            details.update(memory_address=rdx, information_class=r8 & 0xFFFFFFFF)
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
        elif canonical_symbol == "ntsetinformationthread" and (rdx & 0xFFFFFFFF) == 17:
            details.update(handle=rcx, information_class=17, input_address=r8, input_length=r9)
            if (r9 & 0xFFFFFFFF) != 0:
                result = 0xC0000004
            elif rcx != 0xFFFFFFFFFFFFFFFE:
                result = 0xC0000008
            else:
                self.thread_hidden_from_debugger = True
                result = 0
        elif canonical_symbol == "ntclose":
            details.update(handle=rcx, known_handle=rcx in self.files.handles)
            if rcx in self.files.handles:
                del self.files.handles[rcx]
                result = 0
            else:
                result = 0xC0000008
        elif canonical_symbol in (
            "ntdelayexecution",
            "ntsetinformationprocess",
            "ntsetinformationthread",
        ):
            result = 0
        elif canonical_symbol == "ntopenfile":
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
        elif canonical_symbol == "ntraiseharderror":
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
        elif canonical_symbol == "ntcreatesection":
            rsp = self.uc.reg_read(ux.UC_X86_REG_RSP)
            attributes = read_u32(self.uc.mem_read(rsp + 0x30, 4))
            file_handle = read_u64(self.uc.mem_read(rsp + 0x38, 8))
            handle = self.files.section(file_handle, attributes)
            result = 0 if handle is not None else 0xC0000008
            if handle is not None:
                self.write_u64_if_mapped(rcx, handle)
            details["section_attributes"] = attributes
        elif canonical_symbol == "ntmapviewofsection":
            rsp = self.uc.reg_read(ux.UC_X86_REG_RSP)
            def qword(address):
                return read_u64(self.uc.mem_read(address, 8))
            if qword(r8):
                raise ValueError("fixed-address file views are not modeled")
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
            result = 0
        elif canonical_symbol == "ntunmapviewofsection":
            result = 0
        elif canonical_symbol == "ntopensection":
            result = 0xC0000022
        elif canonical_symbol in (
            "ntqueryinformationprocess",
            "ntqueryinformationthread",
        ):
            details.update(handle=rcx, information_class=rdx & 0xFFFFFFFF,
                           output_address=r8, output_length=r9)

            def capture(name, address, size):
                if address and size:
                    try:
                        details[name] = bytes(self.uc.mem_read(address, size)).hex()
                    except UcError as exc:
                        details[name + "_error"] = str(exc)

            return_length = 0
            try:
                rsp = self.uc.reg_read(ux.UC_X86_REG_RSP)
                return_length = read_u64(self.uc.mem_read(rsp + 0x28, 8))
                details["return_length_address"] = return_length
            except UcError as exc:
                details["return_length_address_error"] = str(exc)
            capture("output_before", r8, min(int(r9), 64))
            capture("return_length_before", return_length, 4)
            result = 0
            information_class = rdx & 0xFFFFFFFF
            if canonical_symbol == "ntqueryinformationprocess" and information_class in (7, 30, 31):
                required = 4 if information_class == 31 else 8
                if (r9 & 0xFFFFFFFF) != required:
                    result = 0xC0000004
                elif rcx != 0xFFFFFFFFFFFFFFFF:
                    result = 0xC0000008
                else:
                    try:
                        self.uc.mem_write(r8, int(information_class == 31).to_bytes(required, 'little'))
                        if return_length:
                            self.uc.mem_write(return_length, required.to_bytes(4, 'little'))
                        if information_class == 30:
                            result = 0xC0000353
                    except UcError:
                        result = 0xC0000005
            elif canonical_symbol == "ntqueryinformationthread" and information_class == 17:
                if (r9 & 0xFFFFFFFF) != 1:
                    result = 0xC0000004
                elif rcx != 0xFFFFFFFFFFFFFFFE:
                    result = 0xC0000008
                else:
                    try:
                        self.uc.mem_write(r8, bytes([self.thread_hidden_from_debugger]))
                        if return_length:
                            self.uc.mem_write(return_length, (1).to_bytes(4, 'little'))
                    except UcError:
                        result = 0xC0000005
            elif r8 and r9:
                self.uc.mem_write(r8, b"\x00" * min(int(r9), 0x1000))
            capture("output_after", r8, min(int(r9), 64))
            capture("return_length_after", return_length, 4)
        elif canonical_symbol == "ntquerysysteminformation":
            if (rcx & 0xFFFFFFFF) == 0x23:
                details.update(information_class=0x23, output_length=r8 & 0xFFFFFFFF)
                try:
                    if r9:
                        self.uc.mem_write(r9, (2).to_bytes(4, 'little'))
                    if (r8 & 0xFFFFFFFF) < 2:
                        result = 0xC0000004
                    else:
                        self.uc.mem_write(rdx, b"\x00\x01")
                        result = 0
                except UcError:
                    result = 0xC0000005
            else:
                if rdx and r8:
                    self.uc.mem_write(rdx, b"\x00" * min(int(r8), 0x1000))
                self.write_u32_if_mapped(r9, 0)
                result = 0
        elif symbol_lower == "getcurrentprocess":
            result = 0xFFFFFFFFFFFFFFFF
        elif symbol_lower == "getprocessaffinitymask":
            if rcx != 0xFFFFFFFFFFFFFFFF:
                self.last_error = 6
                result = 0
            elif not rdx or not r8:
                self.last_error = 87
                result = 0
            else:
                self.write_u64_if_mapped(rdx, 1)
                self.write_u64_if_mapped(r8, 1)
                result = 1
        elif symbol_lower == "getcurrentthread":
            result = 0xFFFFFFFFFFFFFFFE
        elif symbol_lower in ("setprocessaffinitymask", "setthreadaffinitymask"):
            handle = 0xFFFFFFFFFFFFFFFF if symbol_lower == "setprocessaffinitymask" else 0xFFFFFFFFFFFFFFFE
            if rcx != handle:
                self.last_error = 6
                result = 0
            elif rdx != 1:
                self.last_error = 87
                result = 0
            else:
                result = 1
        elif symbol_lower == "getcurrentprocessid":
            result = 0x1337
        elif symbol_lower == "getcurrentthreadid":
            result = 0x7331
        elif symbol_lower in (
            "disablethreadlibrarycalls",
            "freeenvironmentstringsw",
            "queryperformancecounter",
        ):
            if symbol_lower == "queryperformancecounter":
                self.write_u64_if_mapped(rcx, self.instructions)
            result = 1
        elif symbol_lower == "gettickcount64":
            result = 0x12345678
        elif symbol_lower == "sleep":
            details["milliseconds"] = rcx & 0xFFFFFFFF
            if details["milliseconds"]:
                return None, details
            result = 0
        elif symbol_lower == "getsystemtimeasfiletime":
            self.write_u64_if_mapped(rcx, 0x01D9000000000000)
            result = 0
        elif symbol_lower in (
            "deletecriticalsection",
            "entercriticalsection",
            "leavecriticalsection",
            "initializecriticalsection",
            "initializecriticalsectionandspincount",
            "initializecriticalsectionex",
            "releasesrwlockexclusive",
            "acquiresrwlockexclusive",
        ):
            result = 1
        elif symbol_lower == "setlasterror":
            self.last_error = rcx & 0xFFFFFFFF
            result = 0
        elif symbol_lower == "getlasterror":
            result = self.last_error
        elif symbol_lower == "isdebuggerpresent":
            result = 0
        else:
            return None, details
        return result & 0xFFFFFFFFFFFFFFFF, details


    def on_block(self, uc, address, size, user_data):
        if self.block_counter is None:
            self.blocks += 1
        else:
            self.blocks = self.block_counter()
        self.instructions = self.blocks
        label = self.synthetic_import_targets.get(address)
        if label is not None and self.import_log is not None:
            self.import_log.begin(uc, address, label, self.blocks)
        if (self.single_step.active and
                self.synthetic_import_targets.get(address, '').lower().endswith('!rtlunwindex')):
            self.single_step.unwind()
            if self.import_log is not None:
                self.import_log.finish('stopped' if self.stop_reason else 'unwind',
                                       target=hex(uc.reg_read(ux.UC_X86_REG_RIP)))
            return
        if self.single_step.on_block(address):
            return
        if self.diagnostics:
            self.diagnostics.observe_block(address, size)
        if self.diagnostics:
            self.recent_blocks.append(hex(address))
            if self.blocks % 16384 == 0:
                now = time.monotonic()
                if now - self.last_progress_time >= 2:
                    self.last_progress_time = now
                    report = {
                        "blocks": self.blocks,
                        "address": address,
                        "recent_blocks": list(self.recent_blocks),
                        "written_page_count": len(self.written_destination_pages),
                        "resolved_import_writes": self.resolved_write_count,
                        "crc_accelerations": len(self.crc_accelerations),
                        "recent_events": self.events[-4:],
                        "registers": register_state(uc),
                    }
                    if self.progress:
                        self.progress(f"blocks {self.blocks}")
                    if self.diagnostics:
                        self.diagnostics.checkpoint(uc, **report)
        if self.blocks == 1 and self.progress:
            self.progress(f"first block 0x{address:x}")

        if address in self.ordinary_blocks:
            return

        if self.check_restored_entry(address):
            return
        if address in self.stack_copy_candidates and self.try_stack_copy(address):
            return
        if address in self.discovered_crc_loops:
            try:
                details = accelerate_crc(uc, address, self.discovered_crc_loops[address], self.image_start, self.image_end,
                                         [(start, start + view["size"]) for start, view in self.files.views.items()])
                if details:
                    self.crc_accelerations.append(details)
                    self.add_event("discovered_crc_accelerated", address, **details)
            except (ValueError, UcError) as exc:
                self.stop("discovered_crc_error", address, error=str(exc))
                return


        label = self.synthetic_import_targets.get(address)
        if label is not None:
            arguments = self.diagnostics.api_enter(uc, label, self.blocks) if self.diagnostics else None
            try:
                result, details = self.emulate_import(label)
            except Exception as error:
                if self.import_log is not None:
                    self.import_log.finish('error', error=str(error))
                self.stop(
                    "import_stub_error", address, import_name=label, error=str(error)
                )
                return
            if self.import_log is not None:
                self.import_log.finish('returned' if result is not None else 'stopped', result,
                                       details=format_report(details))
            if self.diagnostics:
                self.diagnostics.api_return(uc, label, arguments, result, details, self.blocks)
            if result is None:
                self.stop(
                    "guest_hard_error" if details.get("guest_hard_error") else "unknown_import",
                    address,
                    import_name=label,
                    target=address,
                    action="stub",
                    transfer="block_entry",
                    **details,
                )
                return
            self.add_event(
                "import_stub",
                address,
                import_name=label,
                target=address,
                action="stub",
                transfer="block_entry",
                result=result,
                **details,
            )
            rsp = uc.reg_read(ux.UC_X86_REG_RSP)
            return_address = read_u64(uc.mem_read(rsp, 8))
            uc.reg_write(ux.UC_X86_REG_RAX, result)
            uc.reg_write(ux.UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(ux.UC_X86_REG_RIP, return_address)
            return

        if not self.in_module(address):
            self.stop("module_exit", address, target=address)
            return


        if (len(self.ordinary_blocks) < 32768
                and address not in self.stack_copy_candidates
                and address not in self.discovered_crc_loops):
            self.ordinary_blocks.add(address)

    def on_cpuid_instruction(self, uc, user_data):
        leaf = uc.reg_read(ux.UC_X86_REG_EAX)
        subleaf = uc.reg_read(ux.UC_X86_REG_ECX)
        registers = (ux.UC_X86_REG_RAX, ux.UC_X86_REG_RBX,
                     ux.UC_X86_REG_RCX, ux.UC_X86_REG_RDX)
        values = None
        if leaf == 1:
            if self.cpuid_engine is None:
                self.cpuid_engine = Uc(UC_ARCH_X86, UC_MODE_64)
                self.cpuid_engine.ctl_set_cpu_model(uc.ctl_get_cpu_model())
                self.cpuid_engine.mem_map(0x1000, PAGE_SIZE)
                self.cpuid_engine.mem_write(0x1000, b'\x0f\xa2')
            cpu = self.cpuid_engine
            cpu.reg_write(ux.UC_X86_REG_CR4, uc.reg_read(ux.UC_X86_REG_CR4))
            cpu.reg_write(ux.UC_X86_REG_EAX, leaf)
            cpu.reg_write(ux.UC_X86_REG_ECX, subleaf)
            cpu.emu_start(0x1000, 0x1002, count=1)
            values = [cpu.reg_read(register) & 0xFFFFFFFF for register in registers]
            values[2] &= ~(1 << 31)
        elif 0x40000000 <= leaf < 0x50000000:
            values = [0, 0, 0, 0]
        details = dict(leaf=hex(leaf), subleaf=hex(subleaf),
                       action='emulated' if values is not None else 'unicorn')
        if values is not None:
            for register, value in zip(registers, values):
                uc.reg_write(register, value)
            details['output'] = dict(zip(('eax', 'ebx', 'ecx', 'edx'), map(hex, values)))
        self.add_event('cpuid', uc.reg_read(ux.UC_X86_REG_RIP), **details)
        return int(values is not None)

    def on_syscall_instruction(self, uc, user_data):
        address = uc.reg_read(ux.UC_X86_REG_RIP)
        syscall_number = uc.reg_read(ux.UC_X86_REG_RAX)
        syscall_names = self.syscall_catalog.get(syscall_number, [])
        if self.diagnostics:
            self.diagnostics.record('syscall_enter', syscall_number=syscall_number,
                                    syscall_names=syscall_names, blocks=self.blocks,
                                    **self.diagnostics.snapshot(uc))
        self.add_event(
            "syscall",
            address,
            syscall_number=syscall_number,
            syscall_names=syscall_names,
            action="model",
        )
        modeled_protect = any(name in ("NtProtectVirtualMemory", "ZwProtectVirtualMemory") for name in syscall_names)
        if not modeled_protect:
            self.stop_event(self.events[-1])
            return
        rflags = uc.reg_read(ux.UC_X86_REG_EFLAGS)
        if modeled_protect:
            rsp = uc.reg_read(ux.UC_X86_REG_RSP)
            try:
                old_protection = read_u64(uc.mem_read(rsp + 0x28, 8))
                self.write_u32_if_mapped(old_protection, 0x20)
            except Exception:
                pass
        uc.reg_write(ux.UC_X86_REG_RAX, 0)
        uc.reg_write(ux.UC_X86_REG_RCX, address + 2)
        uc.reg_write(ux.UC_X86_REG_R11, rflags)
        if self.diagnostics:
            self.diagnostics.record('syscall_return', syscall_number=syscall_number,
                                    blocks=self.blocks, **self.diagnostics.snapshot(uc))

    def on_peb_read(self, uc, access, address, size, value, user_data):
        rip = uc.reg_read(ux.UC_X86_REG_RIP)
        try:
            raw_value = bytes(uc.mem_read(address, size))
        except Exception:
            raw_value = "unavailable"
        self.add_event(
            "peb_memory_read",
            rip,
            memory_address=address,
            peb_offset=address - PEB_BASE,
            size=size,
            value=raw_value,
        )


    def on_image_write(self, uc, access, address, size, value, user_data):
        self.sync_counts()
        for start, end, _ in self.packed_destination_ranges:
            left, right = max(start, address), min(end, address + size)
            if left < right:
                self.written_destination_pages.update(range(left // PAGE_SIZE, (right - 1) // PAGE_SIZE + 1))
        if size != 8:
            return
        target = value & 0xFFFFFFFFFFFFFFFF
        label = self.synthetic_import_targets.get(target)
        if label is None:
            return
        previous = self.resolved_import_writes.get(address)
        self.resolved_import_writes[address] = ImportWrite(
            target, uc.reg_read(ux.UC_X86_REG_RIP), self.blocks,
            previous.write_count + 1 if previous else 1)
        self.resolved_write_count += 1

    def check_restored_entry(self, address):
        for start, end, name in self.packed_destination_ranges:
            if start <= address < end:
                observed = address // PAGE_SIZE in self.written_destination_pages
                self.stop("restored_code_entry" if observed else "unrestored_code_entry",
                          address, section=name, observed_write=observed,
                          reason=("Execution reached a page written during emulation in a section with no raw data."
                                  if observed else
                                  "Execution reached an unwritten page in a section with no raw data."),
                          at_pe_entry=address == self.entry_address,
                          first_block=self.blocks == 1,
                          block_count=self.blocks,
                          section_start=hex(start), section_end=hex(end),
                          section_header=self.section_headers.get(start),
                          written_page_count=len(self.written_destination_pages))
                return True
        return False

    def restored_ranges(self):
        ranges = []
        for page in self.written_destination_pages:
            for start, end, _ in self.packed_destination_ranges:
                left, right = max(start, page * PAGE_SIZE), min(end, (page + 1) * PAGE_SIZE)
                if left < right:
                    ranges.append((left, right))
        merged = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return [(start - self.image_start, end - self.image_start) for start, end in merged]

    def try_stack_copy(self, address):

        if bytes(self.uc.mem_read(address, 2)) != b"\xf3\xa4":
            return False
        count = self.uc.reg_read(ux.UC_X86_REG_RCX)
        source = self.uc.reg_read(ux.UC_X86_REG_RSI)
        destination = self.uc.reg_read(ux.UC_X86_REG_RDI)
        if self.uc.reg_read(ux.UC_X86_REG_RFLAGS) & 0x400 or not 1 <= count <= STACK_SIZE:
            return False
        if not all(STACK_BASE <= start and start + count <= STACK_BASE + STACK_SIZE for start in (source, destination)):
            return False
        if source < destination < source + count:


            gap = destination - source
            prefix = bytes(self.uc.mem_read(source, gap))
            data = (prefix * ((count + gap - 1) // gap))[:count]
        else:
            data = bytes(self.uc.mem_read(source, count))
        self.uc.mem_write(destination, data)
        self.uc.reg_write(ux.UC_X86_REG_RSI, source + count)
        self.uc.reg_write(ux.UC_X86_REG_RDI, destination + count)
        self.uc.reg_write(ux.UC_X86_REG_RCX, 0)
        self.uc.reg_write(ux.UC_X86_REG_RIP, address + 2)
        self.stack_copy_count += 1
        self.stack_copy_bytes += count
        return True


    def on_invalid_memory(self, uc, access, address, size, value, user_data):
        rip = uc.reg_read(ux.UC_X86_REG_RIP)
        self.stop(
            "invalid_memory",
            rip,
            access=access,
            memory_address=address,
            size=size,
            value=value,
        )
        return False


def final_output_path(input_path, output_name=None, directory=None):
    directory = Path(directory) if directory is not None else Path(__file__).resolve().parent.parent / "output"
    suffix = input_path.suffix or ".bin"
    name = output_name if output_name is not None else input_path.stem + "_unpacked" + suffix
    if not name or name in (".", "..") or name[-1] in " ." or any(ch in name for ch in '<>:"/\\|?*\0'):
        raise ValueError("output must be a filename, not a path")
    reserved = {"CON", "PRN", "AUX", "NUL"} | {f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(1, 10)}
    if name.split(".", 1)[0].upper() in reserved:
        raise ValueError("reserved Windows output filename")
    if not Path(name).suffix:
        name += suffix
    path = directory.resolve() / name
    return path


class LogArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, log_line(message) + "\n")


def build_argument_parser():
    parser = LogArgumentParser(prog="python -m unpack", add_help=False, allow_abbrev=False)
    parser.add_argument("pe", type=Path)
    parser.add_argument("output_name", nargs="?")
    parser.add_argument("--diagnostics", action="store_true")
    return parser


def main():
    args = build_argument_parser().parse_args()
    try:
        input_path = args.pe.resolve(strict=True)
        final_path = final_output_path(input_path, args.output_name)
    except (ValueError, OSError) as exc:
        raise SystemExit(log_line(exc)) from exc
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output_dir = Path.cwd() / "scratch" / f"trace_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=False)
    diagnostic_context = Diagnostics(output_dir) if args.diagnostics else nullcontext(None)
    with watch_run(output_dir) as progress, diagnostic_context as diagnostics:
        run(input_path, final_path, output_dir, progress, diagnostics)


def run(input_path, final_path, output_dir, progress, diagnostics=None):
    global ACTIVE_CATALOG
    progress("Loading Windows catalog")
    try:
        catalog_path = find_or_capture_catalog((Path.cwd(), Path(__file__).resolve().parent.parent))
        ACTIVE_CATALOG = Catalog(catalog_path)
    except (ValueError, OSError) as exc:
        raise SystemExit(log_line(exc)) from exc

    progress("Parsing PE")
    input_bytes = input_path.read_bytes()
    pe = pefile.PE(data=input_bytes, fast_load=False)
    if pe.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        raise SystemExit("expected amd64 pe")
    if pe.OPTIONAL_HEADER.Magic != 0x20B:
        raise SystemExit("expected pe32 plus")
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    input_sha256 = hashlib.sha256(input_bytes).hexdigest()
    if diagnostics:
        diagnostics.record('input', path=str(input_path), sha256=input_sha256,
                           catalog_sha256=require_catalog().sha256)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_end = image_base + align_up(pe.OPTIONAL_HEADER.SizeOfImage)
    if not image_base <= entry < image_end:
        raise SystemExit("entry outside image")
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    tls_callbacks = tls.struct.AddressOfCallBacks if tls else 0
    progress(f"entry 0x{entry:x}")

    progress("Collecting imports and syscall candidates")
    import_slots = collect_imports(pe)
    candidates = raw_syscall_candidates(pe)
    (output_dir / "raw_syscall_candidates.json").write_text(
        json.dumps([f"0x{address:X}" for address in candidates], indent=2), encoding="ascii")

    progress("Mapping image and Windows environment")
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped_start, mapped_end = map_pe(uc, pe)
    clean_ntdll = pefile.PE(data=require_catalog().ntdll_bytes, fast_load=False)
    emu_file_bytes = pe_memory_image(clean_ntdll)
    uc.mem_map(EMU_FILE_VIEW_BASE, align_up(len(emu_file_bytes)), UC_PROT_ALL)
    uc.mem_write(EMU_FILE_VIEW_BASE, emu_file_bytes)
    module_bases, synthetic_import_targets, export_lookup = map_emu_windows_modules(uc, import_slots)
    process_image = None if is_dll else ModuleImage(input_path.name, mapped_start,
                                                   pe.OPTIONAL_HEADER.SizeOfImage, entry, str(input_path))
    rsp = map_synthetic_process_state(uc, module_bases, process_image)
    for _, reg in GPR_REGS:
        uc.reg_write(reg, 0)
    uc.reg_write(ux.UC_X86_REG_RSP, rsp)
    uc.reg_write(ux.UC_X86_REG_RFLAGS, 0x202)
    uc.reg_write(ux.UC_X86_REG_RCX, mapped_start if is_dll else 0)
    uc.reg_write(ux.UC_X86_REG_RDX, 1 if is_dll else 0)
    uc.reg_write(ux.UC_X86_REG_R8, 0)
    uc.reg_write(ux.UC_X86_REG_RIP, entry)

    tracer = Tracer(uc, mapped_start, mapped_end, synthetic_import_targets,
                    pe, module_bases, export_lookup, progress=progress, diagnostics=diagnostics)
    if diagnostics:
        diagnostics.watch_mapping(uc, EMU_FILE_VIEW_BASE, len(emu_file_bytes), 'initial ntdll.dll image')
        if 'ntdll.dll' in module_bases:
            diagnostics.watch_mapping(uc, module_bases['ntdll.dll'], EMU_MODULE_SIZE, 'loaded ntdll.dll')
        diagnostics.watch_mapping(uc, KUSER_SHARED_DATA_BASE, PAGE_SIZE, 'KUSER_SHARED_DATA')
    tracer.module_paths = {base: f"C:\\Windows\\System32\\{name}" for name, base in module_bases.items()}
    tracer.module_paths[mapped_start] = str(input_path)
    tracer.module_paths[0] = process_image.path if process_image else "C:\\host.exe"
    if is_dll:
        tracer.module_paths[HOST_IMAGE_BASE] = "C:\\host.exe"
    tracer.emu_file_size = len(emu_file_bytes)
    tracer.files.files[input_path.name.lower()] = bytes(pe.__data__)
    progress("Recovering encoded string keys")
    tracer.encoded_string_keys = tuple(recover_keys(bytes(pe.__data__)))
    tracer.files.files["ntdll.dll"] = require_catalog().ntdll_bytes
    tracer.syscall_catalog = load_system_syscall_catalog()
    error = None
    progress("Emulating unpacker")
    if diagnostics:
        diagnostics.checkpoint(uc, blocks=0, entry=entry)
    with ImportCallLog(output_dir / 'import_calls.json') as import_log, \
            TraceHooks(tracer, PEB_BASE, PAGE_SIZE) as hooks:
        tracer.import_log = import_log
        progress(f"Hook backend: {hooks.backend}")
        if hooks.backend == 'python':
            print('using python hooks')
        try:
            uc.emu_start(entry, 0)
        except KeyboardInterrupt:
            error = "interrupted"
        except UcError as exc:
            error = str(exc)

    if diagnostics:
        diagnostics.checkpoint(uc, blocks=tracer.blocks, stop_reason=tracer.stop_reason,
                               error=error, recent_blocks=list(tracer.recent_blocks))
    execution = {
        "stop_reason": tracer.stop_reason,
        "error": error,
        "blocks": tracer.blocks,
        "hooks": tracer.hook_statistics,
        "registers": register_state(uc),
        "written_destination_pages": sorted(tracer.written_destination_pages),
    }

    (output_dir / "execution.json").write_text(
        json.dumps(format_report(execution), indent=2), encoding="ascii")
    if error:
        progress(f"Emulation error: {error}")
    elif tracer.stop_reason is None:
        progress("Emulation returned without a recorded stop reason")
    progress("Writing events")
    events_path = output_dir / "events.json"
    events_path.write_text(json.dumps(format_report(tracer.events), indent=2), encoding="ascii")
    if error or not tracer.stop_reason or tracer.stop_reason.kind != "restored_code_entry":
        reason = tracer.stop_reason.kind if tracer.stop_reason else "no_stop"
        detail = tracer.stop_reason.details.get("reason", "") if tracer.stop_reason else ""
        failure = f"Export refused ({reason}): {error or detail or 'unpacking did not reach restored code'}"
        summary = {**execution, "input": str(input_path), "entry": entry,
                   "unicorn_error": error, "analysis_pe": None,
                   "reconstruction_error": failure, "events": str(events_path)}
        (output_dir / "summary.json").write_text(
            json.dumps(format_report(summary), indent=2), encoding="ascii")
        raise SystemExit(log_line(f"export refused {reason}"))
    progress("Summarizing sections and resolving imports")
    section_summaries = summarize_mapped_sections(uc, pe)
    import_report = build_resolved_import_report(uc, tracer, module_bases, import_slots, mapped_start)
    resolved_imports_path = output_dir / "resolved_imports.json"
    resolved_imports_path.write_text(json.dumps(format_report(import_report), indent=2), encoding="ascii")
    analysis_pe_path = None
    reconstruction_report_path = None
    reconstruction_error = None
    progress("Reconstructing PE")
    try:
        ranges = tracer.restored_ranges()
        output, reconstruction = reconstruct_imports(dump_pe(uc.mem_read, mapped_start), import_report, ranges)
        with pefile.PE(data=output) as rebuilt:
            import_metadata = import_address_metadata(rebuilt, output, import_report)
        analysis_pe_path = final_path
        analysis_pe_path.parent.mkdir(parents=True, exist_ok=True)
        with analysis_pe_path.open("wb") as stream:
            stream.write(output)
        import_metadata_path = analysis_pe_path.with_name(analysis_pe_path.name + '.imports.json')
        import_metadata_path.write_text(json.dumps(import_metadata, indent=2), encoding='ascii')
        reconstruction['import_addresses'] = str(import_metadata_path)
        reconstruction["output"] = str(analysis_pe_path)
        reconstruction_report_path = output_dir / "analysis.imports.json"
        reconstruction_report_path.write_text(json.dumps(format_report(reconstruction), indent=2), encoding="ascii")
    except (ValueError, RuntimeError, OSError, pefile.PEFormatError) as exc:
        reconstruction_error = str(exc)

    summary = {
        "catalog_sha256": require_catalog().sha256,
        "catalog_windows": require_catalog().windows,
        "input": str(input_path),
        "input_sha256": input_sha256,
        "image_base": mapped_start,
        "image_end": mapped_end,
        "entry": entry,
        "entry_kind": "dll" if is_dll else "exe",
        "dll_reason_rdx": "0x1" if is_dll else None,
        "written_destination_pages": [page * PAGE_SIZE for page in sorted(tracer.written_destination_pages)],
        "instructions": tracer.instructions,
        "blocks": tracer.blocks,
        "hooks": tracer.hook_statistics,
        "stack_copy_accelerations": tracer.stack_copy_count,
        "stack_copy_bytes": tracer.stack_copy_bytes,
        "discovered_crc_loops": [{"rva": address - mapped_start, "state_xor": candidate["state_xor"]}
                                 for address, candidate in tracer.discovered_crc_loops.items()],
        "import_slots": len(import_slots),
        "emu_modules": {name: base for name, base in sorted(module_bases.items())},
        "raw_syscall_candidates": len(candidates),
        "resolved_import_writes": tracer.resolved_write_count,
        "resolved_import_slots": len(tracer.resolved_import_writes),
        "resolved_imports": str(resolved_imports_path),
        "crc_accelerations": tracer.crc_accelerations,
        "stop_reason": tracer.stop_reason,
        "unicorn_error": error,
        "stop_registers": tracer.stop_registers,
        "final_registers": register_state(uc),
        "mapped_sections": section_summaries,
        "analysis_pe": str(analysis_pe_path) if analysis_pe_path else None,
        "reconstruction_report": str(reconstruction_report_path) if reconstruction_report_path else None,
        "reconstruction_error": reconstruction_error,
        "events": str(events_path),
    }
    progress("Writing summary")
    (output_dir / "summary.json").write_text(json.dumps(format_report(summary), indent=2), encoding="ascii")
    if reconstruction_error:
        error = reconstruction_error.split(':', 1)[0]
        raise SystemExit(log_line(f"export failed {error}"))
    print("export complete")
    print(f"imports {reconstruction['import_count']}")
    print(log_line(f"stop {tracer.stop_reason.kind}"))
    if reconstruction['exceptions'].get('error'):
        print("exception directory cleared")
    elif reconstruction['exceptions'].get('dropped_count'):
        print(f"exception entries dropped {reconstruction['exceptions']['dropped_count']}")


if __name__ == "__main__":
    main()
