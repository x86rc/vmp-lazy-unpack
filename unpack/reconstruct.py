from importlib import import_module
import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from .arch import encode_ptr, for_pe, read_ptr, write_ptr
from .binary import encode_i32, encode_u32, read_i32, read_u32, write_u32
from .pe import align_up, parse_pe, file_offset
from .pe import write_pe_structure, IMAGE_IMPORT_DESCRIPTOR
from .imports import number, import_slots
from .import_wrappers import resolve_import_wrappers, retarget_wrapper_patch
from .decode_imports_arx import validate_metadata as validate_arx_metadata
from .decode_imports_xor import validate_metadata as validate_xor_metadata
from .unwind import repair_exception_tables

reconstruct_32 = import_module('.32bit.reconstruct_32', __package__)

IMPORT_STORAGE_CHARACTERISTICS = 0xC0000040


def prepare_import_storage(data):

    pe = parse_pe(data)
    section = max(pe.sections, key=lambda s: s.VirtualAddress)
    output = bytearray(data)
    old_pointer = section.PointerToRawData
    raw_size = section.SizeOfRawData
    pointer = old_pointer
    if not raw_size or pointer + raw_size != len(output):
        pointer = align_up(len(output), pe.OPTIONAL_HEADER.FileAlignment)
        output.extend(bytes(pointer - len(output)))
        output.extend(data[old_pointer:old_pointer + raw_size] if raw_size else b"")
        write_u32(output, section.get_field_absolute_offset("PointerToRawData"), pointer)
    payload_offset = align_up(max(section.Misc_VirtualSize, raw_size), 16)
    return bytes(output), {"section_rva": section.VirtualAddress,
                           "payload_rva": section.VirtualAddress + payload_offset,
                           "payload_offset": payload_offset, "raw_pointer": pointer,
                           "previous_raw_pointer": old_pointer}


def extend_import_storage(output, pe, storage, content, characteristics):
    section = next(s for s in pe.sections if s.VirtualAddress == storage["section_rva"])
    pointer = storage["raw_pointer"]
    virtual_size = storage["payload_offset"] + len(content)
    raw_size = align_up(virtual_size, pe.OPTIONAL_HEADER.FileAlignment)
    output.extend(bytes(pointer + storage["payload_offset"] - len(output)))
    output.extend(content)
    output.extend(bytes(pointer + raw_size - len(output)))
    original_name = section.Name.rstrip(b"\0")
    name = original_name


    if name in (b".reloc", b".rsrc"):
        name = b".idata"
        offset = section.get_file_offset()
        output[offset:offset + 8] = name.ljust(8, b"\0")
    write_u32(output, section.get_field_absolute_offset("Misc_VirtualSize"), virtual_size)
    write_u32(output, section.get_field_absolute_offset("SizeOfRawData"), raw_size)

    flags = (section.Characteristics | characteristics) & ~(0x02000000 | 0x80)
    write_u32(output, section.get_field_absolute_offset("Characteristics"), flags)
    write_u32(output, pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"),
              align_up(section.VirtualAddress + max(virtual_size, raw_size), pe.OPTIONAL_HEADER.SectionAlignment))
    write_u32(output, pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfInitializedData"),
              pe.OPTIONAL_HEADER.SizeOfInitializedData + raw_size - section.SizeOfRawData)
    return {**storage, "section_name": name.decode("ascii", "replace"),
            "previous_section_name": original_name.decode("ascii", "replace"),
            "virtual_size": virtual_size, "raw_size": raw_size}


def identity(record):
    symbol = record["symbol"]
    if isinstance(symbol, str) and symbol.startswith("ordinal_"):
        symbol = int(symbol.split("_", 1)[1], 0)
    if isinstance(symbol, int) and not 0 <= symbol <= 65535:
        raise BuildError("invalid import ordinal")
    return record["module"].lower(), symbol


def extra_imports(pe, records, section_rva):
    groups = {}
    for record in records:
        module, symbol = identity(record)
        groups.setdefault(module, []).append(symbol)
    existing = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
    names = {}
    for descriptor in existing:
        names.setdefault(descriptor.dll.decode("ascii").lower(), descriptor.dll.decode("ascii"))
    descriptor_size = (len(groups) + 1) * 20
    content = bytearray(descriptor_size)
    slots = {}
    arch = for_pe(pe)

    def pad(alignment):
        content.extend(bytes(align_up(len(content), alignment) - len(content)))

    for index, (module, imports) in enumerate(sorted(groups.items())):
        name_rva = section_rva + len(content)
        name = names.get(module, module[:-4].upper() + '.dll' if module.endswith('.dll') else module.upper())
        content.extend(name.encode("ascii") + b"\0")
        thunks = []
        for symbol in imports:
            if isinstance(symbol, int):
                thunks.append(arch.ordinal_flag | symbol)
            else:
                if not symbol or "\0" in symbol:
                    raise BuildError("invalid import name")
                pad(2)
                thunks.append(section_rva + len(content))
                content.extend(b"\0\0" + symbol.encode("ascii") + b"\0")
        pad(arch.ptr)
        lookup_rva = section_rva + len(content)
        encoded = b"".join(encode_ptr(arch, value) for value in thunks) + bytes(arch.ptr)
        content.extend(encoded)
        iat_rva = section_rva + len(content)
        content.extend(encoded)
        for slot_index, symbol in enumerate(imports):
            slots[(module, symbol)] = pe.OPTIONAL_HEADER.ImageBase + iat_rva + slot_index * arch.ptr
        write_pe_structure(content, index * 20, IMAGE_IMPORT_DESCRIPTOR,
                           OriginalFirstThunk=lookup_rva, Name=name_rva, FirstThunk=iat_rva)
    return bytes(content), descriptor_size, slots


def reconstruct_imports(data, report, restored_ranges, *, scan_wrappers=True, api_targets=None):

    data, storage = prepare_import_storage(data)
    pe = parse_pe(data)
    arch = for_pe(pe)
    base = pe.OPTIONAL_HEADER.ImageBase
    if number(report["image_base"]) != base:
        raise BuildError("import report image base mismatch")
    if report.get("unresolved_loader_queries"):
        raise BuildError("unresolved loader queries")
    if not restored_ranges:
        raise BuildError("no restored import ranges")
    image = pe.get_memory_mapped_image(max_virtual_address=pe.OPTIONAL_HEADER.SizeOfImage)
    actual = import_slots(pe)
    bootstrap = set()
    bootstrap_targets = {}
    for record in report["bootstrap_iat"]:
        slot = number(record["slot_rva"])
        key = identity(record)
        if actual.get(slot) != key:
            raise BuildError("bootstrap import differs from binary metadata")
        bootstrap.add(key)
        if "emu_address" in record:
            bootstrap_targets.setdefault(key, set()).add(number(record["emu_address"]))

    def restored(slot):
        return any(start <= slot and slot + arch.ptr <= end for start, end in restored_ranges)

    selected = {}
    for category, records in (("recovered_iat", report["recovered_iat"]),
                              ("runtime", report["resolved_imports"])):
        for record in records:
            slot = number(record["slot_rva"])
            if category == "recovered_iat" and not restored(slot):
                continue
            if category == "recovered_iat" and number(record["emu_address"]) not in bootstrap_targets.get(identity(record), set()):
                raise BuildError("bootstrap import mismatch")
            offset = file_offset(pe, slot, arch.ptr)
            if read_ptr(arch, data, offset) != number(record["emu_address"]):
                raise BuildError("import pointer mismatch")
            if slot in selected and identity(selected[slot][0]) != identity(record):
                raise BuildError("clashing imports at slot")
            selected[slot] = (record, category)
    encoded = {}
    for record in report.get("encoded_imports", []):
        slot = number(record["slot_rva"])
        key = record["key"]
        if record.get("encoding") != "subtract_signed_i32" or not isinstance(key, int) or not -(1 << 31) <= key < (1 << 31):
            raise BuildError("unsupported encoded import arithmetic")
        offset = file_offset(pe, slot, arch.ptr)
        stored = read_ptr(arch, data, offset)
        if stored != number(record["encoded_value"]) or (stored + key) & arch.mask != number(record["emu_address"]):
            raise BuildError("encoded import mismatch")
        validate_metadata = (validate_arx_metadata if record.get('metadata_encoding') == 'arx32'
                             else validate_xor_metadata)
        if not validate_metadata(data, pe, record):
            raise BuildError('encoded import metadata differs from dump')
        if key == 0 and slot in selected and identity(selected[slot][0]) == identity(record):
            continue
        if slot in encoded and encoded[slot] != record:
            raise BuildError("clashing encoded import records")
        encoded[slot] = record
        selected.pop(slot, None)
    discovered = []
    discovery_report = None
    if scan_wrappers and arch.bits == 64 and not report.get('encoded_imports') and api_targets:
        discovered, discovery_report = resolve_import_wrappers(
            pe, image, [], None, restored_ranges, api_targets=api_targets)
    if not selected and not encoded and not discovered:
        raise BuildError("no imports recovered")
    extras = set()
    for record in [item[0] for item in selected.values()] + list(encoded.values()) + discovered:
        key = identity(record)
        if key not in bootstrap:
            extras.add(key)
    for slot, key in actual.items():
        if slot in encoded:
            raise BuildError("encoded slot overlaps existing import")
        if slot in selected:
            if identity(selected[slot][0]) != key:
                raise BuildError("observed slot conflicts with existing import")
        else:
            selected[slot] = (dict(module=key[0], symbol=key[1], slot_rva=slot,
                                   emu_address=read_ptr(arch, data, file_offset(pe, slot, arch.ptr))), 'bootstrap')
    records = {}
    for record in [item[0] for item in selected.values()] + list(encoded.values()) + discovered:
        records.setdefault(identity(record), record)
    section_rva = storage["payload_rva"]
    content, descriptor_size, new_slots = extra_imports(pe, list(records.values()), section_rva)
    destinations = new_slots
    content = bytearray(content)


    plain = {slot: record for slot, (record, _) in selected.items()}
    thunks = {}
    for record in list(encoded.values()) + list(plain.values()):
        key = identity(record)
        if key in thunks:
            continue
        content.extend(bytes(align_up(len(content), arch.ptr) - len(content)))
        address = base + section_rva + len(content)
        if arch.bits == 64:
            displacement = destinations[key] - (address + 6)
            if not -(1 << 31) <= displacement < (1 << 31):
                raise BuildError("import thunk exceeds relative address range")
            content.extend(b"\xff\x25" + encode_i32(displacement))
        else:
            content.extend(b"\xff\x25" + encode_u32(destinations[key]))
        thunks[key] = address
    targets = {}
    for slot, (record, category) in selected.items():
        destination = destinations[identity(record)]
        if base + slot == destination:
            continue
        if category == "runtime":
            category = "runtime_duplicate" if identity(record) in bootstrap else "runtime_only"
        targets[base + slot] = (destination, category, record)
    if arch.bits == 32:
        patches = reconstruct_32.scan_import_references(pe, image, targets) if targets else []
    else:
        patches = scan_import_references(pe, image, targets) if targets else []
    if discovery_report is not None:
        wrapper_report = discovery_report
        for patch in discovered:
            relocated = retarget_wrapper_patch(patch, destinations, arch)
            if relocated is None:
                raise BuildError('wrapper iat target exceeds relative address range')
            patches.append(relocated)
        patches.sort(key=lambda p: p['instruction_va'])
    elif scan_wrappers:
        wrapper_patches, wrapper_report = resolve_import_wrappers(
            pe, image, list(encoded.values()), destinations, restored_ranges)
        patches = sorted(patches + wrapper_patches, key=lambda p: p["instruction_va"])
    else:
        wrapper_report = {'candidate_count': 0, 'resolved_count': 0, 'rejected': {},
                          'skipped': 'wrapper emulation disabled'}

    end = -1
    for patch in patches:
        if patch["instruction_va"] < end:
            raise BuildError("overlapping candidate import instructions")
        end = patch["instruction_va"] + patch["instruction_size"]
    output = bytearray(data)
    apply_patches(output, patches)
    encoded_patches = []
    plain_patches = []
    occupied = set()
    instruction_patches = {byte for patch in patches for byte in range(patch["patch_file_offset"], patch["patch_file_offset"] + len(patch["new_bytes"]))}
    slot_records = [(slot, record, record["key"], encoded_patches) for slot, record in encoded.items()]
    slot_records += [(slot, record, 0, plain_patches) for slot, record in plain.items()]
    for slot, record, key, patch_list in slot_records:
        offset = file_offset(pe, slot, arch.ptr)
        covered = set(range(offset, offset + arch.ptr))
        if covered & (occupied | instruction_patches):
            raise BuildError("overlapping import slot patches")
        occupied.update(covered)
        thunk = thunks[identity(record)]
        value = (thunk - key) & arch.mask
        write_ptr(arch, output, offset, value)
        patch_list.append({"slot_rva": hex(slot), "file_offset": offset,
                                "old_value": record.get("encoded_value", record["emu_address"]), "new_value": hex(value),
                                "key": key, "thunk_va": hex(thunk),
                                "iat_va": hex(destinations[identity(record)]),
                                "module": record["module"], "symbol": record["symbol"]})
    section = extend_import_storage(output, pe, storage, content,
                             IMPORT_STORAGE_CHARACTERISTICS | (0x20000000 if thunks else 0))
    set_directory(output, pe, 1, section_rva, descriptor_size)
    set_directory(output, pe, 12, 0, 0)
    verified = parse_pe(bytes(output))
    expected = {slot - base: key for key, slot in new_slots.items()}
    verified_slots = import_slots(verified)
    if verified_slots != expected:
        missing = [(hex(slot), key) for slot, key in expected.items() if verified_slots.get(slot) != key]
        unexpected = [(hex(slot), key) for slot, key in verified_slots.items() if expected.get(slot) != key]
        raise BuildError(f"rebuilt import mismatch with {len(missing)} missing or changed {missing[:8]} and "
                         f"{len(unexpected)} unexpected {unexpected[:8]}")
    write_u32(output, verified.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum"), 0)
    output = bytes(output)
    try:
        output, exception_report = repair_exception_tables(output)
    except ValueError as exc:
        output = bytearray(output)
        set_directory(output, verified, 3, 0, 0)
        output = bytes(output)
        exception_report = {"status": "cleared", "error": str(exc)}
    for patch in patches:
        offset = patch["patch_file_offset"]
        if output[offset:offset + len(patch["new_bytes"])] != patch["new_bytes"]:
            raise BuildError("patch verification failed")
    for patch in encoded_patches + plain_patches:
        value = read_ptr(arch, output, patch["file_offset"])
        thunk = number(patch["thunk_va"])
        offset = file_offset(verified, thunk - base, 6)
        if (value + patch["key"]) & arch.mask != thunk or output[offset:offset + 2] != b"\xff\x25":
            raise BuildError("import slot thunk verification failed")
        if arch.bits == 64:
            if thunk + 6 + read_i32(output, offset + 2) != number(patch["iat_va"]):
                raise BuildError("import slot thunk iat target mismatch")
        elif read_u32(output, offset + 2) != number(patch["iat_va"]):
            raise BuildError("import slot thunk iat target mismatch")
    result = {
        "import_storage": section,
        "exceptions": exception_report,
        "import_count": len(expected),
        "extra_import_count": len(extras),
        "patches": patches,
        "encoded_slot_patches": encoded_patches,
        "plain_slot_patches": plain_patches,
        "import_thunk_count": len(thunks),
        "wrapper_resolution": wrapper_report,
    }
    if discovery_report is not None:
        result['wrapper_imports'] = [dict(module=r['module'], symbol=r['symbol'],
                                          emu_address=r['emu_address'])
                                     for r in records.values() if r.get('category') == 'api_wrapper']
    return output, serializable_report(result)

class BuildError(RuntimeError):
    pass




def scan_import_references(
    pe: pefile.PE,
    image: bytes,
    target_map: dict[int, tuple[int, str, dict]],
):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    boundary_decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    boundary_decoder.skipdata = True
    image_base = pe.OPTIONAL_HEADER.ImageBase
    execute_flag = pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
    patches = {}

    for section in pe.sections:
        if not section.Characteristics & execute_flag:
            continue
        start_rva = section.VirtualAddress
        size = section.Misc_VirtualSize
        data = image[start_rva : start_rva + size]
        boundaries = None
        boundary = None
        offset = 0
        while offset + 6 <= len(data):
            if (
                0x48 <= data[offset] <= 0x4F
                and offset + 7 <= len(data)
                and data[offset + 1] == 0x8B
                and data[offset + 2] & 0xC7 == 0x05
            ):
                pass
            elif (
                0x40 <= data[offset] <= 0x4F
                and offset + 7 <= len(data)
                and data[offset + 1] == 0xFF
                and data[offset + 2] in (0x15, 0x25, 0x35)
            ):
                pass
            elif (
                data[offset] == 0xFF
                and data[offset + 1] in (0x15, 0x25, 0x35)
                and not (offset and 0x40 <= data[offset - 1] <= 0x4F)
            ):
                pass
            else:
                offset += 1
                continue

            instruction_rva = start_rva + offset
            instruction_va = image_base + instruction_rva
            decoded = list(
                decoder.disasm(data[offset : offset + 15], instruction_va, count=1)
            )
            if len(decoded) != 1:
                offset += 1
                continue
            instruction = decoded[0]
            pointer_load = (instruction.mnemonic == 'mov' and len(instruction.operands) == 2
                            and instruction.operands[0].type == X86_OP_REG
                            and instruction.operands[0].size == 8
                            and instruction.operands[1].type == X86_OP_MEM
                            and instruction.operands[1].size == 8)
            if instruction.mnemonic not in ("call", "jmp", "push") and not pointer_load:
                offset += 1
                continue
            targets = [
                instruction.address + instruction.size + operand.mem.disp
                for operand in instruction.operands
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP
            ]
            matched = [target for target in targets if target in target_map]
            if not matched:
                offset += 1
                continue
            if pointer_load:
                if boundaries is None:
                    boundaries = boundary_decoder.disasm_lite(data, image_base + start_rva)
                while boundary is None or boundary[0] + boundary[1] <= instruction.address:
                    boundary = next(boundaries, None)
                    if boundary is None:
                        break
                if boundary is None or boundary[0] != instruction.address:
                    offset += 1
                    continue
            if len(matched) != 1 or instruction.disp_size != 4:
                raise BuildError(
                    f"ambiguous import reference at 0x{instruction.address:X}"
                )

            old_target = matched[0]
            new_target, category, import_record = target_map[old_target]
            displacement = new_target - (instruction.address + instruction.size)
            if not -(1 << 31) <= displacement < (1 << 31):
                raise BuildError(
                    f"iat target out of rel32 range at 0x{instruction.address:X}"
                )
            patch_rva = instruction_rva + instruction.disp_offset
            patch_file_offset = file_offset(pe, patch_rva, 4)
            old_bytes = image[patch_rva : patch_rva + 4]
            new_bytes = encode_i32(displacement)
            patch = {
                "instruction_va": instruction.address,
                "instruction_rva": instruction_rva,
                "instruction_size": instruction.size,
                "mnemonic": instruction.mnemonic,
                "patch_va": image_base + patch_rva,
                "patch_rva": patch_rva,
                "patch_file_offset": patch_file_offset,
                "old_bytes": old_bytes,
                "new_bytes": new_bytes,
                "old_target_va": old_target,
                "new_target_va": new_target,
                "category": category,
                "module": import_record["module"],
                "symbol": import_record["symbol"],
            }
            previous = patches.get(patch_file_offset)
            if previous is not None and previous != patch:
                raise BuildError(
                    f"clashing import patches at file offset 0x{patch_file_offset:X}"
                )
            patches[patch_file_offset] = patch
            offset += instruction.size

    return sorted(patches.values(), key=lambda item: item["patch_va"])


def apply_patches(data: bytearray, patches: list[dict]) -> None:
    for patch in patches:
        offset = patch["patch_file_offset"]
        end = offset + len(patch["old_bytes"])
        if data[offset:end] != patch["old_bytes"]:
            raise BuildError(
                f"input changed at patch file offset 0x{offset:X}"
            )
        data[offset:end] = patch["new_bytes"]


def set_directory(data: bytearray, pe: pefile.PE, index: int, rva: int, size: int):
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    write_u32(data, directory.get_field_absolute_offset("VirtualAddress"), rva)
    write_u32(data, directory.get_field_absolute_offset("Size"), size)


def serializable_report(report: dict) -> dict:
    result = dict(report)
    result["patches"] = [
        {
            **patch,
            "instruction_va": f"0x{patch['instruction_va']:X}",
            "instruction_rva": f"0x{patch['instruction_rva']:X}",
            "patch_va": f"0x{patch['patch_va']:X}",
            "patch_rva": f"0x{patch['patch_rva']:X}",
            "patch_file_offset": f"0x{patch['patch_file_offset']:X}",
            "old_bytes": patch["old_bytes"].hex(" "),
            "new_bytes": patch["new_bytes"].hex(" "),
            "old_target_va": f"0x{patch['old_target_va']:X}",
            "new_target_va": f"0x{patch['new_target_va']:X}",
        }
        for patch in report["patches"]
    ]
    return result
