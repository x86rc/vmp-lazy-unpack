import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_INVALID

from ..binary import encode_u32
from ..pe import file_offset


def scan_import_references(pe, image, target_map):
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    boundary_decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    boundary_decoder.skipdata = True
    image_base = pe.OPTIONAL_HEADER.ImageBase
    execute_flag = pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
    patches = {}

    for section in pe.sections:
        if not section.Characteristics & execute_flag:
            continue
        start_rva = section.VirtualAddress
        size = section.Misc_VirtualSize
        data = image[start_rva:start_rva + size]
        boundaries = None
        boundary = None
        offset = 0
        while offset + 5 <= len(data):
            head = data[offset]
            if head == 0xFF and offset + 6 <= len(data) and data[offset + 1] in (0x15, 0x25, 0x35):
                pass
            elif head == 0x8B and offset + 6 <= len(data) and data[offset + 1] & 0xC7 == 0x05:
                pass
            elif head == 0xA1:
                pass
            else:
                offset += 1
                continue

            instruction_rva = start_rva + offset
            instruction_va = image_base + instruction_rva
            decoded = list(decoder.disasm(data[offset:offset + 15], instruction_va, count=1))
            if len(decoded) != 1:
                offset += 1
                continue
            instruction = decoded[0]
            pointer_load = (instruction.mnemonic == 'mov' and len(instruction.operands) == 2
                            and instruction.operands[0].type == X86_OP_REG
                            and instruction.operands[0].size == 4
                            and instruction.operands[1].type == X86_OP_MEM
                            and instruction.operands[1].size == 4)
            if instruction.mnemonic not in ("call", "jmp", "push") and not pointer_load:
                offset += 1
                continue
            targets = [
                operand.mem.disp
                for operand in instruction.operands
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_INVALID
                and operand.mem.index == X86_REG_INVALID
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
                raise ValueError(f"unknown import reference at 0x{instruction.address:X}")

            old_target = matched[0]
            new_target, category, import_record = target_map[old_target]
            if new_target >= 1 << 32:
                raise ValueError(f"iat target outside 32 bit range at 0x{instruction.address:X}")
            patch_rva = instruction_rva + instruction.disp_offset
            patch_file_offset = file_offset(pe, patch_rva, 4)
            old_bytes = image[patch_rva:patch_rva + 4]
            new_bytes = encode_u32(new_target)
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
                raise ValueError(f"bad import patches at file offset 0x{patch_file_offset:X}")
            patches[patch_file_offset] = patch
            offset += instruction.size

    return sorted(patches.values(), key=lambda item: item["patch_va"])
