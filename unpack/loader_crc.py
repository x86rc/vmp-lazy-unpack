import re
import struct
import unicorn.x86_const as ux
from unicorn import UC_PROT_WRITE
from .binary import read_i32, read_u32
from .semantic_crc import discover_semantic_crc_loops

PATTERN = (
    "41 bb ?? ?? ?? ?? 45 0f b6 9c 13 ?? ?? ?? ?? "
    "68 37 f1 18 ac f6 54 24 07 44 33 d9 66 c1 6c 24 04 8d "
    "68 05 a7 93 68 41 81 e3 ff 00 00 00 66 81 64 24 01 2a 9a "
    "c1 44 24 02 d8 46 8b 1c 9f 0f 83 00 00 00 00 e8 00 00 00 00 "
    "c1 e9 08 66 d1 64 24 0c 0f 98 44 24 0b 41 33 cb 48 ff c2 "
    "81 f1 ?? ?? ?? ?? 66 c1 64 24 0b ac 48 ff cd 48 8d 64 24 18 "
    "0f 85 8b ff ff ff"
)
MATCHER = re.compile(b"".join(b"." if item == "??" else re.escape(bytes.fromhex(item))
                               for item in PATTERN.split()), re.DOTALL)
FILE_PATTERN = (
    "bf b9 80 1e 8b 40 c0 cf 22 0b ff 41 0f b6 3c 21 33 f9 "
    "68 0b bb a5 6e f7 54 24 02 81 e7 ff 00 00 00 c1 7c 24 00 f1 "
    "68 ac 9a 9a 77 8b 3c ba c0 7c 24 0a 61 c1 e9 08 c1 44 24 07 fc "
    "ff 44 24 09 33 cf 49 ff c1 e8 00 00 00 00 fe 44 24 16 "
    "81 f1 ?? ?? ?? ?? c1 6c 24 0d 6f f7 5c 24 13 66 ff 4c 24 15 "
    "48 ff c8 e8 00 00 00 00 68 bc 9d 38 b2 e8 00 00 00 00 "
    "48 8d 64 24 30 0f 85 82 ff ff ff"
)
FILE_MATCHER = re.compile(b"".join(b"." if item == "??" else re.escape(bytes.fromhex(item))
                                    for item in FILE_PATTERN.split()), re.DOTALL)
POST_PATTERN = (
    "ba 3e d1 3a 95 0f b6 14 20 e9 00 00 00 00 e9 00 00 00 00 e9 00 00 00 00 "
    "41 33 d1 e9 00 00 00 00 e9 00 00 00 00 81 e2 ff 00 00 00 "
    "68 94 e9 af 0a 66 c1 7c 24 01 c5 41 8b 14 90 41 c1 e9 08 "
    "48 81 64 24 00 2e ad 24 60 66 c1 7c 24 01 6f 44 33 ca "
    "66 c1 74 24 03 c3 48 ff c0 48 c1 64 24 00 ac 41 81 f1 ?? ?? ?? ?? "
    "48 c1 44 24 00 e3 c7 44 24 02 2c 25 a3 d2 48 ff cb "
    "68 af a8 8d 95 e8 00 00 00 00 e9 00 00 00 00 48 8d 64 24 18 0f 85 6f ff ff ff"
)
POST_MATCHER = re.compile(b"".join(b"." if item == "??" else re.escape(bytes.fromhex(item))
                                    for item in POST_PATTERN.split()), re.DOTALL)


def discover_crc_loops(pe):
    matches = {}
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        for match in MATCHER.finditer(section.get_data()):
            raw = match.group()
            seed = read_u32(raw, 2)
            displacement = read_i32(raw, 11)
            if seed + displacement != 0:
                continue
            address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + match.start()
            matches[address] = {"bytes": raw, "state_xor": read_u32(raw, 93)}
        for match in FILE_MATCHER.finditer(section.get_data()):
            raw = match.group()
            address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + match.start()
            matches[address] = {"bytes": raw, "state_xor": read_u32(raw, raw.index(b"\x81\xf1") + 2),
                                "kind": "file_crc"}
        for match in POST_MATCHER.finditer(section.get_data()):
            raw = match.group()
            address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + match.start()
            matches[address] = {"bytes": raw, "state_xor": read_u32(raw, raw.index(b"\x81\xf1") + 2),
                                "kind": "post_crc"}
    matches.update(discover_semantic_crc_loops(pe))
    return matches


def accelerate_crc(uc, address, candidate, image_start, image_end, file_ranges=()):
    raw = candidate["bytes"]
    if candidate.get("proof_address", address) != address:
        raise ValueError("CRC candidate address mismatch")
    if bytes(uc.mem_read(address, len(raw))) != raw:
        raise ValueError("CRC loop bytes changed since discovery")
    file_crc = candidate.get("kind") == "file_crc"
    post_crc = candidate.get("kind") == "post_crc"
    count_reg = ux.UC_X86_REG_RBX if post_crc else ux.UC_X86_REG_RAX if file_crc else ux.UC_X86_REG_RBP
    source_reg = ux.UC_X86_REG_RAX if post_crc else ux.UC_X86_REG_R9 if file_crc else ux.UC_X86_REG_RDX
    table_reg = ux.UC_X86_REG_R8 if post_crc else ux.UC_X86_REG_RDX if file_crc else ux.UC_X86_REG_RDI
    crc_reg = ux.UC_X86_REG_R9D if post_crc else ux.UC_X86_REG_ECX
    if "registers" in candidate:
        roles = candidate["registers"]
        count_reg, source_reg, table_reg, crc_reg = (
            getattr(ux, "UC_X86_REG_" + roles[role].upper()) for role in ("count", "source", "table", "crc"))
    count = uc.reg_read(count_reg)
    source = uc.reg_read(source_reg)
    table = uc.reg_read(table_reg)
    if count <= 1:
        return None
    if not (count <= 0x10000000 and any(start <= source and source + count <= end
                                       for start, end in ((image_start, image_end),) + tuple(file_ranges))
            and image_start <= table and table + 1024 <= image_end):
        return None
    stack = uc.reg_read(ux.UC_X86_REG_RSP)
    depth = candidate.get("stack_depth", 48 if file_crc else 24)
    if not any(start <= stack - depth and stack <= end + 1 and permissions & UC_PROT_WRITE
               for start, end, permissions in uc.mem_regions()):
        return None
    if any(stack - depth < end and start < stack for start, end in
           ((source, source + count), (table, table + 1024), (address, address + len(raw)))):
        return None
    values = struct.unpack("<256I", bytes(uc.mem_read(table, 1024)))
    crc = uc.reg_read(crc_reg)
    state_xor = candidate["state_xor"]
    for byte in bytes(uc.mem_read(source, count - 1)):
        crc = (crc >> 8) ^ values[(crc ^ byte) & 255] ^ state_xor
    uc.reg_write(crc_reg, crc)
    uc.reg_write(source_reg, source + count - 1)
    uc.reg_write(count_reg, 1)

    return {"source": source, "table": table, "skipped_iterations": count - 1,
            "state_xor": state_xor}
