import struct
import unicorn.x86_const as ux
from unicorn import UC_PROT_WRITE
from .semantic_crc import discover_semantic_crc_loops

def discover_crc_loops(pe):
    return discover_semantic_crc_loops(pe)


def accelerate_crc(uc, address, candidate, image_start, image_end, file_ranges=(), arch=None):
    raw = candidate["bytes"]
    if candidate.get("proof_address", address) != address:
        raise ValueError("crc candidate address mismatch")
    code_ranges = candidate.get('code_ranges', [(address, raw)])
    for start, code in code_ranges:
        if bytes(uc.mem_read(start, len(code))) != code:
            raise ValueError("crc loop bytes changed since discovery")
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
    stack = uc.reg_read(arch.sp if arch is not None else ux.UC_X86_REG_RSP)
    depth = candidate["stack_depth"]
    if not any(start <= stack - depth and stack <= end + 1 and permissions & UC_PROT_WRITE
               for start, end, permissions in uc.mem_regions()):
        return None
    if any(stack - depth < end and start < stack for start, end in
           ((source, source + count), (table, table + 1024)) +
           tuple((start, start + len(code)) for start, code in code_ranges)):
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
