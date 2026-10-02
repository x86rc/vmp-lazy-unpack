import struct

import pefile

from .binary import read_u16, read_u32, write_u32
from .pe import align_up, parse_pe

MAX_HEADERS = 1024 * 1024


def dump_pe(read_memory, image_base):

    def read(rva, size):
        data = bytes(read_memory(image_base + rva, size))
        if len(data) != size:
            raise ValueError(f"short memory read at RVA 0x{rva:X}")
        return data

    dos = read(0, 64)
    if dos[:2] != b"MZ":
        raise ValueError("missing MZ header")
    nt_offset = read_u32(dos, 0x3C)
    if not 64 <= nt_offset <= MAX_HEADERS - 24:
        raise ValueError("invalid PE header offset")
    nt = read(nt_offset, 24)
    if nt[:4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    machine, count = struct.unpack_from("<HH", nt, 4)
    optional_size = read_u16(nt, 20)
    table_end = nt_offset + 24 + optional_size + count * 40
    if machine != 0x8664 or optional_size != 240 or not 0 < count <= 96 or table_end > MAX_HEADERS:
        raise ValueError("unsupported or invalid AMD64 PE headers")
    header_data = bytearray(read(0, table_end))


    for index in range(count):
        write_u32(header_data, nt_offset + 24 + optional_size + index * 40 + 20, 0)
    pe = pefile.PE(data=header_data, fast_load=True)
    header = pe.OPTIONAL_HEADER
    if header.Magic != 0x20B or len(header.DATA_DIRECTORY) != 16:
        raise ValueError("expected PE32+ with 16 data directories")
    if header.ImageBase != image_base:
        raise ValueError("rebased image unsupported")
    if not table_end <= header.SizeOfHeaders <= min(MAX_HEADERS, header.SizeOfImage):
        raise ValueError("invalid SizeOfHeaders")
    if header.SizeOfImage <= 0:
        raise ValueError("invalid image size")
    file_alignment = header.FileAlignment
    section_alignment = header.SectionAlignment
    align_up(0, file_alignment)
    align_up(0, section_alignment)
    if not 512 <= file_alignment <= 65536 or section_alignment < file_alignment:
        raise ValueError("unsupported PE alignments")

    sections = sorted(pe.sections, key=lambda section: section.VirtualAddress)
    if len(sections) != count:
        raise ValueError("truncated section table")
    previous_end = header.SizeOfHeaders
    for section in sections:
        size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        start = section.VirtualAddress
        if start % section_alignment or start < previous_end or start + size > header.SizeOfImage:
            raise ValueError("unaligned, overlapping, or out-of-image section")
        previous_end = start + align_up(size, section_alignment)
        if previous_end > header.SizeOfImage:
            raise ValueError("aligned section exceeds SizeOfImage")

    output = bytearray(read(0, header.SizeOfHeaders))
    output.extend(bytes(align_up(len(output), file_alignment) - len(output)))
    raw_header_size = len(output)
    iat = header.DATA_DIRECTORY[12]
    section_table = nt_offset + 24 + optional_size
    for index, section in enumerate(sections):
        data = read(section.VirtualAddress, max(section.Misc_VirtualSize, section.SizeOfRawData))
        last_nonzero = len(data.rstrip(b"\0"))
        kept = min(len(data), last_nonzero + 4) if last_nonzero else 0
        raw_size = align_up(kept, file_alignment)
        offset = len(output) if raw_size else 0
        section.SizeOfRawData = raw_size
        section.PointerToRawData = offset

        section.PointerToRelocations = section.PointerToLinenumbers = 0
        section.NumberOfRelocations = section.NumberOfLinenumbers = 0
        if iat.VirtualAddress and (
            section.VirtualAddress <= iat.VirtualAddress < section.VirtualAddress + max(section.Misc_VirtualSize, len(data))
        ):
            section.Characteristics |= 0xC0000000
        location = section_table + index * 40
        output[location:location + 40] = section.__pack__()
        output.extend(data[:kept])
        output.extend(bytes(raw_size - kept))

    def set_field(name, value):
        write_u32(output, header.get_field_absolute_offset(name), value)

    set_field("SizeOfHeaders", raw_header_size)
    set_field("SizeOfImage", previous_end)
    for index in (4, 6, 11, 12):
        struct.pack_into("<II", output, header.DATA_DIRECTORY[index].get_file_offset(), 0, 0)
    struct.pack_into("<II", output, pe.FILE_HEADER.get_field_absolute_offset("PointerToSymbolTable"), 0, 0)
    checked = parse_pe(bytes(output))
    set_field("CheckSum", checked.generate_checksum())
    return bytes(output)
