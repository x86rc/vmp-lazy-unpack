import pefile

IMAGE_FILE_HEADER = pefile.PE.__IMAGE_FILE_HEADER_format__
IMAGE_EXPORT_DIRECTORY = pefile.PE.__IMAGE_EXPORT_DIRECTORY_format__
IMAGE_IMPORT_DESCRIPTOR = pefile.PE.__IMAGE_IMPORT_DESCRIPTOR_format__
IMAGE_DATA_DIRECTORY = pefile.PE.__IMAGE_DATA_DIRECTORY_format__
IMAGE_OPTIONAL_HEADER64 = pefile.PE.__IMAGE_OPTIONAL_HEADER64_format__
IMAGE_SECTION_HEADER = pefile.PE.__IMAGE_SECTION_HEADER_format__


def write_pe_structure(data, offset, layout, **fields):
    record = pefile.Structure(layout)
    size = record.sizeof()
    if offset < 0 or offset + size > len(data):
        raise ValueError(f"{record.name} exceeds buffer bounds")
    record.__unpack__(bytes(size))
    for name, value in fields.items():
        if name not in record.__field_offsets__:
            raise ValueError(f"Unknown {record.name} field: {name}")
        setattr(record, name, value)
    data[offset:offset + size] = record.__pack__()


def align_up(value, alignment):
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError("alignment must be a positive power of two")
    return (value + alignment - 1) & -alignment


def parse_pe(data):
    pe = pefile.PE(data=data, fast_load=False)
    if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
        raise ValueError("only AMD64 PE32+ is supported")
    size = pe.OPTIONAL_HEADER.SizeOfImage
    if size <= 0:
        raise ValueError("invalid image size")
    headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    if not 0 < headers <= min(len(data), size):
        raise ValueError("invalid or truncated headers")
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) < 16:
        raise ValueError("a full PE data-directory table is required")
    if len(pe.sections) != pe.FILE_HEADER.NumberOfSections or not pe.sections:
        raise ValueError("missing or truncated section table")
    if any(section.get_file_offset() + 40 > headers for section in pe.sections):
        raise ValueError("section table extends past SizeOfHeaders")
    align_up(0, pe.OPTIONAL_HEADER.FileAlignment)
    align_up(0, pe.OPTIONAL_HEADER.SectionAlignment)
    ranges = []
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start < headers or end > size:
            raise ValueError("section lies outside image or overlaps headers")
        if any(start < right and left < end for left, right in ranges):
            raise ValueError("overlapping sections are not supported")
        ranges.append((start, end))
        if section.SizeOfRawData:
            if section.PointerToRawData < headers or section.PointerToRawData + section.SizeOfRawData > len(data):
                raise ValueError("invalid or truncated section data")
    return pe


def memory_image(data):
    pe = parse_pe(data)
    image = bytearray(pe.OPTIONAL_HEADER.SizeOfImage)
    headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    image[:headers] = data[:headers]
    for section in pe.sections:
        start = section.VirtualAddress
        image[start:start + section.SizeOfRawData] = section.get_data()
    return bytes(image)


def file_offset(pe, rva, size):

    for section in pe.sections:
        delta = rva - section.VirtualAddress
        if 0 <= delta and delta + size <= section.SizeOfRawData:
            return section.PointerToRawData + delta
    raise ValueError(f"RVA 0x{rva:X} is not backed by section data")
