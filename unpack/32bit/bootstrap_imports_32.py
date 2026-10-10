from ..binary import read_u32, write_u32
from ..pe import file_offset, parse_pe
from ..reconstruct import (prepare_import_storage, extend_import_storage, identity,
                          IMPORT_STORAGE_CHARACTERISTICS)


def classify_scanned_imports(bootstrap, scanned, restored_ranges):
    bootstrap_keys = {identity(record) for record in bootstrap}
    recovered, additional = [], []
    for record in scanned:
        if identity(record) in bootstrap_keys:
            recovered.append(record)
        elif any(start <= record['slot_va'] and record['slot_va'] + 4 <= end
                 for start, end, _ in restored_ranges):
            additional.append(record)
    return recovered, additional


def preserve_import_lookups(data, original):
    descriptors = [item for item in getattr(original, 'DIRECTORY_ENTRY_IMPORT', [])
                   if not item.struct.OriginalFirstThunk]
    if not descriptors:
        return data
    prepared, storage = prepare_import_storage(data)
    pe = parse_pe(prepared)
    if pe.OPTIONAL_HEADER.ImageBase != original.OPTIONAL_HEADER.ImageBase:
        raise ValueError('import image base differs')
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress != original.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress:
        raise ValueError('import directory differs')
    output, content = bytearray(prepared), bytearray()
    for descriptor in descriptors:
        source = descriptor.struct
        rva = original.get_rva_from_offset(source.get_file_offset())
        offset = file_offset(pe, rva, 20)
        if (read_u32(prepared, offset + 12), read_u32(prepared, offset + 16)) != (source.Name, source.FirstThunk):
            raise ValueError('import descriptor differs')
        if read_u32(prepared, offset):
            continue
        size = (len(descriptor.imports) + 1) * 4
        lookup = original.get_data(source.FirstThunk, size)
        if len(lookup) != size or read_u32(lookup, size - 4):
            raise ValueError('original import lookup truncated')
        write_u32(output, offset, storage['payload_rva'] + len(content))
        content.extend(lookup)
    if not content:
        return data
    extend_import_storage(output, pe, storage, content, IMPORT_STORAGE_CHARACTERISTICS)
    write_u32(output, pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'), 0)
    parse_pe(bytes(output))
    return bytes(output)
