from .binary import encode_u32, read_u32, write_u32
from .pe import file_offset, parse_pe


def repair_exception_tables(data):
    pe = parse_pe(data)
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    report = {"runtime_functions": 0, "unwind_records": 0, "handlers": 0,
              "chains": 0, "pdata_restored": 0, "pdata_status": "absent",
              "prologue_offset_mismatches": 0, "dropped_count": 0, "dropped_entries": []}
    if not directory.VirtualAddress and not directory.Size:
        return data, report
    if not directory.VirtualAddress or not directory.Size or directory.Size % 12 or directory.VirtualAddress % 4:
        raise ValueError("invalid exception directory")

    protected = []

    def read(rva, size):
        offset = file_offset(pe, rva, size)
        protected.append((rva, rva + size))
        return data[offset:offset + size]

    def code_range_error(begin, end):
        if begin >= end:
            return f"end RVA 0x{end:X} is not greater than the start"
        section = pe.get_section_by_rva(begin)
        if section is None:
            return "start is outside image sections"
        name = section.Name.rstrip(b'\0').decode('ascii', errors='replace')
        if not section.Characteristics & 0x20000000:
            return f"section {name!r} is not executable (characteristics 0x{section.Characteristics:X})"
        section_end = section.VirtualAddress + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if end > section_end:
            return f"end RVA 0x{end:X} exceeds section {name!r} ending at 0x{section_end:X}"
        return None

    def row(blob, offset=0, record_rva=None):
        result = tuple(read_u32(blob, offset + i) for i in (0, 4, 8))
        begin, end, unwind = result
        reason = code_range_error(begin, end)
        if reason is None and not unwind:
            reason = "unwind RVA is zero"
        if reason is None and unwind % 4:
            reason = f"unwind RVA 0x{unwind:X} is not four-byte aligned"
        if reason:
            location = f", record RVA 0x{record_rva:X}" if record_rva is not None else ""
            raise ValueError(f"invalid runtime function at RVA 0x{begin:X} "
                             f"(end 0x{end:X}, unwind 0x{unwind:X}{location}): {reason}")
        return result

    table = read(directory.VirtualAddress, directory.Size)
    visited = set()

    def validate_chain(root):
        unwind = root
        path = set()
        while unwind not in visited:
            if unwind in path:
                raise ValueError(f"unwind chain cycle at RVA 0x{unwind:X}")
            path.add(unwind)
            version_flags, prologue, count, frame = read(unwind, 4)
            version, flags = version_flags & 7, version_flags >> 3
            if version not in (1, 2):
                raise ValueError(f"unsupported unwind version {version} at RVA 0x{unwind:X}")
            if flags > 7 or flags & 4 and flags & 3:
                raise ValueError(f"invalid unwind flags at RVA 0x{unwind:X}")
            if (frame & 15) not in (0, 3, 5, 6, 7, 12, 13, 14, 15) or not frame & 15 and frame >> 4:
                raise ValueError(f"invalid unwind frame register at RVA 0x{unwind:X}")
            codes = read(unwind + 4, ((count + 1) & ~1) * 2) if count else b""
            index = 0
            previous = 255
            prologue_mismatch = False
            while index < count:
                offset, encoded = codes[index * 2:index * 2 + 2]
                operation, info = encoded & 15, encoded >> 4
                slots = {0: 1, 1: 2 if info == 0 else 3, 2: 1, 3: 1,
                         4: 2, 5: 3, 6: 1, 8: 2, 9: 3, 10: 1}.get(operation)
                if (slots is None or index + slots > count or operation == 1 and info > 1
                        or operation == 3 and not frame & 15
                        or operation == 10 and info > 1 or operation == 6 and version != 2):
                    raise ValueError(f"invalid unwind opcode at RVA 0x{unwind:X}")
                if operation != 6:
                    if offset > previous:
                        raise ValueError(f"unordered unwind codes at RVA 0x{unwind:X}")
                    previous = offset
                    prologue_mismatch |= offset > prologue
                index += slots
            report["prologue_offset_mismatches"] += prologue_mismatch
            tail = unwind + 4 + len(codes)
            if flags & 4:
                _, _, unwind = row(read(tail, 12), record_rva=tail)
                report["chains"] += 1
            else:
                if flags & 3:
                    handler = read_u32(read(tail, 4))
                    reason = code_range_error(handler, handler + 1)
                    if reason:
                        raise ValueError(f"invalid exception handler RVA 0x{handler:X} "
                                         f"(unwind RVA 0x{unwind:X}): {reason}")
                    handler_section = pe.get_section_by_rva(tail)
                    protected.append((tail, handler_section.VirtualAddress + max(
                        handler_section.Misc_VirtualSize, handler_section.SizeOfRawData)))
                    report["handlers"] += 1
                break
        return path

    rows = []
    for offset in range(0, len(table), 12):
        counts = {key: report[key] for key in ('chains', 'handlers', 'prologue_offset_mismatches')}
        try:
            entry = row(table, offset, directory.VirtualAddress + offset)
            path = validate_chain(entry[2])
        except ValueError as exc:
            report.update(counts)
            report['dropped_entries'].append({
                'record_rva': directory.VirtualAddress + offset,
                'begin_rva': read_u32(table, offset),
                'end_rva': read_u32(table, offset + 4),
                'unwind_rva': read_u32(table, offset + 8),
                'error': str(exc),
            })
            continue
        rows.append(entry)
        visited.update(path)

    ordered = sorted(rows)
    overlaps = sum(left[1] > right[0] for left, right in zip(ordered, ordered[1:]))
    if overlaps and rows != ordered:
        raise ValueError("cannot reorder overlapping runtime functions")
    report['overlapping_ranges'] = overlaps
    report['dropped_count'] = len(report['dropped_entries'])

    output = bytearray(data)
    table_offset = file_offset(pe, directory.VirtualAddress, directory.Size)
    packed = b"".join(encode_u32(value) for entry in ordered for value in entry)
    output[table_offset:table_offset + len(packed)] = packed
    write_u32(output, directory.get_field_absolute_offset('Size'), len(packed))
    if not ordered:
        write_u32(output, directory.get_field_absolute_offset('VirtualAddress'), 0)
    if report['dropped_count']:
        report['status'] = 'filtered' if ordered else 'cleared'
    report.update(runtime_functions=len(rows), unwind_records=len(visited),
                  table_sorted=rows != ordered, directory_rva=directory.VirtualAddress if ordered else 0)
    candidates = [s for s in pe.sections if s.Name.rstrip(b"\0") == b".pdata"]
    for section in candidates:
        start, size = section.VirtualAddress, section.Misc_VirtualSize
        end = start + size
        report["pdata_status"] = "preserved"
        native = [entry for entry in ordered if entry[1] <= start]
        if (len(candidates) != 1 or not size or size % 12 or len(native) * 12 != size
                or section.Characteristics & 0xA0000000 or size > section.SizeOfRawData
                or any(start < right and left < end for left, right in protected)
                or any(d.VirtualAddress < end and start < d.VirtualAddress + d.Size
                       for i, d in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY) if i != 4 and d.Size)):
            continue
        offset = file_offset(pe, start, size)
        old = data[offset:offset + size]
        plausible = False
        for index in range(0, size, 12):
            try:
                row(old, index)
                plausible = True
                break
            except ValueError:
                pass
        if plausible:
            continue
        output[offset:offset + size] = b"".join(encode_u32(value) for entry in native for value in entry)
        report.update(pdata_restored=len(native), pdata_status="restored_native_copy", pdata_rva=start)
    if output != data:
        checked = parse_pe(bytes(output))
        write_u32(output, checked.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum"), checked.generate_checksum())
    return bytes(output), report
