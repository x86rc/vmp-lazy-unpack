import struct
from .binary import encode_u32, read_u32, read_u64
from .discover import transform


def decode_name(image, rva, key, limit=256):
    if not 0 < rva < len(image):
        return None
    data = transform(image[rva:min(rva + limit, len(image))], key)
    end = data.find(b"\0")
    if end <= 0 or any(value < 32 or value > 126 for value in data[:end]):
        return None
    return data[:end].decode("ascii")


def find_all(data, pattern):
    cursor = 0
    while (cursor := data.find(pattern, cursor)) >= 0:
        yield cursor
        cursor += 1


def recover_encoded_imports(image, image_base, module_bases, catalog, string_keys, *, require_initialized=True):
    tables = []
    slots = {}
    seen_tables = set()
    for module, module_base in sorted(module_bases.items()):
        exports = catalog.exports(module)
        by_name = {item["name"]: item["ordinal"] for item in exports if item["name"]}
        ordinals = {item["ordinal"] for item in exports}
        spellings = {module, module.upper(), module.capitalize(),
                     module.rsplit(".", 1)[0].upper() + ".dll"}
        for string_key in string_keys:
            for spelling in spellings:
                for name_rva in find_all(image, transform(spelling.encode("ascii") + b"\0", string_key)):
                    for table_rva in find_all(image, encode_u32(name_rva)):
                        if table_rva in seen_tables:
                            continue
                        records = []
                        cursor = table_rva + 4
                        valid = False
                        for _ in range(4096):
                            if cursor + 4 > len(image):
                                break
                            name = read_u32(image, cursor)
                            if name == 0:
                                valid = bool(records)
                                break
                            if cursor + 12 > len(image):
                                break
                            name, slot, key = struct.unpack_from("<IIi", image, cursor)
                            if slot + 8 > len(image):
                                break
                            if name & 0x80000000:
                                ordinal = name & 0x7fffffff
                                symbol = f"ordinal_{ordinal}"
                            else:
                                symbol = decode_name(image, name, string_key)
                                ordinal = by_name.get(symbol)
                            if ordinal not in ordinals or ordinal < 1:
                                break

                            expected = module_base + 0x40000 + (ordinal - 1) * 16
                            stored = read_u64(image, slot)
                            if require_initialized and (stored + key) & 0xffffffffffffffff != expected:
                                break
                            records.append({"module": module, "symbol": symbol, "slot_rva": slot,
                                            "slot_va": image_base + slot, "emu_address": expected,
                                            "encoded_value": stored, "key": key,
                                            "record_rva": cursor, "table_rva": table_rva,
                                            "source": "encoded_import_table" if require_initialized else "static_import_metadata",
                                            "encoding": "subtract_signed_i32"})
                            cursor += 12
                        if not valid:
                            continue
                        seen_tables.add(table_rva)
                        for record in records:
                            slot = record["slot_rva"]
                            if slot in slots and (slots[slot]["emu_address"], slots[slot]["key"]) != (record["emu_address"], record["key"]):
                                raise ValueError("conflicting encoded-import evidence")
                            slots.setdefault(slot, record)
                        tables.append({"rva": table_rva, "end_rva": cursor + 4,
                                       "module": module, "string_key": string_key, "count": len(records)})
    return {"tables": sorted(tables, key=lambda table: table["rva"]),
            "imports": sorted(slots.values(), key=lambda record: record["slot_rva"])}
