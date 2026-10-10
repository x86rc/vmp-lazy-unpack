import struct

from .binary import encode_u32, read_u32, read_u64
from .discover import transform
from .imports import number
from .pe import file_offset


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


def validate_metadata(data, pe, record):
    offset = file_offset(pe, number(record['record_rva']), 12)
    _, slot, key = struct.unpack_from('<IIi', data, offset)
    return slot == number(record['slot_rva']) and key == record['key']


class XorImportDecoder:
    def __init__(self, image_base, module_bases, catalog, string_keys, *, require_initialized=True,
                 slot_size=8):
        self.base = image_base
        self.module_bases = module_bases
        self.catalog = catalog
        self.string_keys = string_keys
        self.require_initialized = require_initialized
        self.slot_size = slot_size

    def recover(self, image):
        tables = []
        slots = {}
        seen_tables = set()
        for module, module_base in sorted(self.module_bases.items()):
            exports = self.catalog.exports(module)
            by_name = {item["name"]: item["ordinal"] for item in exports if item["name"]}
            ordinals = {item["ordinal"] for item in exports}
            spellings = {module, module.upper(), module.capitalize(),
                         module.rsplit(".", 1)[0].upper() + ".dll"}
            for string_key in self.string_keys:
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
                                if slot + self.slot_size > len(image):
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
                                stored = read_u64(image, slot) if self.slot_size == 8 else read_u32(image, slot)
                                if self.require_initialized and (stored + key) & ((1 << (self.slot_size * 8)) - 1) != expected:
                                    break
                                records.append({"module": module, "symbol": symbol, "slot_rva": slot,
                                                "slot_va": self.base + slot, "emu_address": expected,
                                                "encoded_value": stored, "key": key,
                                                "record_rva": cursor, "table_rva": table_rva,
                                                "source": "encoded_import_table" if self.require_initialized else "static_import_metadata",
                                                "encoding": "subtract_signed_i32"})
                                cursor += 12
                            if not valid:
                                continue
                            seen_tables.add(table_rva)
                            for record in records:
                                slot = record["slot_rva"]
                                if slot in slots and (slots[slot]["emu_address"], slots[slot]["key"]) != (record["emu_address"], record["key"]):
                                    raise ValueError("clashing encoded imports")
                                slots.setdefault(slot, record)
                            tables.append({"rva": table_rva, "end_rva": cursor + 4,
                                           "module": module, "string_key": string_key, "count": len(records)})
        return {"tables": sorted(tables, key=lambda table: table["rva"]),
                "imports": sorted(slots.values(), key=lambda record: record["slot_rva"])}
