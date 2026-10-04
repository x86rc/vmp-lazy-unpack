def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def import_slots(pe):
    result = {}
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        module = descriptor.dll.decode("ascii").lower()
        for item in descriptor.imports:

            symbol = item.ordinal if item.import_by_ordinal else item.name.decode("ascii")
            result[item.address - pe.OPTIONAL_HEADER.ImageBase] = (module, symbol)
    return result
