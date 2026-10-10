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


def import_address_metadata(pe, report):
    base = pe.OPTIONAL_HEADER.ImageBase
    if number(report['image_base']) != base:
        raise ValueError('import report and output image bases differ')
    addresses = {}
    for category in ('bootstrap_iat', 'resolved_imports', 'recovered_iat', 'encoded_imports', 'wrapper_imports'):
        for record in report.get(category, []):
            symbol = record['symbol']
            if isinstance(symbol, str) and symbol.startswith('ordinal_'):
                symbol = int(symbol.split('_', 1)[1], 0)
            key = (record['module'].lower(), symbol)
            addresses.setdefault(key, set()).add(number(record['emu_address']))
    imports = {}
    module_names = {}
    for descriptor in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        module = descriptor.dll.decode('ascii')
        module = module_names.setdefault(module.lower(), module)
        entries = imports.setdefault(module, [])
        for item in descriptor.imports:
            symbol = item.ordinal if item.import_by_ordinal else item.name.decode('ascii')
            targets = addresses.get((module.lower(), symbol))
            if not targets:
                raise ValueError(f'missing runtime import address for {module} {symbol}')
            if len(targets) != 1:
                raise ValueError(f'clashing runtime import addresses for {module} {symbol}')
            entries.append(dict(symbol=symbol, iat_rva=hex(item.address - base),
                                iat_va=hex(item.address), runtime_address=hex(next(iter(targets)))))
    return dict(image_base=hex(base), imports=imports)
