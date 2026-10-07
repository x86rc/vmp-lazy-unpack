import argparse
import json
from pathlib import Path

from .binary import write_u64
from .catalog import Catalog
from .discover import recover_keys
from .encoded_imports import recover_encoded_imports
from .imports import import_slots, number
from .pe import file_offset, memory_image, parse_pe
from .reconstruct import reconstruct_imports


def resolve_static_imports(data, catalog, string_keys=None):
    pe = parse_pe(data)
    base = pe.OPTIONAL_HEADER.ImageBase
    keys = list(recover_keys(data) if string_keys is None else string_keys)
    if not keys:
        raise ValueError('no string key found')
    modules = set(catalog.modules)
    for name in catalog.document.get('api_sets', {}):
        try:
            catalog.exports(name)
        except ValueError:
            continue
        modules.add(name)
    modules = sorted(modules)
    module_bases = {name: 0x7FFA00000000 + index * 0x200000 for index, name in enumerate(modules)}
    recovered = recover_encoded_imports(memory_image(data), base, module_bases, catalog, keys,
                                        require_initialized=False)
    if not recovered['imports']:
        raise ValueError('no iat found')

    prepared = bytearray(data)
    records = []
    occupied = set()
    metadata = {byte for table in recovered['tables']
                for byte in range(table['rva'], table['end_rva'])}
    for record in recovered['imports']:
        slot = record['slot_rva']
        covered = set(range(slot, slot + 8))
        if covered & (occupied | metadata):
            raise ValueError('import slots overlap each other or table metadata')
        occupied.update(covered)
        offset = file_offset(pe, slot, 8)
        value = (record['emu_address'] - record['key']) & 0xffffffffffffffff
        write_u64(prepared, offset, value)
        records.append({**record, 'encoded_value': value})
    bootstrap = [dict(slot_rva=slot, module=module, symbol=symbol)
                 for slot, (module, symbol) in import_slots(pe).items()]
    evidence = dict(image_base=base, bootstrap_iat=bootstrap, resolved_imports=[],
                    recovered_iat=[], encoded_imports=records)
    ranges = [(s.VirtualAddress, s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData))
              for s in pe.sections]
    output, reconstruction = reconstruct_imports(bytes(prepared), evidence, ranges)
    return output, {
        'string_keys': keys,
        'tables': recovered['tables'],
        'imports': recovered['imports'],
        'reconstruction': reconstruction,
    }


def import_metadata(output, report):
    pe = parse_pe(output)
    base = pe.OPTIONAL_HEADER.ImageBase
    records = {record['slot_rva']: record for record in report['imports']}
    slots = {}
    reconstruction = report['reconstruction']
    for patch in reconstruction['plain_slot_patches'] + reconstruction['encoded_slot_patches']:
        rva = number(patch['slot_rva'])
        slot = {key: value for key, value in patch.items()
                if key not in ('module', 'symbol', 'iat_va')}
        slot['slot_va'] = hex(base + rva)
        record = records.get(rva)
        if record:
            slot.update({key: value for key, value in record.items()
                         if key not in ('module', 'symbol', 'source', 'encoded_value')})
            slot['old_value'] = record['encoded_value']
        for key in ('slot_rva', 'slot_va', 'old_value', 'new_value', 'file_offset',
                    'emu_address', 'record_rva', 'table_rva'):
            if key in slot:
                slot[key] = hex(number(slot[key]))
        slots.setdefault(number(patch['iat_va']), []).append(slot)
    imports = {}
    for rva, (module, symbol) in sorted(import_slots(pe).items()):
        imports.setdefault(module, {'tables': {}, 'imports': []})['imports'].append(dict(
            symbol=symbol, iat_rva=hex(rva), iat_va=hex(base + rva),
            slots=sorted(slots.get(base + rva, []), key=lambda slot: number(slot['slot_rva']))))
    for table in report['tables']:
        imports[table['module']]['tables'][hex(table['rva'])] = dict(
            end_rva=hex(table['end_rva']), string_key=table['string_key'])
    return imports


def run_static_imports(input_path, output_path):
    report_path = output_path.with_suffix(output_path.suffix + '.imports.json')
    catalog_path = Path(__file__).resolve().parent.parent / 'catalog'
    data = input_path.read_bytes()
    output, report = resolve_static_imports(data, Catalog(catalog_path))
    imports = import_metadata(output, report)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(output)
    with report_path.open('w', encoding='utf-8') as stream:
        json.dump(imports, stream, indent=2)
    from .tracer import print_resolution_counts
    print(f"{sum(len(module['imports']) for module in imports.values())} iat entries")
    print_resolution_counts(report['reconstruction'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path, help='output bin')
    args = parser.parse_args()
    try:
        run_static_imports(args.input, args.output)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
