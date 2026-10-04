from typing import NamedTuple


class ModuleImage(NamedTuple):
    name: str
    base: int
    size: int
    entry: int
    path: str


class ImportWrite(NamedTuple):
    target: int
    writer: int
    block_count: int
    write_count: int


class Event(NamedTuple):
    kind: str
    address: int
    instruction_count: int
    details: dict


HEX_FIELDS = frozenset((
    'address', 'base', 'decoder', 'destination', 'source', 'target', 'result',
    'image_base', 'image_end', 'entry', 'entry_rva', 'rva', 'end_rva',
    'slot_va', 'slot_rva', 'emu_address', 'writer_va', 'last_writer_va',
    'first_slot_rva', 'last_slot_rva', 'record_rva', 'table_rva', 'return_address',
    'memory_address', 'peb_offset', 'syscall_number', 'state_xor', 'string_key',
    'encoded_value', 'old_value', 'new_value', 'table', 'handle', 'file_handle', 'section_handle', 'value',
    'allocation', 'protection', 'status', 'section_attributes', 'view',
    'written_destination_pages',
))
REGISTER_FIELDS = frozenset((
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip', 'rflags',
))


def format_report(value, field=None):
    if isinstance(value, Event):
        value = value._asdict()
    if isinstance(value, dict):
        if field == 'emu_modules':
            return {key: format_report(item, 'base' if type(item) is int else key)
                    for key, item in value.items()}
        return {key: format_report(item, key) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [format_report(item, field) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if type(value) is int:
        if field in REGISTER_FIELDS:
            return f"0x{value:016X}"
        if field in HEX_FIELDS:
            return f"0x{value:X}"
    return value
