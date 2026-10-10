import struct

from .imports import number
from .pe import file_offset


MASK32 = 0xffffffff


def rotate(value, count):
    return ((value << count) | (value >> (32 - count))) & MASK32


def advance(a, b):
    total = (a + b) & MASK32
    middle = (total + (rotate(b, 5) ^ total)) & MASK32
    mixed = (middle + (rotate(total, 13) ^ middle)) & MASK32
    return (a + mixed) & MASK32, (b + (rotate(middle, 17) ^ mixed)) & MASK32


def decode_words(image, offset, state, count):
    a, b = state
    words = []
    for _ in range(count):
        words.append(struct.unpack_from('<I', image, offset)[0] ^ a ^ b)
        offset += 4
        a, b = advance(a, b)
    return words, (offset, (a, b))


def signed(value):
    return value if value < 0x80000000 else value - 0x100000000


def validate_metadata(data, pe, record):
    state = tuple(number(value) for value in record['metadata_state'])
    if len(state) != 2 or any(not 0 <= value <= MASK32 for value in state):
        raise ValueError('invalid arx import state')
    source = record['source']
    if source == 'arx_import_table':
        offset = file_offset(pe, number(record['record_rva']), 12)
        (_, slot, key), _ = decode_words(data, offset, state, 3)
        return slot == number(record['slot_rva']) and signed(key) == record['key']
    if source == 'arx_import_write':
        offset = file_offset(pe, number(record['record_rva']), 4)
        (key,), _ = decode_words(data, offset, state, 1)
        return signed(key) == record['key']
    raise ValueError('unknown arx import source')


class ArxImportDecoder:
    def __init__(self, image_base, image_end, arch, targets):
        self.base = image_base
        self.end = image_end
        self.arch = arch
        self.targets = targets
        self.observations = []
        self.seen = set()
        self.target_range = (min(targets), max(targets)) if targets else None

    def observe(self, uc, access, address, size, value, user):
        if self.arch.bits != 64 or size != 8 or self.target_range is None:
            return
        value &= self.arch.mask
        low, high = self.target_range
        if not self.base <= address <= self.end - 8 or value in self.targets or not (
                low - 0x7fffffff <= value <= high + 0x80000000):
            return
        stack = uc.reg_read(self.arch.sp)
        stack_end = self.arch.stack_base + self.arch.stack_size
        if not self.arch.stack_base <= stack < stack_end:
            return
        stack_bytes = bytes(uc.mem_read(stack, stack_end - stack))
        registers = tuple(uc.reg_read(reg) for _, reg in self.arch.gpr)
        observation = (address - self.base, value, stack_bytes, registers)
        if observation in self.seen:
            return
        self.seen.add(observation)
        self.observations.append(dict(slot_rva=observation[0], encoded_value=value,
            stack=stack_bytes, registers=list(registers)))

    def record(self, image, slot, key, api, offset, state, source):
        module, symbol = self.targets[api].split('!', 1)
        return dict(module=module, symbol=symbol, slot_rva=slot, slot_va=self.base + slot,
                    emu_address=api, encoded_value=struct.unpack_from('<Q', image, slot)[0],
                    key=key, encoding='subtract_signed_i32', metadata_encoding='arx32',
                    record_rva=offset, metadata_state=list(state), source=source)

    def row(self, image, offset, state):
        if offset + 12 > len(image):
            return None
        (name, slot, key), after = decode_words(image, offset, state, 3)
        if not 0 < name < len(image) or not 0 < slot <= len(image) - 8:
            return None
        key = signed(key)
        api = (struct.unpack_from('<Q', image, slot)[0] + key) & self.arch.mask
        if api not in self.targets:
            return None
        return self.record(image, slot, key, api, offset, state, 'arx_import_table'), after

    def candidates(self, image, observation):
        stack = observation['stack']
        registers = observation['registers']
        qwords = {struct.unpack_from('<Q', stack, i)[0] for i in range(len(stack) - 7)}
        qwords.update(registers)
        dwords = {struct.unpack_from('<I', stack, i)[0] for i in range(len(stack) - 3)}
        dwords.update(value & MASK32 for value in registers)
        pointers = {value - self.base for value in qwords
                    if self.base <= value <= self.base + len(image) - 24}
        apis = qwords & self.targets.keys()
        matches = []
        for offset in pointers:
            cipher = struct.unpack_from('<I', image, offset + 8)[0]
            for api in apis:
                key = api - observation['encoded_value']
                if not -(1 << 31) <= key < (1 << 31):
                    continue
                mask = cipher ^ (key & MASK32)
                for a in dwords:
                    b = a ^ mask
                    if b not in dwords or self.row(image, offset + 12, advance(a, b)) is None:
                        continue
                    matches.append(self.record(image, observation['slot_rva'], key, api,
                                               offset + 8, (a, b), 'arx_import_write'))
                    if len(matches) > 1:
                        return []
        return matches

    def suffix(self, image, first):
        records = [first]
        offset = first['record_rva'] + 4
        state = advance(*first['metadata_state'])
        while True:
            decoded = self.row(image, offset, state)
            if decoded is not None:
                record, (offset, state) = decoded
                records.append(record)
                continue
            if offset + 8 > len(image):
                break
            (name, count), after = decode_words(image, offset, state, 2)
            if not 0 < name < len(image) or not 0 < count <= (len(image) - offset - 8) // 12:
                break
            group = []
            for _ in range(count):
                decoded = self.row(image, *after)
                if decoded is None:
                    break
                record, after = decoded
                group.append(record)
            if len(group) != count or len({record['module'] for record in group}) != 1:
                break
            records.extend(group)
            offset, state = after
        return records, offset

    def recover(self, image):
        records, tables = {}, []
        if self.arch.bits != 64:
            return dict(tables=tables, imports=[])
        for observation in self.observations:
            slot = observation['slot_rva']
            if slot in records or struct.unpack_from('<Q', image, slot)[0] != observation['encoded_value']:
                continue
            matches = self.candidates(image, observation)
            if not matches:
                continue
            recovered, end = self.suffix(image, matches[0])
            for record in recovered:
                slot = record['slot_rva']
                if slot in records and any(records[slot][key] != record[key]
                                           for key in ('module', 'symbol', 'key', 'emu_address')):
                    raise ValueError('clashing arx imports at slot')
                records.setdefault(slot, record)
            tables.append(dict(rva=matches[0]['record_rva'], end_rva=end, count=len(recovered)))
        return dict(tables=tables, imports=sorted(records.values(), key=lambda record: record['slot_rva']))
