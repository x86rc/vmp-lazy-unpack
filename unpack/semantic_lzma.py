from collections import deque
from copy import copy
from dataclasses import dataclass, field

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .arch import arch_of
from .semantic_crc import ROOTS


def bounded(value):
    pending = [value]
    count = 0
    while pending:
        item = pending.pop()
        if isinstance(item, tuple):
            count += 1
            if count > 64:
                return ('unknown', object())
            pending.extend(item[1:])
    return value


def expression(op, left, right):
    if isinstance(left, int) and isinstance(right, int):
        if op == 'add': return left + right
        if op == 'sub': return left - right
        if op == 'mul': return left * right
        if op == 'and': return left & right
        if op == 'or': return left | right
        if op == 'xor': return left ^ right
        if op == 'shl': return left << (right & 63)
        if op == 'shr': return left >> (right & 63)
    if op in ('add', 'sub', 'or', 'xor') and right == 0:
        return left
    if op == 'mul' and right == 1:
        return left
    if op in ('sub', 'xor') and left == right:
        return 0
    result = bounded((op, left, right))
    if is_node(result, 'unknown'):
        return result
    if op in ('add', 'mul', 'and', 'or', 'xor') and repr(left) > repr(right):
        left, right = right, left
    return op, left, right


def is_node(value, op):
    return isinstance(value, tuple) and value[0] == op


def low(value, bits):
    if isinstance(value, int):
        return value & ((1 << bits) - 1)
    if is_node(value, 'memory') and value[2] * 8 <= bits:
        return value
    if is_node(value, 'register') and value[2] * 8 <= bits:
        return value
    if is_node(value, 'low') and value[2] <= bits:
        return value
    if isinstance(value, tuple) and value[0] in ('add', 'sub', 'mul', 'and', 'or', 'xor'):
        operands = [part[1] if is_node(part, 'low') and part[2] == bits else part for part in value[1:]]
        value = expression(value[0], *operands)
    return ('low', value, bits)


def bound_parts(value):
    if not is_node(value, 'mul'):
        return None
    for shifted, probability in ((value[1], value[2]), (value[2], value[1])):
        if (is_node(shifted, 'shr') and shifted[2] == 11 and
                is_node(probability, 'memory') and probability[2] == 2):
            return shifted[1], probability
    return None


def normalized_source(code):
    if not isinstance(code, tuple) or code[0] not in ('or', 'add', 'xor'):
        return None
    for shifted, byte in ((code[1], code[2]), (code[2], code[1])):
        if is_node(shifted, 'shl') and shifted[2] == 8 and is_node(byte, 'memory') and byte[2] == 1:
            return byte[1]
    return None


def register_nodes(value):
    if is_node(value, 'register'):
        yield value
    elif isinstance(value, tuple):
        for part in value[1:]:
            yield from register_nodes(part)


@dataclass
class State:
    pc: int
    registers: dict = field(default_factory=dict)
    stack: dict = field(default_factory=dict)
    sp: int = 0
    comparison: object = None
    bit: object = None
    store: object = None
    visited: set = field(default_factory=set)

    def fork(self, pc):
        state = copy(self)
        state.pc = pc
        state.registers = dict(self.registers)
        state.stack = dict(self.stack)
        state.visited = set(self.visited)
        return state


class LzmaMatcher:
    def __init__(self, sections, mode=CS_MODE_64):
        self.sections = sections
        self.decoder = Cs(CS_ARCH_X86, mode)
        self.decoder.detail = True
        self.instructions = {}
        self.ptr = 4 if mode == CS_MODE_32 else 8

    def decode(self, address):
        if address not in self.instructions:
            data = next((raw[address - base:address - base + 15] for base, raw in self.sections
                         if base <= address < base + len(raw)), b'')
            self.instructions[address] = next(self.decoder.disasm(data, address, count=1), None)
        return self.instructions[address]

    def root(self, register):
        name = self.decoder.reg_name(register)
        return ROOTS.get(name, name)

    def reg(self, state, register, size=8):
        root = self.root(register)
        if root == 'rsp':
            return ('stack', state.sp)
        value = state.registers.get(root, ('register', root, size))
        shift = 8 if self.decoder.reg_name(register) in ('ah', 'bh', 'ch', 'dh') else 0
        while (is_node(value, 'partial') and value[4] <= shift and
               shift + size * 8 <= value[4] + value[3] * 8):
            shift -= value[4]
            value = value[2]
        if isinstance(value, int):
            return (value >> shift) & ((1 << (size * 8)) - 1)
        if shift:
            value = expression('shr', value, shift)
        if size < 4:
            return low(value, size * 8)
        return value

    def address(self, state, ins, operand):
        mem = operand.mem
        base = ins.address + ins.size if self.root(mem.base) == 'rip' else (
            self.reg(state, mem.base) if mem.base else 0)
        if is_node(base, 'stack') and not mem.index:
            return ('stack', base[1] + mem.disp)
        if mem.index:
            base = expression('add', base, expression('mul', self.reg(state, mem.index), mem.scale))
        return expression('add', base, mem.disp)

    def read(self, state, ins, operand):
        if operand.type == X86_OP_IMM:
            return operand.imm
        if operand.type == X86_OP_REG:
            return self.reg(state, operand.reg, operand.size)
        if operand.type == X86_OP_MEM:
            address = self.address(state, ins, operand)
            if is_node(address, 'stack'):
                return state.stack.get((address[1], operand.size), ('unknown', ins.address))
            return ('memory', address, operand.size, ins.address)
        return ('unknown', ins.address)

    def write(self, state, ins, operand, value):
        if operand.type == X86_OP_REG:
            root = self.root(operand.reg)
            if root == 'rsp':
                if not is_node(value, 'stack'):
                    return False
                state.sp = value[1]
            elif operand.size >= 4:
                state.registers[root] = value & ((1 << (operand.size * 8)) - 1) if isinstance(value, int) else value
            else:
                old = state.registers.get(root)
                if isinstance(old, int) and isinstance(value, int):
                    shift = 8 if self.decoder.reg_name(operand.reg) in ('ah', 'bh', 'ch', 'dh') else 0
                    mask = ((1 << (operand.size * 8)) - 1) << shift
                    state.registers[root] = (old & ~mask) | ((value << shift) & mask)
                else:
                    shift = 8 if self.decoder.reg_name(operand.reg) in ('ah', 'bh', 'ch', 'dh') else 0
                    state.registers[root] = bounded(('partial', old, value, operand.size, shift))
        elif operand.type == X86_OP_MEM:
            address = self.address(state, ins, operand)
            if is_node(address, 'stack'):
                start = address[1]
                for key in list(state.stack):
                    if start < key[0] + key[1] and key[0] < start + operand.size:
                        del state.stack[key]
                state.stack[(start, operand.size)] = value
            elif operand.size == 2 and state.bit:
                probability = state.bit['probability']
                if address == probability[1]:
                    state.store = (ins.address, value)
        return True

    def step(self, state, ins):
        ops, name = ins.operands, ins.mnemonic
        if name == 'pushfq':
            state.sp -= self.ptr
            state.stack[(state.sp, self.ptr)] = ('flags', state.comparison)
        elif name == 'popfq':
            flags = state.stack.get((state.sp, self.ptr))
            state.comparison = flags[1] if is_node(flags, 'flags') else None
            state.sp += self.ptr
            return True
        elif name == 'push' and len(ops) == 1:
            value = self.read(state, ins, ops[0])
            state.sp -= self.ptr
            state.stack[(state.sp, self.ptr)] = value
        elif name == 'pop' and len(ops) == 1:
            value = state.stack.get((state.sp, self.ptr), ('unknown', ins.address))
            state.sp += self.ptr
            if not self.write(state, ins, ops[0], value): return False
        elif name in ('mov', 'movabs', 'movzx', 'movsx', 'movsxd') and len(ops) == 2:
            value = self.read(state, ins, ops[1])
            if name in ('movsx', 'movsxd'):
                if isinstance(value, int):
                    bits = ops[1].size * 8
                    if value & (1 << (bits - 1)):
                        value -= 1 << bits
                else:
                    value = ('signed', value, ops[1].size)
            if not self.write(state, ins, ops[0], value): return False
        elif name == 'lea' and len(ops) == 2:
            if not self.write(state, ins, ops[0], self.address(state, ins, ops[1])): return False
        elif name == 'cmp' and len(ops) == 2:
            state.comparison = (self.read(state, ins, ops[0]), self.read(state, ins, ops[1]),
                                self.root(ops[0].reg) if ops[0].type == X86_OP_REG else None,
                                self.root(ops[1].reg) if ops[1].type == X86_OP_REG else None)
            return True
        elif name in ('add', 'sub', 'and', 'or', 'xor', 'shl', 'sal', 'shr', 'sar', 'imul') and len(ops) in (2, 3):
            left = self.read(state, ins, ops[1] if len(ops) == 3 else ops[0])
            right = self.read(state, ins, ops[-1])
            if name in ('shl', 'sal', 'shr', 'sar') and isinstance(right, int):
                right &= 63 if ops[0].size == 8 else 31
            if is_node(left, 'stack') and name in ('add', 'sub') and isinstance(right, int):
                value = ('stack', left[1] + right * (1 if name == 'add' else -1))
            else:
                op = {'sal': 'shl', 'sar': 'shr', 'imul': 'mul'}.get(name, name)
                value = expression(op, left, right)
            if not self.write(state, ins, ops[0], value): return False
        elif name in ('inc', 'dec') and len(ops) == 1:
            value = expression('add', self.read(state, ins, ops[0]), 1 if name == 'inc' else -1)
            if not self.write(state, ins, ops[0], value): return False
        elif name not in ('nop', 'clc', 'stc', 'cmc'):
            for register in ins.regs_access()[1]:
                root = self.root(register)
                if root == 'rsp': return False
                state.registers[root] = ('unknown', ins.address, root)
            if ops and ops[0].type == X86_OP_MEM and is_node(self.address(state, ins, ops[0]), 'stack'):
                self.write(state, ins, ops[0], ('unknown', ins.address))
        if any(self.decoder.reg_name(register) == 'rflags' for register in ins.regs_access()[1]):
            state.comparison = None
        return True

    def match(self, seed, budget=4096):
        root = self.root(seed.operands[0].reg)
        initial = ('register', root, seed.operands[0].size)
        pending = deque([State(seed.address, registers={root: initial})])
        found = {}
        steps = 0
        while pending and steps < budget:
            state = pending.pop()
            while steps < budget and state.pc not in state.visited:
                state.visited.add(state.pc)
                ins = self.decode(state.pc)
                if ins is None: break
                steps += 1
                next_pc = ins.address + ins.size
                if ins.mnemonic in ('jmp', 'call'):
                    target = self.read(state, ins, ins.operands[0])
                    if not isinstance(target, int): break
                    if ins.mnemonic == 'call':
                        state.sp -= self.ptr
                        state.stack[(state.sp, self.ptr)] = next_pc
                    state.pc = target
                    continue
                if ins.mnemonic == 'ret':
                    target = state.stack.get((state.sp, self.ptr))
                    if not isinstance(target, int): break
                    state.sp += self.ptr
                    state.pc = target
                    continue
                if ins.mnemonic.startswith('j'):
                    if not ins.operands or ins.operands[0].type != X86_OP_IMM: break
                    target = ins.operands[0].imm
                    comparison = state.comparison
                    taken = state.fork(target)
                    if comparison:
                        left, right, left_reg, right_reg = comparison
                        bound_on_right = bound_parts(right) is not None
                        bound, code, code_reg = (right, left, left_reg) if bound_on_right else (left, right, right_reg)
                        parts = bound_parts(bound)
                        lower = (ins.mnemonic == 'jb') if bound_on_right else (ins.mnemonic == 'ja')
                        valid = ins.mnemonic in (('jb', 'jae') if bound_on_right else ('ja', 'jbe'))
                        if parts and valid and code_reg and parts[0] == state.registers.get(root, initial):
                            bit = dict(branch=ins.address, probability=parts[1], bound=bound,
                                       range=parts[0], code=code, code_register=code_reg)
                            state.bit = dict(bit, side='one' if lower else 'zero')
                            taken.bit = dict(bit, side='zero' if lower else 'one')
                            state.store = taken.store = None
                    if target != next_pc and len(pending) < 128:
                        pending.append(taken)
                    state.pc = next_pc
                    continue
                if not self.step(state, ins): break
                if state.bit and state.store:
                    bit, (store, value) = state.bit, state.store
                    prob = bit['probability']
                    zero = expression('add', prob, expression('shr', expression('sub', 2048, prob), 5))
                    one = expression('sub', prob, expression('shr', prob, 5))
                    expected = low(zero if bit['side'] == 'zero' else one, 16)
                    if value == expected:
                        range_value = bit['bound'] if bit['side'] == 'zero' else expression('sub', bit['range'], bit['bound'])
                        code_value = bit['code'] if bit['side'] == 'zero' else expression('sub', bit['code'], bit['bound'])
                        if (state.registers.get(root) == range_value and
                                state.registers.get(bit['code_register'], ('register', bit['code_register'], 4)) == code_value):
                            row = found.setdefault(bit['branch'], dict(address=seed.address,
                                bound_branch=bit['branch'], range_register=root, code_register=bit['code_register'],
                                probability_load=prob[3]))
                            row[bit['side'] + '_store'] = store
                            source = normalized_source(bit['code'])
                            if source is not None and bit['range'] == expression('shl', initial, 8):
                                for register in register_nodes(source):
                                    if state.registers.get(register[1]) == expression('add', register, 1):
                                        row['normalization'] = True
                                        row['source_register'] = register[1]
                            break
                state.pc = next_pc
        return [row for row in found.values() if row.get('normalization') and
                'zero_store' in row and 'one_store' in row]


def discover_lzma_candidates(pe):
    base = pe.OPTIONAL_HEADER.ImageBase
    sections = [(base + s.VirtualAddress, s.get_data()[:s.Misc_VirtualSize])
                for s in pe.sections if s.Characteristics & 0x20000000]
    matcher = LzmaMatcher(sections, arch_of(pe).cs_mode)
    seeds = {}
    for address, data in sections:
        offset = 0
        while (offset := data.find(b'\x00\x00\x00\x01', offset)) >= 0:
            for start in range(max(0, offset - 11), offset):
                ins = matcher.decode(address + start)
                if (ins is not None and ins.mnemonic == 'cmp' and len(ins.operands) == 2 and
                        ins.operands[0].type == X86_OP_REG and ins.operands[0].size == 4 and
                        ins.operands[1].type == X86_OP_IMM and ins.operands[1].imm == 1 << 24 and
                        ins.address + ins.imm_offset == address + offset):
                    seeds[ins.address] = ins
            offset += 1
    results = {}
    for seed in seeds.values():
        for candidate in matcher.match(seed):
            candidate.pop('normalization')
            results.setdefault(candidate['bound_branch'], candidate)
    return sorted(results.values(), key=lambda row: row['address'])
