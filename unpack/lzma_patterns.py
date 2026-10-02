from collections import Counter
from dataclasses import dataclass

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

from .binary import encode_u32
from .semantic_crc import ROOTS

BASE_PROBABILITIES = 0x736
LITERAL_PROBABILITIES = 0x300
PROBABILITY_TOTAL = 1 << 11
INITIAL_PROBABILITY = PROBABILITY_TOTAL // 2
NORMALIZE_THRESHOLD = 1 << 24
ARGUMENT_HOME_STORES = (b'\x4c\x89\x4c\x24\x20', b'\x4c\x89\x8c\x24\x20\x00\x00\x00')
CONDITIONS = frozenset(('a', 'ae', 'b', 'be', 'e', 'ne', 'g', 'ge', 'l', 'le',
                        'o', 'no', 's', 'ns', 'p', 'np'))


@dataclass(frozen=True, slots=True)
class Decoder:
    address: int
    code: bytes
    stack_size: int = 0


def recognize_decoder(data, start, base):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    pending = [(start, 0)]
    decoded = {}
    stack_at = {}
    stack_size = 0
    covered = set()
    returns = 0
    integer_ops = {
        'mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'lea', 'xchg', 'xadd',
        'add', 'adc', 'sub', 'sbb', 'mul', 'imul', 'neg', 'not', 'and', 'or',
        'xor', 'cmp', 'test', 'inc', 'dec', 'bswap', 'bt', 'btc', 'btr', 'bts',
        'bsf', 'bsr', 'shl', 'sal', 'shr', 'sar', 'rol', 'ror', 'rcl', 'rcr',
        'shld', 'shrd', 'push', 'pop', 'pushfq', 'popfq', 'ret', 'nop',
        'clc', 'stc', 'cmc', 'cld', 'lahf', 'sahf', 'cbw', 'cwde', 'cdqe',
        'cwd', 'cdq', 'cqo', 'rep stosw',
    }
    while pending:
        offset, depth = pending.pop()
        if offset in stack_at and stack_at[offset] != depth:
            return None
        while offset not in decoded:
            if not start <= offset < len(data) or offset in covered:
                return None
            ins = next(md.disasm(data[offset:offset + 15], base + offset, count=1), None)
            if ins is None or ins.group(CS_GRP_CALL):
                return None
            if not (ins.mnemonic in integer_ops or ins.group(CS_GRP_JUMP)
                    or (ins.mnemonic.startswith('set') and ins.mnemonic[3:] in CONDITIONS)
                    or (ins.mnemonic.startswith('cmov') and ins.mnemonic[4:] in CONDITIONS)):
                return None
            if any((op.type == X86_OP_MEM and op.mem.segment)
                   or (op.type == X86_OP_REG and md.reg_name(op.reg) not in ROOTS)
                   for op in ins.operands):
                return None
            span = set(range(offset, offset + ins.size))
            if span & covered:
                return None
            covered.update(span)
            decoded[offset] = ins
            stack_at[offset] = depth
            if ins.group(CS_GRP_RET):
                if ins.mnemonic != 'ret' or ins.operands or depth:
                    return None
                returns += 1
                break
            writes_sp = any(ROOTS.get(md.reg_name(reg)) == 'rsp' for reg in ins.regs_access()[1])
            if writes_sp:
                if ins.mnemonic in ('push', 'pushfq'):
                    depth += 8
                elif ins.mnemonic in ('pop', 'popfq') and not any(op.type == X86_OP_REG and ROOTS.get(md.reg_name(op.reg)) == 'rsp' for op in ins.operands):
                    depth -= 8
                elif (ins.mnemonic in ('add', 'sub') and len(ins.operands) == 2
                      and ins.operands[0].type == X86_OP_REG and md.reg_name(ins.operands[0].reg) == 'rsp'
                      and ins.operands[1].type == X86_OP_IMM):
                    depth += ins.operands[1].imm * (1 if ins.mnemonic == 'sub' else -1)
                elif (ins.mnemonic == 'lea' and len(ins.operands) == 2
                      and md.reg_name(ins.operands[0].reg) == 'rsp' and ins.operands[1].type == X86_OP_MEM
                      and md.reg_name(ins.operands[1].mem.base) == 'rsp' and not ins.operands[1].mem.index):
                    depth -= ins.operands[1].mem.disp
                else:
                    return None
                if depth < 0:
                    return None
                stack_size = max(stack_size, depth)
            if ins.group(CS_GRP_JUMP):
                if len(ins.operands) != 1 or ins.operands[0].type != X86_OP_IMM:
                    return None
                target = ins.operands[0].imm - base
                if not start <= target < len(data):
                    return None
                if ins.mnemonic == 'jmp':
                    offset = target
                    if offset in stack_at and stack_at[offset] != depth:
                        return None
                    continue
                pending.append((target, depth))
            offset += ins.size
            if offset in stack_at and stack_at[offset] != depth:
                return None
    if not returns:
        return None
    counts = Counter()
    constants = set()
    state_aliases = {'rcx'}
    properties = set()
    prologue = True
    for offset, ins in sorted(decoded.items()):
        for op in ins.operands:
            if op.type == X86_OP_IMM:
                constants.add(op.imm)
        if prologue:
            for op in ins.operands:
                if op.type == X86_OP_MEM and not op.mem.index and md.reg_name(op.mem.base) in state_aliases:
                    if (op.mem.disp in (0, 4, 8) and op.size == 4) or (op.mem.disp == 16 and op.size == 8):
                        properties.add(op.mem.disp)
            alias = None
            if ins.mnemonic == 'mov' and len(ins.operands) == 2:
                dst, src = ins.operands
                if dst.type == src.type == X86_OP_REG and dst.size == src.size == 8 and md.reg_name(src.reg) in state_aliases:
                    alias = md.reg_name(dst.reg)
            for reg in ins.regs_access()[1]:
                root = ROOTS.get(md.reg_name(reg), md.reg_name(reg))
                if ins.mnemonic in ('cqo', 'cdq', 'cwd') and root == 'rax':
                    continue
                state_aliases.discard(root)
            if alias:
                state_aliases.add(alias)
            if ins.group(CS_GRP_JUMP) and ins.mnemonic != 'jmp':
                prologue = False
        if ins.mnemonic == 'rep stosw':
            counts['probability_init'] += 1
        if ins.mnemonic == 'cmp' and any(o.type == X86_OP_IMM and o.imm == NORMALIZE_THRESHOLD for o in ins.operands):
            counts['normalize'] += 1
        if ins.mnemonic in ('shr', 'sar') and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_IMM:
            if ins.operands[1].imm == 5:
                counts['adapt'] += 1
            if ins.mnemonic == 'shr' and ins.operands[1].imm == 11 and ins.operands[0].size == 4:
                root = ROOTS.get(md.reg_name(ins.operands[0].reg))
                cursor = offset + ins.size
                seen = set()
                while cursor in decoded and cursor not in seen:
                    seen.add(cursor)
                    step = decoded[cursor]
                    if step.mnemonic == 'imul' and len(step.operands) == 2 and step.operands[0].reg == ins.operands[0].reg:
                        counts['bound'] += 1
                        break
                    if step.mnemonic == 'jmp':
                        cursor = step.operands[0].imm - base
                        continue
                    if step.group(CS_GRP_JUMP) or step.group(CS_GRP_RET):
                        break
                    if root in {ROOTS.get(md.reg_name(r)) for r in step.regs_access()[1]}:
                        break
                    cursor += step.size
        if ins.mnemonic == 'movzx' and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_MEM and ins.operands[1].size == 2:
            counts['probability_load'] += 1
        if ins.mnemonic == 'mov' and ins.operands and ins.operands[0].type == X86_OP_MEM and ins.operands[0].size == 2:
            counts['probability_store'] += 1
    if properties != {0, 4, 8, 16} or not {LITERAL_PROBABILITIES, BASE_PROBABILITIES,
                                          INITIAL_PROBABILITY, PROBABILITY_TOTAL}.issubset(constants):
        return None
    if not counts['probability_init'] or any(counts[key] < 2 for key in ('normalize', 'adapt', 'bound', 'probability_load', 'probability_store')):
        return None
    end = max(offset + ins.size for offset, ins in decoded.items())
    return Decoder(base + start, bytes(data[start:end]), stack_size)


def discover_decoders(pe):
    result = {}
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()
        base = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        searched = set()
        cursor = 0
        while (cursor := data.find(encode_u32(BASE_PROBABILITIES), cursor)) >= 0:
            start = max(data.rfind(pattern, 0, cursor) for pattern in ARGUMENT_HOME_STORES)
            cursor += 1
            if start < 0 or start in searched:
                continue
            searched.add(start)
            candidate = recognize_decoder(data, start, base)
            if candidate is not None:
                result[candidate.address] = candidate
    return result
