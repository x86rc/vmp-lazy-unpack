import re
import struct
from collections import defaultdict, deque
from dataclasses import dataclass

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

from .arch import arch_of
from .semantic_crc import instruction_ranges
from .semantic_lzma import LzmaMatcher


BASE_PROBABILITIES = 0x736
LITERAL_PROBABILITIES = 0x300
NONVOLATILE = {'rbx', 'rbp', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15'}
NONVOLATILE32 = {'rbx', 'rbp', 'rsi', 'rdi'}


@dataclass(frozen=True)
class Decoder:
    address: int
    code_ranges: tuple
    stack_size: int
    sites: tuple


def frame_nonvolatile(matcher):
    return NONVOLATILE32 if matcher.decoder.mode == CS_MODE_32 else NONVOLATILE


def frame_start(matcher, address):
    first = matcher.decode(address)
    if first is None:
        return False
    ops = first.operands
    nonvolatile = frame_nonvolatile(matcher)
    if first.mnemonic == 'push':
        if len(ops) != 1 or ops[0].type != X86_OP_REG or matcher.root(ops[0].reg) not in nonvolatile:
            return False
    elif first.mnemonic == 'mov':
        if (len(ops) != 2 or ops[0].type != X86_OP_MEM or ops[1].type != X86_OP_REG or
                matcher.root(ops[0].mem.base) != 'rsp' or ops[0].mem.index or
                ops[0].mem.disp not in ((4, 8, 12, 16) if matcher.decoder.mode == CS_MODE_32 else (8, 16, 24, 32))):
            return False
    else:
        return False
    saved = set()
    seen = set()
    for _ in range(128):
        ins = matcher.decode(address)
        if ins is None or address in seen or ins.group(CS_GRP_CALL) or ins.group(CS_GRP_RET):
            return False
        seen.add(address)
        ops = ins.operands
        if ins.group(CS_GRP_JUMP):
            if ins.mnemonic != 'jmp' or ops[0].type != X86_OP_IMM:
                return False
            address = ops[0].imm
            continue
        if ins.mnemonic == 'push' and ops[0].type == X86_OP_REG:
            register = matcher.root(ops[0].reg)
            if register in nonvolatile:
                saved.add(register)
        if saved and len(ops) == 2 and ops[0].type == X86_OP_REG and matcher.root(ops[0].reg) == 'rsp':
            if ins.mnemonic == 'sub' and ops[1].type == X86_OP_IMM and ops[1].imm > 0:
                return True
            if (ins.mnemonic == 'lea' and ops[1].type == X86_OP_MEM and
                    matcher.root(ops[1].mem.base) == 'rsp' and not ops[1].mem.index and ops[1].mem.disp < 0):
                return True
        address += ins.size
    return False


def collect_decoder(matcher, entry, sites):
    pending = [(entry, 0)]
    depths = {}
    instructions = {}
    covered = set()
    maximum = 0
    returns = 0
    while pending:
        address, depth = pending.pop()
        if address in depths:
            if depths[address] != depth:
                return None
            continue
        if len(depths) >= 8192 or depth < 0 or depth > 0x10000:
            return None
        ins = matcher.decode(address)
        if ins is None:
            return None
        span = set(range(address, address + ins.size))
        if span & covered:
            return None
        covered.update(span)
        depths[address] = depth
        instructions[address] = ins
        ops = ins.operands
        next_address = address + ins.size
        if ins.group(CS_GRP_RET):
            if ins.mnemonic != 'ret' or ops or depth:
                return None
            returns += 1
            continue
        if ins.group(CS_GRP_CALL):
            if len(ops) != 1 or ops[0].type != X86_OP_IMM:
                return None
            pending.append((ops[0].imm, depth + matcher.ptr))
            maximum = max(maximum, depth + matcher.ptr)
            continue
        if any(matcher.root(reg) == 'rsp' for reg in ins.regs_access()[1]):
            if ins.mnemonic in ('push', 'pushfq'):
                depth += matcher.ptr
            elif ins.mnemonic in ('pop', 'popfq') and not any(
                    op.type == X86_OP_REG and matcher.root(op.reg) == 'rsp' for op in ops):
                depth -= matcher.ptr
            elif (ins.mnemonic in ('add', 'sub') and len(ops) == 2 and
                  ops[0].type == X86_OP_REG and matcher.root(ops[0].reg) == 'rsp' and ops[1].type == X86_OP_IMM):
                depth += ops[1].imm * (1 if ins.mnemonic == 'sub' else -1)
            elif (ins.mnemonic == 'lea' and len(ops) == 2 and ops[0].type == X86_OP_REG and
                  matcher.root(ops[0].reg) == 'rsp' and ops[1].type == X86_OP_MEM and
                  matcher.root(ops[1].mem.base) == 'rsp' and not ops[1].mem.index):
                depth -= ops[1].mem.disp
            else:
                return None
        if depth < 0:
            return None
        maximum = max(maximum, depth)
        if ins.group(CS_GRP_JUMP):
            if len(ops) != 1 or ops[0].type != X86_OP_IMM:
                return None
            pending.append((ops[0].imm, depth))
            if ins.mnemonic == 'jmp':
                continue
        pending.append((next_address, depth))
    matched = tuple(sorted(set(instructions) & sites))
    if not returns or not matched:
        return None
    ranges = tuple(instruction_ranges([instructions[a] for a in sorted(instructions)]))
    return Decoder(entry, ranges, maximum, matched)


def discover_decoders(pe, sites):
    if not sites:
        return {}
    base = pe.OPTIONAL_HEADER.ImageBase
    sections = [(base + s.VirtualAddress, s.get_data()[:s.Misc_VirtualSize])
                for s in pe.sections if s.Characteristics & 0x20000000]
    matcher = LzmaMatcher(sections, arch_of(pe).cs_mode)
    incoming = defaultdict(list)
    for address, data in sections:
        for match in re.finditer(rb'\xe9|\xe8|\x0f[\x80-\x8f]', data):
            offset = match.start()
            size = 6 if data[offset] == 0x0f else 5
            if offset + size <= len(data):
                target = address + offset + size + struct.unpack_from('<i', data, offset + size - 4)[0]
                if any(start <= target < start + len(raw) for start, raw in sections):
                    incoming[target].append(address + offset)
    site_addresses = {site['address'] for site in sites}
    queue = deque(sorted(site_addresses))
    seen = set()
    entries = set()
    while queue and len(seen) < 16384:
        address = queue.popleft()
        if address in seen:
            continue
        seen.add(address)
        if frame_start(matcher, address):
            entries.add(address)
        queue.extend(incoming.get(address, ()))
        for start in range(address - 15, address):
            ins = matcher.decode(start)
            if (ins is not None and ins.address + ins.size == address and
                    not ins.group(CS_GRP_CALL) and not ins.group(CS_GRP_RET) and ins.mnemonic != 'jmp'):
                queue.append(start)
        for section_base, data in sections:
            offset = address - section_base
            if not 0 <= offset < len(data):
                continue
            for match in re.finditer(rb'[\x70-\x7f\xeb]', data[max(0, offset - 129):min(len(data)-1, offset + 127)]):
                source = max(0, offset - 129) + match.start()
                if section_base + source + 2 + int.from_bytes(data[source+1:source+2], 'little', signed=True) == address:
                    queue.append(section_base + source)
    result = {}
    for entry in sorted(entries):
        candidate = collect_decoder(matcher, entry, site_addresses)
        if candidate is not None:
            result[entry] = candidate
    return result
