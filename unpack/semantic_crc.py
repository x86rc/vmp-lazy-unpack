from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from .binary import read_i32

ROOTS = {}
for root, aliases in {
    "rax": "rax eax ax al ah", "rbx": "rbx ebx bx bl bh", "rcx": "rcx ecx cx cl ch",
    "rdx": "rdx edx dx dl dh", "rsi": "rsi esi si sil", "rdi": "rdi edi di dil",
    "rbp": "rbp ebp bp bpl", "rsp": "rsp esp sp spl",
}.items():
    ROOTS.update({alias: root for alias in aliases.split()})
for index in range(8, 16):
    ROOTS.update({f"r{index}{suffix}": f"r{index}" for suffix in ("", "d", "w", "b")})
REG64 = set(ROOTS.values())
SCRATCH_OPS = {"mov", "not", "neg", "inc", "dec", "add", "sub", "adc", "sbb", "xor", "and", "or", "shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr"}
PREFIX_OPS = SCRATCH_OPS | {"bswap", "btc", "btr", "bts"}


def condition(name, flags):
    name = name.removeprefix("set").removeprefix("j")
    sf, zf, of, cf, pf = (flags.get(k) for k in ("sf", "zf", "of", "cf", "pf"))
    simple = {"s": sf, "ns": None if sf is None else not sf, "e": zf, "z": zf,
              "ne": None if zf is None else not zf, "nz": None if zf is None else not zf,
              "b": cf, "c": cf, "ae": None if cf is None else not cf,
              "nb": None if cf is None else not cf, "o": of, "no": None if of is None else not of,
              "p": pf, "pe": pf, "np": None if pf is None else not pf}
    below_or_equal = True if cf is True or zf is True else False if cf is False and zf is False else None
    simple['be'] = below_or_equal
    simple['a'] = None if below_or_equal is None else not below_or_equal
    return simple.get(name)


def scratch_operation(ins, md, stack, memory, flags):

    op = ins.operands[0]
    start = stack + op.mem.disp
    values = [memory.get(start + index) for index in range(op.size)]
    value = sum(byte << (8 * index) for index, byte in enumerate(values)) if all(byte is not None for byte in values) else None
    bits = op.size * 8
    mask = (1 << bits) - 1
    sign = 1 << (bits - 1)
    immediate = ins.operands[1].imm & mask if len(ins.operands) > 1 else None
    name = ins.mnemonic
    result = None
    if name == "mov":
        result = immediate
    elif name.startswith("set"):
        known = condition(name, flags)
        result = int(known) if known is not None else None
    elif name == "not":
        result = value ^ mask if value is not None else None
    elif name in ('shl', 'sal', 'shr', 'sar'):
        count = immediate & (63 if bits == 64 else 31)
        if count == 0:
            result = value
        else:
            flags.update({key: None for key in ('sf', 'zf', 'of', 'cf', 'pf')})
            if value is not None:
                if name in ('shl', 'sal'):
                    result = (value << count) & mask
                    if count < bits:
                        flags['cf'] = bool((value >> (bits - count)) & 1)
                elif name == 'shr':
                    result = value >> count
                    if count < bits:
                        flags['cf'] = bool((value >> (count - 1)) & 1)
                else:
                    signed = value - (1 << bits) if value & sign else value
                    result = (signed >> count) & mask
                    if count < bits:
                        flags['cf'] = bool((value >> (count - 1)) & 1)
                flags['sf'], flags['zf'] = bool(result & sign), result == 0
                flags['pf'] = (result & 255).bit_count() % 2 == 0
                if count == 1:
                    flags['of'] = (bool(result & sign) ^ flags['cf'] if name in ('shl', 'sal')
                                   else bool(value & sign) if name == 'shr' else False)
    elif name in ("inc", "dec", "add", "sub", "neg", "xor", "and", "or"):
        carry = flags.get("cf")
        flags.update({key: None for key in ("sf", "zf", "of", "cf", "pf")})
        if name in ("inc", "dec"):
            flags["cf"] = carry
        if name in ("xor", "and", "or"):
            flags["cf"] = flags["of"] = False
        if value is not None:
            if name in ("inc", "add"):
                addend = 1 if name == "inc" else immediate
                result = (value + addend) & mask
                flags["of"] = bool((~(value ^ addend) & (value ^ result)) & sign)
                if name == "add":
                    flags["cf"] = value + addend > mask
            elif name in ("dec", "sub"):
                subtrahend = 1 if name == "dec" else immediate
                result = (value - subtrahend) & mask
                flags["of"] = bool(((value ^ subtrahend) & (value ^ result)) & sign)
                if name == "sub":
                    flags["cf"] = value < subtrahend
            elif name == "neg":
                result = (-value) & mask
                flags["cf"], flags["of"] = value != 0, value == sign
            elif name == "xor":
                result = value ^ immediate
            elif name == "and":
                result = value & immediate
            elif name == "or":
                result = value | immediate
            flags["sf"], flags["zf"], flags["pf"] = bool(result & sign), result == 0, (result & 255).bit_count() % 2 == 0
    else:


        affected = ("cf", "of") if name in ("rol", "ror", "rcl", "rcr") else ("sf", "zf", "pf", "cf", "of")
        flags.update({key: None for key in affected})
    for index in range(op.size):
        memory[start + index] = (result >> (8 * index)) & 255 if result is not None else None


def recognize_loop(raw, address):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(raw, address))
    if not instructions or sum(ins.size for ins in instructions) != len(raw):
        return None
    return recognize_instructions(instructions, address, md)


def instruction_ranges(instructions):
    ranges = []
    for ins in instructions:
        if ranges and ranges[-1][0] + len(ranges[-1][1]) == ins.address:
            start, raw = ranges[-1]
            ranges[-1] = (start, raw + bytes(ins.bytes))
        else:
            ranges.append((ins.address, bytes(ins.bytes)))
    return ranges


def recognize_instructions(instructions, address, md):
    if not instructions:
        return None
    last = instructions[-1]
    if last.mnemonic != "jne" or len(last.operands) != 1 or last.operands[0].type != X86_OP_IMM or last.operands[0].imm != address:
        return None
    core = []
    stack = 0
    depth = 0
    after_count_dec = False
    scratch = {}
    flags = {}
    branch_proofs = []

    def reg(op):
        return md.reg_name(op.reg) if op.type == X86_OP_REG else None

    def root(op):
        return ROOTS.get(reg(op))

    skip = set()
    if len(instructions) >= 5:
        call, pop, add, jump, overwrite = instructions[:5]
        if (call.mnemonic == "call" and call.operands[0].type == X86_OP_IMM
                and call.operands[0].imm == call.address + call.size
                and pop.mnemonic == "pop" and reg(pop.operands[0]) in REG64
                and add.mnemonic == "add" and len(add.operands) == 2
                and reg(add.operands[0]) == reg(pop.operands[0]) and add.operands[1].type == X86_OP_IMM
                and jump.mnemonic == "jmp" and reg(jump.operands[0]) == reg(pop.operands[0])
                and call.address + call.size + add.operands[1].imm == jump.address + jump.size
                and overwrite.mnemonic == "mov" and overwrite.operands[0].size == 4
                and root(overwrite.operands[0]) == root(pop.operands[0])
                and overwrite.operands[1].type == X86_OP_IMM):


            skip = {0, 1, 2, 3}
            depth = 8
    for index, ins in enumerate(instructions[:-1]):
        if index in skip:
            continue
        ops = ins.operands
        if (ins.mnemonic == 'jmp' and len(ops) == 1 and ops[0].type == X86_OP_IMM
                and ops[0].imm == instructions[index + 1].address):
            continue
        if ins.mnemonic.startswith("j") and len(ops) == 1 and ops[0].type == X86_OP_IMM and ops[0].imm == ins.address + ins.size:
            continue
        if ins.mnemonic.startswith("j") and len(ops) == 1 and ops[0].type == X86_OP_IMM and condition(ins.mnemonic, flags) is False:
            branch_proofs.append({"address": ins.address, "target": ops[0].imm, "condition": ins.mnemonic, "taken": False})
            continue
        if (ins.mnemonic == "call" and len(ops) == 1 and ops[0].type == X86_OP_IMM
                and ops[0].imm == instructions[index + 1].address):
            stack -= 8
            depth = max(depth, -stack)
            for byte in range(8):
                scratch[stack + byte] = ((ins.address + ins.size) >> (byte * 8)) & 255
            continue
        if ins.mnemonic == "push" and ops[0].type == X86_OP_IMM and ins.bytes[0] in (0x68, 0x6A):
            stack -= 8
            depth = max(depth, -stack)
            for byte in range(8):
                scratch[stack + byte] = (ops[0].imm >> (byte * 8)) & 255
            continue
        if ins.mnemonic == "lea" and len(ops) == 2 and reg(ops[0]) == "rsp" and ops[1].type == X86_OP_MEM:
            mem = ops[1].mem
            if md.reg_name(mem.base) != "rsp" or mem.index or not 0 <= mem.disp <= -stack:
                return None
            stack += mem.disp
            continue
        if ops and ops[0].type == X86_OP_MEM and (ins.mnemonic in SCRATCH_OPS or ins.mnemonic.startswith("set")):
            mem = ops[0].mem
            if mem.segment or md.reg_name(mem.base) != "rsp" or mem.index or any(op.type != X86_OP_IMM for op in ops[1:]):
                return None
            if not stack <= stack + mem.disp < 0 or stack + mem.disp + ops[0].size > 0:
                return None
            if ins.mnemonic.startswith("set") or ins.mnemonic in ("adc", "sbb", "rcl", "rcr"):
                loaded = next((i for i, item in enumerate(core) if item.mnemonic == "movzx"), None)
                if loaded is None or not any(item.mnemonic == "xor" for item in core[loaded + 1:]):
                    return None
            if after_count_dec and ins.mnemonic not in ("not", "mov"):
                return None
            scratch_operation(ins, md, stack, scratch, flags)
            continue
        if ins.mnemonic == "nop":
            continue
        if (ins.mnemonic == "dec" and ops and ops[0].type == X86_OP_REG
                and any(item.mnemonic == "movzx" for item in core)):
            after_count_dec = True
        if ins.mnemonic not in ("mov", "movzx", "lea", "bswap"):
            flags = {key: None for key in ("sf", "zf", "cf", "of", "pf")}
            if ins.mnemonic in ("xor", "and", "or"):
                flags["cf"] = flags["of"] = False
        core.append(ins)
    if stack != 0 or depth > 256:
        return None
    byte_index = next((index for index, ins in enumerate(core) if ins.mnemonic == "movzx"), None)
    if byte_index is None:
        return None
    prefix, core = core[:byte_index], core[byte_index:]
    if [ins.mnemonic for ins in core] != ["movzx", "xor", "and", "mov", "shr", "xor", "inc", "xor", "dec"]:
        return None
    load, mix, mask, lookup, shift, combine, advance, key_op, count_op = core
    if len(load.operands) != 2 or load.operands[0].type != X86_OP_REG or load.operands[0].size != 4 or load.operands[1].type != X86_OP_MEM or load.operands[1].size != 1:
        return None
    temp = reg(load.operands[0])
    temp_root = root(load.operands[0])
    if temp_root == "rsp":
        return None
    for ins in prefix:
        if ins.mnemonic not in PREFIX_OPS or not ins.operands or root(ins.operands[0]) != temp_root:
            return None
        if any(op.type != X86_OP_IMM and root(op) != temp_root for op in ins.operands[1:]):
            return None
    mem = load.operands[1].mem
    if mem.segment or mem.scale != 1:
        return None
    address_regs = [md.reg_name(r) for r in (mem.base, mem.index) if r and md.reg_name(r) not in ("riz", "eiz")]
    if temp_root in address_regs:
        if len(prefix) != 1 or prefix[0].mnemonic != "mov" or len(prefix[0].operands) != 2 or reg(prefix[0].operands[0]) != temp or prefix[0].operands[1].type != X86_OP_IMM:
            return None
        if (prefix[0].operands[1].imm & 0xffffffff) + mem.disp != 0:
            return None
        address_regs.remove(temp_root)
    elif mem.disp != 0:
        return None
    if len(address_regs) != 1 or address_regs[0] not in REG64:
        return None
    source = address_regs[0]

    def rr(ins, left, right):
        return len(ins.operands) == 2 and reg(ins.operands[0]) == left and reg(ins.operands[1]) == right

    def ri(ins, left, value):
        return len(ins.operands) == 2 and reg(ins.operands[0]) == left and ins.operands[1].type == X86_OP_IMM and ins.operands[1].imm == value

    if len(shift.operands) != 2 or shift.operands[0].size != 4:
        return None
    crc = reg(shift.operands[0])
    if not crc or not rr(mix, temp, crc) or not ri(mask, temp, 255) or not ri(shift, crc, 8) or not rr(combine, crc, temp):
        return None
    if len(lookup.operands) != 2 or reg(lookup.operands[0]) != temp or lookup.operands[1].type != X86_OP_MEM or lookup.operands[1].size != 4:
        return None
    table_mem = lookup.operands[1].mem
    table = md.reg_name(table_mem.base)
    if table not in REG64 or table_mem.segment or table_mem.disp != 0 or table_mem.scale != 4 or md.reg_name(table_mem.index) != temp_root:
        return None
    if len(advance.operands) != 1 or reg(advance.operands[0]) != source or advance.operands[0].size != 8:
        return None
    if len(count_op.operands) != 1 or count_op.operands[0].size != 8 or reg(count_op.operands[0]) not in REG64:
        return None
    count = reg(count_op.operands[0])
    if len({temp_root, ROOTS[crc], table, source, count, "rsp"}) != 6:
        return None
    if len(key_op.operands) != 2 or reg(key_op.operands[0]) != crc or key_op.operands[1].type != X86_OP_IMM:
        return None
    return {"bytes": b''.join(bytes(ins.bytes) for ins in instructions),
            "code_ranges": instruction_ranges(instructions),
            "state_xor": key_op.operands[1].imm & 0xffffffff,
            "kind": "semantic_crc", "registers": {"source": source, "count": count, "table": table, "crc": crc},
            "stack_depth": depth, "proof_address": address, "branch_proofs": branch_proofs}


def recognize_scattered_loop(data, start, tail, base, md=None):
    if md is None:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
    instructions = []
    covered = set()
    offset = start
    allowed = PREFIX_OPS | {'movzx', 'lea', 'push', 'pop', 'call', 'nop'}
    for _ in range(512):
        if not 0 <= offset < len(data) or offset in covered:
            return None
        ins = next(md.disasm(data[offset:offset + 15], base + offset, count=1), None)
        if ins is None:
            return None
        span = set(range(offset, offset + ins.size))
        if covered & span:
            return None
        covered.update(span)
        instructions.append(ins)
        if offset == tail:
            return recognize_instructions(instructions, base + start, md)
        if ins.mnemonic in ('jmp', 'call'):
            if len(ins.operands) != 1 or ins.operands[0].type != X86_OP_IMM:
                return None
            offset = ins.operands[0].imm - base
            continue
        if not (ins.mnemonic in allowed or ins.mnemonic.startswith(('j', 'set'))):
            return None
        offset += ins.size
    return None


def discover_semantic_crc_loops(pe):
    result = {}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()
        base = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        for opcode, size in ((b'\x0f\x85', 6), (b'\x75', 2)):
            offset = 0
            while (offset := data.find(opcode, offset)) >= 0:
                if offset + size <= len(data):
                    displacement = (read_i32(data, offset + 2) if size == 6 else
                                    int.from_bytes(data[offset + 1:offset + 2], 'little', signed=True))
                    start = offset + size + displacement
                    if not 0 <= start < len(data) or start == offset:
                        offset += 1
                        continue
                    address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + start
                    candidate = (recognize_loop(data[start:offset + size], address)
                                 if 0 < offset - start <= 512 else None)
                    if candidate is None:
                        candidate = recognize_scattered_loop(data, start, offset, base, md)
                    if candidate:
                        result[address] = candidate
                offset += 1
    return result
