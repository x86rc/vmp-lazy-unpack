from collections import Counter
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import (Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_PROT_READ,
                     UC_PROT_EXEC, UC_HOOK_CODE, UC_HOOK_MEM_READ,
                     UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID)
import unicorn.x86_const as ux
from .binary import encode_i32, read_i32, read_u64
from .pe import align_up, file_offset
from .imports import number

MASK = (1 << 64) - 1
REGS = [getattr(ux, 'UC_X86_REG_' + name.upper()) for name in
        ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9',
         'r10', 'r11', 'r12', 'r13', 'r14', 'r15')]
XMMS = [getattr(ux, f'UC_X86_REG_XMM{i}') for i in range(16)]


class WrapperOracle:
    def __init__(self, pe, image, records):
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.image = image
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.uc.mem_map(self.base, align_up(pe.OPTIONAL_HEADER.SizeOfImage, 4096), UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_write(self.base, image)
        self.stack = 0x60000000
        self.stack_size = 0x20000
        self.sp = self.stack + 0x18000
        self.uc.mem_map(self.stack, self.stack_size)
        self.apis = {}
        self.slots = []
        for record in records:
            self.apis.setdefault(number(record['emu_address']), []).append(record)
            self.slots.append((self.base + number(record['slot_rva']), record))
        for page in {address & ~4095 for address in self.apis}:
            self.uc.mem_map(page, 4096, UC_PROT_READ | UC_PROT_EXEC)
        self.decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        self.decoded = {}
        self.uc.hook_add(UC_HOOK_CODE, self.code)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.uc.hook_add(UC_HOOK_MEM_READ, self.read)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self.invalid)
        self.context = self.uc.context_save()

    def fail(self, reason):
        self.reason = reason
        self.uc.emu_stop()

    def invalid(self, uc, access, address, size, value, user):
        self.fail('unmapped_or_protected_memory')
        return False

    def write(self, uc, access, address, size, value, user):

        if not self.stack <= address or address + size > self.sp:
            self.fail('non_scratch_write')

    def read(self, uc, access, address, size, value, user):
        self.reads.append((address, size))
        for slot, record in self.slots:
            if address <= slot and slot + 8 <= address + size:
                self.used.add(number(record['slot_rva']))

    def code(self, uc, address, size, user):
        if address in self.apis:
            self.api = address
            uc.emu_stop()
            return
        if not (self.source <= address < self.source_end or self.vm_start <= address < self.vm_end):
            self.fail('code_outside_wrapper_section')
            return
        self.trace.append(address)
        instruction = self.decoded.get(address)
        if instruction is None:
            instruction = next(self.decoder.disasm(bytes(uc.mem_read(address, size)), address, 1), None)
            self.decoded[address] = instruction
        if instruction is None or instruction.mnemonic not in {
            'mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'lea', 'xchg',
            'push', 'pop', 'pushfq', 'popfq', 'call', 'jmp', 'ret', 'nop',
            'add', 'sub', 'adc', 'sbb', 'xor', 'and', 'or', 'not', 'neg',
            'inc', 'dec', 'shl', 'shr', 'sar', 'rol', 'ror', 'rcl', 'rcr',
            'shld', 'shrd', 'bswap', 'imul', 'mul', 'test', 'cmp',
            'bt', 'btc', 'btr', 'bts', 'clc', 'stc', 'cmc',
            'sete', 'setne', 'seta', 'setae', 'setb', 'setbe', 'setg', 'setge', 'setl', 'setle', 'seto', 'setno', 'sets', 'setns', 'setp', 'setnp',
            'cmove', 'cmovne', 'cmova', 'cmovae', 'cmovb', 'cmovbe', 'cmovg', 'cmovge', 'cmovl', 'cmovle', 'cmovo', 'cmovno', 'cmovs', 'cmovns', 'cmovp', 'cmovnp',
            'ja', 'jae', 'jb', 'jbe', 'je', 'jne', 'jg', 'jge', 'jl', 'jle',
            'jo', 'jno', 'js', 'jns', 'jp', 'jnp', 'jrcxz',
        }:
            self.fail('unsupported_wrapper_instruction')

    def probe(self, source, prefix_size, vm_start, vm_end, seed):
        uc = self.uc
        uc.context_restore(self.context)
        self.source, self.source_end = source, source + prefix_size + 5
        self.vm_start, self.vm_end = vm_start, vm_end
        self.api = None
        self.reason = 'instruction_or_time_limit'
        self.trace, self.reads, self.used = [], [], set()
        pattern = bytes(((i * 37 + seed * 71) & 255) for i in range(256))
        uc.mem_write(self.stack, pattern * (self.stack_size // 256))
        expected = {}
        for index, reg in enumerate(REGS + XMMS):
            value = ((0x102030405060708 * (index + 1) + seed * 0x173859ab) & MASK) if seed else 0
            uc.reg_write(reg, value)
            expected[reg] = value
        flags = (0x202, 0x247, 0xA92)[seed]
        uc.reg_write(ux.UC_X86_REG_EFLAGS, flags)
        uc.reg_write(ux.UC_X86_REG_RSP, self.sp)
        caller = bytes(uc.mem_read(self.sp, 256))
        try:
            uc.emu_start(source, 0, count=4000, timeout=100000)
        except UcError:
            return None, self.reason
        if self.api is None:
            return None, self.reason
        if any(uc.reg_read(reg) != value for reg, value in expected.items()):
            return None, 'registers_changed'
        if uc.reg_read(ux.UC_X86_REG_EFLAGS) != flags:
            return None, 'flags_changed'
        if uc.reg_read(ux.UC_X86_REG_RSP) != self.sp - 8 or bytes(uc.mem_read(self.sp, 256)) != caller:
            return None, 'stack_changed'
        returned = read_u64(uc.mem_read(self.sp - 8, 8))
        length = returned - source
        if length not in (6, 7) or length < prefix_size + 5:
            return None, 'unexpected_return_address'
        matching = [r for r in self.apis[self.api] if number(r['slot_rva']) in self.used]
        if not matching:
            return None, 'no_encoded_slot_read'
        record = matching[0]

        return (length, record, tuple(self.trace), tuple(self.reads)), None

    def resolve(self, source, prefix_size, vm_start, vm_end):
        first = None
        for seed in range(3):
            result, reason = self.probe(source, prefix_size, vm_start, vm_end, seed)
            if result is None:
                return None, reason
            if first is not None and result != first:
                return None, 'input_dependent_path'
            first = result
        return (first[0], first[1]), None


def resolve_import_wrappers(pe, image, records, destinations, restored_ranges):
    if not records:
        return [], {'candidate_count': 0, 'resolved_count': 0, 'rejected': {}}
    base = pe.OPTIONAL_HEADER.ImageBase
    sections = [s for s in pe.sections if s.Characteristics & 0x20000000 and
                any(start <= s.VirtualAddress < end for start, end in restored_ranges)]


    counts = [sum(s.VirtualAddress <= number(r["slot_rva"]) < s.VirtualAddress + s.Misc_VirtualSize
                  for r in records) for s in sections]
    if not counts or max(counts) <= sum(counts) / 2:
        return [], {"candidate_count": 0, "resolved_count": 0, "rejected": {"ambiguous_wrapper_section": 1}}
    wrapper_section = sections[counts.index(max(counts))]
    oracle = WrapperOracle(pe, image, records)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.skipdata = True
    patches, rejected = [], Counter()
    candidates = 0
    branch_targets = set()
    for section in sections:
        if section is wrapper_section:
            continue
        start = section.VirtualAddress
        end = start + min(section.Misc_VirtualSize, section.SizeOfRawData)
        offset = start
        previous = None

        while offset < end:
            instruction = next(decoder.disasm(image[offset:offset + 15], base + offset, 1), None)
            if instruction is None:
                break
            if (instruction.mnemonic.startswith("j") or instruction.mnemonic == "call") and instruction.op_str.startswith("0x"):
                branch_targets.add(int(instruction.op_str, 16))
            target = None
            if instruction.bytes[0] == 0xe8 and instruction.size == 5:
                target = instruction.address + 5 + read_i32(instruction.bytes, 1)
            vm = next((s for s in (wrapper_section,) if s is not section and
                       base + s.VirtualAddress <= (target or 0) < base + s.VirtualAddress + s.Misc_VirtualSize), None)
            if vm is not None:
                candidates += 1
                source = instruction.address
                prefix = 0
                if previous is not None and previous.address + previous.size == source and (
                        (previous.mnemonic == 'push' and previous.size <= 2) or previous.mnemonic == 'pushfq'):
                    prefix = previous.size
                    source = previous.address
                if candidates > 4096:
                    result, reason = None, "candidate_limit"
                else:
                    result, reason = oracle.resolve(source, prefix, base + vm.VirtualAddress,
                                                     base + vm.VirtualAddress + vm.Misc_VirtualSize)
                if result is None:
                    rejected[reason] += 1
                else:
                    length, record = result
                    symbol = record['symbol']
                    if isinstance(symbol, str) and symbol.startswith('ordinal_'):
                        symbol = int(symbol.split('_', 1)[1], 0)
                    destination = destinations[(record['module'].lower(), symbol)]
                    displacement = destination - (source + length)
                    if not -(1 << 31) <= displacement < (1 << 31):
                        rejected['iat_out_of_range'] += 1
                    else:
                        rva = source - base
                        new = (b'\x48' if length == 7 else b'') + b'\xff\x15' + encode_i32(displacement)
                        patches.append(dict(instruction_va=source, instruction_rva=rva,
                            instruction_size=length, mnemonic='call', patch_va=source, patch_rva=rva,
                            patch_file_offset=file_offset(pe, rva, length), old_bytes=image[rva:rva + length],
                            new_bytes=new, old_target_va=target, new_target_va=destination,
                            category='encoded_wrapper', module=record['module'], symbol=record['symbol']))
                        offset = rva + length
                        previous = None
                        continue
            previous = instruction
            offset += instruction.size
    safe = []
    for patch in patches:
        start = patch['instruction_va']
        if any(start < target < start + patch['instruction_size'] for target in branch_targets):
            rejected['branch_into_patch'] += 1
        else:
            safe.append(patch)
    patches = safe
    return patches, {'candidate_count': candidates, 'resolved_count': len(patches),
                     'rejected': dict(rejected), 'states_per_candidate': 3,
                     'limitation': 'Sampled states only; unresolved wrappers unchanged.'}
