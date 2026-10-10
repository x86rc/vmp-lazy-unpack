from collections import Counter
from bisect import bisect_left, bisect_right
from time import monotonic
from capstone import Cs, CS_ARCH_X86
from unicorn import (Uc, UcError, UC_ARCH_X86, UC_PROT_READ,
                     UC_PROT_EXEC, UC_HOOK_CODE, UC_HOOK_MEM_READ,
                     UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID)
import unicorn.x86_const as ux
from .arch import arch_of, read_ptr
from .binary import encode_i32, encode_u32, read_i32
from .pe import align_up, file_offset
from .imports import number


REGS = [getattr(ux, 'UC_X86_REG_' + name.upper()) for name in
        ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9',
         'r10', 'r11', 'r12', 'r13', 'r14', 'r15')]
SCRATCH_REGS = {ux.UC_X86_REG_RAX, ux.UC_X86_REG_R10, ux.UC_X86_REG_R11}
XMMS = [getattr(ux, f'UC_X86_REG_XMM{i}') for i in range(16)]
REGS32 = [getattr(ux, 'UC_X86_REG_' + name.upper()) for name in
          ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp')]
SCRATCH_REGS32 = {ux.UC_X86_REG_EAX, ux.UC_X86_REG_ECX, ux.UC_X86_REG_EDX}
XMMS32 = [getattr(ux, f'UC_X86_REG_XMM{i}') for i in range(8)]


class WrapperOracle:
    def __init__(self, pe, image, records, *, api_targets=None):
        self.arch = arch_of(pe)
        self.mask = self.arch.mask
        self.regs = REGS32 if self.arch.bits == 32 else REGS
        self.scratch_regs = SCRATCH_REGS32 if self.arch.bits == 32 else SCRATCH_REGS
        self.xmms = XMMS32 if self.arch.bits == 32 else XMMS
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.code_ranges = [(self.base + section.VirtualAddress,
                             self.base + section.VirtualAddress + section.Misc_VirtualSize)
                            for section in pe.sections if section.Characteristics & 0x20000000]
        self.uc = Uc(UC_ARCH_X86, self.arch.uc_mode)
        self.uc.mem_map(self.base, align_up(pe.OPTIONAL_HEADER.SizeOfImage, 4096), UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_write(self.base, image)
        self.stack = 0x60000000
        self.stack_size = 0x20000
        self.sp = self.stack + 0x18000
        self.uc.mem_map(self.stack, self.stack_size)
        self.apis = {}
        self.require_slot = api_targets is None
        self.slots = sorted({self.base + number(record['slot_rva']) for record in records})
        for record in records:
            self.apis.setdefault(number(record['emu_address']), []).append(record)
        if api_targets is not None:
            for address, label in api_targets.items():
                module, symbol = label.split('!', 1)
                self.apis[address] = [dict(module=module, symbol=symbol, emu_address=address)]
        for page in {address & ~4095 for address in self.apis}:
            self.uc.mem_map(page, 4096, UC_PROT_READ | UC_PROT_EXEC)
        self.decoder = Cs(CS_ARCH_X86, self.arch.cs_mode)
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
        first = bisect_left(self.slots, address)
        last = bisect_right(self.slots, address + size - self.arch.ptr, lo=first)
        self.used.update(slot - self.base for slot in self.slots[first:last])

    def code(self, uc, address, size, user):
        if monotonic() >= self.deadline:
            self.fail('instruction_or_time_limit')
            return
        if address in self.apis:
            self.api = address
            uc.emu_stop()
            return
        if not any(start <= address < end for start, end in self.code_ranges):
            self.fail('code_outside_executable_sections')
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

    def probe(self, source, prefix_size, seed):
        uc = self.uc
        uc.context_restore(self.context)
        self.api = None
        self.failure_details = {}
        self.reason = 'instruction_or_time_limit'
        self.trace, self.reads, self.used = [], [], set()
        pattern = bytes(((i * 37 + seed * 71) & 255) for i in range(256))
        uc.mem_write(self.stack, pattern * (self.stack_size // 256))
        expected = {}
        for index, reg in enumerate(self.regs + self.xmms):
            value = ((0x102030405060708 * (index + 1) + seed * 0x173859ab) & self.mask) if seed else 0
            uc.reg_write(reg, value)
            expected[reg] = value
        flags = (0x202, 0x247, 0xA92)[seed]
        uc.reg_write(ux.UC_X86_REG_EFLAGS, flags)
        uc.reg_write(self.arch.sp, self.sp)
        caller = bytes(uc.mem_read(self.sp, 256))
        self.deadline = monotonic() + 0.1
        try:
            uc.emu_start(source, 0, count=4000)
        except UcError:
            return None, self.reason
        if self.api is None:
            return None, self.reason
        changed = [reg for reg, value in expected.items()
                   if reg not in self.scratch_regs and uc.reg_read(reg) != value]
        if changed:
            if self.arch.bits == 64:
                names = dict(zip(REGS, ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9',
                                        'r10', 'r11', 'r12', 'r13', 'r14', 'r15')))
                names.update({register: f'xmm{index}' for index, register in enumerate(XMMS)})
            else:
                names = dict(zip(REGS32, ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp')))
                names.update({register: f'xmm{index}' for index, register in enumerate(XMMS32)})
            self.failure_details['registers'] = [names[register] for register in changed]
            return None, 'registers_changed'
        if uc.reg_read(ux.UC_X86_REG_EFLAGS) != flags:
            return None, 'flags_changed'
        stack = uc.reg_read(self.arch.sp)
        if stack not in (self.sp - self.arch.ptr, self.sp) or bytes(uc.mem_read(self.sp, 256)) != caller:
            return None, 'stack_changed'
        transfer = 'call' if stack == self.sp - self.arch.ptr else 'jmp'
        length = read_ptr(self.arch, uc.mem_read(self.sp - self.arch.ptr, self.arch.ptr)) - source \
            if transfer == 'call' else prefix_size + 5
        if length not in (6, 7) or length < prefix_size + 5:
            return None, 'unexpected_return_address'
        matching = [r for r in self.apis[self.api]
                    if not self.require_slot or number(r['slot_rva']) in self.used]
        if not matching:
            return None, 'no_encoded_slot_read'
        record = matching[0]

        return (length, record, tuple(self.trace), tuple(self.reads), transfer), None

    def resolve(self, source, prefix_size):
        first = None
        for seed in range(3):
            result, reason = self.probe(source, prefix_size, seed)
            if result is None:
                return None, reason
            if first is not None and result != first:
                return None, 'input_dependent_path'
            first = result
        self.transfer = first[4]
        return (first[0], first[1]), None


def retarget_wrapper_patch(patch, destinations, arch):
    symbol = patch['symbol']
    if isinstance(symbol, str) and symbol.startswith('ordinal_'):
        symbol = int(symbol.split('_', 1)[1], 0)
    destination = destinations[(patch['module'].lower(), symbol)]
    opcode = b'\xff\x15' if patch['mnemonic'] == 'call' else b'\xff\x25'
    length = patch['instruction_size']
    if arch.bits == 64:
        displacement = destination - (patch['instruction_va'] + length)
        if not -(1 << 31) <= displacement < (1 << 31):
            return None
        new = (b'\x48' if length == 7 else b'') + opcode + encode_i32(displacement)
    else:
        new = b'\x90' * (length - 6) + opcode + encode_u32(destination)
    return dict(patch, new_bytes=new, new_target_va=destination)


def resolve_import_wrappers(pe, image, records, destinations, restored_ranges, *, api_targets=None):
    if not records and not api_targets:
        return [], {'candidate_count': 0, 'resolved_count': 0, 'rejected': {}}
    base = pe.OPTIONAL_HEADER.ImageBase
    sections = [s for s in pe.sections if s.Characteristics & 0x20000000 and
                any(start <= s.VirtualAddress < end for start, end in restored_ranges)]


    wrapper_section = None
    if api_targets is None:
        counts = [sum(s.VirtualAddress <= number(r["slot_rva"]) < s.VirtualAddress + s.Misc_VirtualSize
                      for r in records) for s in sections]
        if not counts or max(counts) <= sum(counts) / 2:
            return [], {"candidate_count": 0, "resolved_count": 0, "rejected": {"ambiguous_wrapper_section": 1}}
        wrapper_section = sections[counts.index(max(counts))]
    oracle = WrapperOracle(pe, image, records, api_targets=api_targets)
    arch = oracle.arch
    decoder = Cs(CS_ARCH_X86, arch.cs_mode)
    decoder.skipdata = True
    patches, rejected = [], Counter()
    rejected_candidates = []
    candidates = 0
    branch_targets = set()
    for section in sections:
        if section is wrapper_section:
            continue
        target_ranges = [(base + s.VirtualAddress, base + s.VirtualAddress + s.Misc_VirtualSize)
                         for s in sections if s is not section and
                         (wrapper_section is None or s is wrapper_section)]
        start = section.VirtualAddress
        end = start + min(section.Misc_VirtualSize, section.SizeOfRawData)
        offset = start
        previous = None
        decoded_end = start

        while offset < end:
            if offset >= decoded_end:
                decoded_end = min(offset + 4096, end)
                instructions = decoder.disasm_lite(image[offset:decoded_end + 14], base + offset)
            instruction = next(instructions, None)
            if instruction is None:
                break
            address, size, mnemonic, operands = instruction
            if (mnemonic.startswith("j") or mnemonic == "call") and operands.startswith("0x"):
                branch_targets.add(int(operands, 16))
            target = None
            if image[offset] == 0xe8 and size == 5:
                target = address + 5 + read_i32(image, offset + 1)
            if target is not None and any(left <= target < right for left, right in target_ranges):
                candidates += 1
                source = address
                prefix = 0
                if previous is not None and previous[0] + previous[1] == source and (
                        (previous[2] == 'push' and previous[1] <= 2) or previous[2] == 'pushfq' or
                        (previous[2] == 'nop' and previous[1] <= 2)):
                    prefix = previous[1]
                    source = previous[0]
                if candidates > 4096:
                    result, reason = None, "candidate_limit"
                else:
                    result, reason = oracle.resolve(source, prefix)
                if result is None:
                    rejected[reason] += 1
                    rejected_candidates.append(dict(address=hex(source), target=hex(target), reason=reason,
                                                    **(oracle.failure_details if candidates <= 4096 else {})))
                else:
                    length, record = result
                    rva = source - base
                    patch = dict(instruction_va=source, instruction_rva=rva,
                        instruction_size=length, mnemonic=oracle.transfer, patch_va=source, patch_rva=rva,
                        patch_file_offset=file_offset(pe, rva, length), old_bytes=image[rva:rva + length],
                        old_target_va=target, category='encoded_wrapper',
                        module=record['module'], symbol=record['symbol'])
                    if api_targets is not None:
                        patch.update(category='api_wrapper', emu_address=record['emu_address'])
                    if destinations is not None:
                        patch = retarget_wrapper_patch(patch, destinations, arch)
                        if patch is None:
                            rejected['iat_out_of_range'] += 1
                            previous = instruction
                            offset += size
                            continue
                    patches.append(patch)
                    offset = rva + length
                    decoded_end = offset
                    previous = None
                    continue
            previous = instruction
            offset += size
    safe = []
    for patch in patches:
        start = patch['instruction_va']
        if any(start < target < start + patch['instruction_size'] for target in branch_targets):
            rejected['branch_into_patch'] += 1
        else:
            safe.append(patch)
    patches = safe
    return patches, {'candidate_count': candidates, 'resolved_count': len(patches),
                     'rejected': dict(rejected), 'rejected_candidates': rejected_candidates}
