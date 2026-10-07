import lzma

from unicorn import (Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_PROT_READ, UC_PROT_EXEC,
                     UC_PROT_WRITE, UC_HOOK_CODE, UC_HOOK_MEM_WRITE)
import unicorn.x86_const as ux

from .binary import read_u32, read_u64, encode_u64, write_u32, write_u64
from .pe import align_up
from .lzma_functions import BASE_PROBABILITIES, LITERAL_PROBABILITIES, discover_decoders


PRESERVED = tuple(getattr(ux, 'UC_X86_REG_' + name) for name in
                  ('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))
PRESERVED += tuple(getattr(ux, f'UC_X86_REG_XMM{i}') for i in range(6, 16))


def filters(lc, lp, pb, capacity):
    return {'id': lzma.FILTER_LZMA1, 'dict_size': max(4096, capacity), 'lc': lc, 'lp': lp, 'pb': pb}


def validate_decoder(candidate):
    cases = (
        (bytes(range(256)) + b'abcabcabc' * 16, (3, 0, 2)),
        (b'\x00' * 129 + b'repeated block ' * 32 + bytes(range(64)), (0, 0, 0)),
        (bytes((i * 73 + (i >> 2)) & 255 for i in range(513)), (2, 1, 1)),
        (b'', (1, 0, 4)),
    )
    for seed, (payload, properties) in enumerate(cases):
        lc, lp, pb = properties
        packed = lzma.compress(payload, format=lzma.FORMAT_RAW, filters=[filters(lc, lp, pb, len(payload))])
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        pages = {page for address, raw in candidate.code_ranges
                 for page in range(address & ~0xFFF, align_up(address + len(raw), 4096), 4096)}
        for page in sorted(pages):
            uc.mem_map(page, 4096, UC_PROT_READ | UC_PROT_EXEC)
        for address, raw in candidate.code_ranges:
            uc.mem_write(address, raw)
        code_end = max(pages) + 4096
        base = align_up(code_end, 0x10000) + 0x10000
        source, destination, state, probs, counts, stack, sentinel = (
            base + offset for offset in (0, 0x10000, 0x20000, 0x30000, 0x40000, 0x50000, 0x80000))
        prob_size = 2 * (BASE_PROBABILITIES + (LITERAL_PROBABILITIES << (lc + lp)))
        for address, size in ((source, 4096), (destination, 4096), (state, 4096),
                              (probs, align_up(prob_size, 4096)), (counts, 4096),
                              (stack, 0x20000), (sentinel, 4096)):
            uc.mem_map(address, size)
        uc.mem_write(source, packed)
        uc.mem_protect(source, 4096, UC_PROT_READ)
        uc.mem_write(destination, b'\xa5' * 4096)
        uc.mem_write(probs, b'\xa5' * prob_size)
        descriptor = bytearray(24)
        for offset, value in ((0, lc), (4, lp), (8, pb)):
            write_u32(descriptor, offset, value)
        write_u64(descriptor, 16, probs)
        uc.mem_write(state, bytes(descriptor))
        uc.mem_protect(state, 4096, UC_PROT_READ)
        sp = stack + 0x10008
        uc.mem_write(sp, encode_u64(sentinel))
        uc.mem_write(sp + 0x28, encode_u64(destination) + encode_u64(len(payload) + 16) + encode_u64(counts + 8))
        uc.reg_write(ux.UC_X86_REG_RSP, sp)
        uc.reg_write(ux.UC_X86_REG_RCX, state)
        uc.reg_write(ux.UC_X86_REG_RDX, source)
        uc.reg_write(ux.UC_X86_REG_R8, len(packed))
        uc.reg_write(ux.UC_X86_REG_R9, counts)
        uc.reg_write(ux.UC_X86_REG_EFLAGS, (0x202, 0x247, 0xA92, 0x246)[seed])
        expected = {reg: (seed + 1) * 0x123456 + i for i, reg in enumerate(PRESERVED)}
        for reg, value in expected.items():
            uc.reg_write(reg, value)
        failure = []
        allowed = ((destination, destination + len(payload)), (probs, probs + prob_size),
                   (counts, counts + 16), (stack, sp), (sp + 8, sp + 0x28))
        def on_write(engine, access, address, size, value, user):
            if not any(start <= address and address + size <= end for start, end in allowed):
                failure.append('write outside decoder outputs or scratch')
                engine.emu_stop()
        def on_code(engine, address, size, user):
            if not any(start <= address and address + size <= start + len(raw)
                       for start, raw in candidate.code_ranges):
                failure.append('code outside decoder')
                engine.emu_stop()
        uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
        uc.hook_add(UC_HOOK_CODE, on_code)
        try:
            uc.emu_start(candidate.address, sentinel, count=2000000, timeout=1000000)
        except UcError as exc:
            return False, f'conformance memory/instruction error: {exc}'
        if failure:
            return False, failure[0]
        if uc.reg_read(ux.UC_X86_REG_RIP) != sentinel:
            return False, 'conformance probe did not return'
        if uc.reg_read(ux.UC_X86_REG_RAX) != 0 or uc.reg_read(ux.UC_X86_REG_RSP) != sp + 8:
            return False, 'decoder status or return stack mismatch'
        if any(uc.reg_read(reg) != value for reg, value in expected.items()):
            return False, 'callee-saved register mismatch'
        if uc.reg_read(ux.UC_X86_REG_EFLAGS) & 0x400:
            return False, 'direction flag not restored'
        if bytes(uc.mem_read(destination, len(payload))) != payload:
            return False, 'decoded output mismatch'
        if read_u64(uc.mem_read(counts, 8)) != len(packed) or read_u64(uc.mem_read(counts + 8, 8)) != len(payload):
            return False, 'processed-size mismatch'
    return True, None


def decode_call(uc, candidate, image_start, image_end, destination_ranges):
    if any(bytes(uc.mem_read(start, len(raw))) != raw for start, raw in candidate.code_ranges):
        raise ValueError('decoder code changed')
    if uc.reg_read(ux.UC_X86_REG_EFLAGS) & 0x400:
        raise ValueError('decoder requires a cleared direction flag')
    state = uc.reg_read(ux.UC_X86_REG_RCX)
    source = uc.reg_read(ux.UC_X86_REG_RDX)
    input_limit = uc.reg_read(ux.UC_X86_REG_R8)
    input_processed = uc.reg_read(ux.UC_X86_REG_R9)
    sp = uc.reg_read(ux.UC_X86_REG_RSP)
    return_address = read_u64(uc.mem_read(sp, 8))
    args = uc.mem_read(sp + 0x28, 24)
    destination, output_limit, output_processed = (read_u64(args, offset) for offset in (0, 8, 16))
    if not image_start <= source < image_end or not image_start <= return_address < image_end:
        raise ValueError('source or return outside image')
    section = next(((start, end, name) for start, end, name in destination_ranges if start <= destination < end), None)
    if section is None:
        raise ValueError('destination is not a packed section')
    descriptor = uc.mem_read(state, 24)
    lc, lp, pb = (read_u32(descriptor, offset) for offset in (0, 4, 8))
    if lc > 8 or lp > 4 or pb > 4 or lc + lp > 4:
        raise ValueError('unsupported LZMA properties')
    capacity = min(section[1] - destination, output_limit)
    source_size = min(image_end - source, input_limit)
    if capacity <= 0 or source_size < 5:
        raise ValueError('empty decoder buffer')
    probs = read_u64(descriptor, 16)
    prob_size = 2 * (BASE_PROBABILITIES + (LITERAL_PROBABILITIES << (lc + lp)))
    if probs < image_end and image_start < probs + prob_size:
        raise ValueError('image-backed probability workspace requires Unicorn')
    writes = ((destination, destination + capacity), (input_processed, input_processed + 8),
              (output_processed, output_processed + 8), (probs, probs + prob_size))
    protected = ((state, state + 24),
                 (sp - candidate.stack_size, sp + 0x40)) + tuple(
                     (start, start + len(raw)) for start, raw in candidate.code_ranges)
    regions = list(uc.mem_regions())
    for start, end in writes:
        if not start or not any(left <= start < end <= right + 1 and perms & UC_PROT_WRITE for left, right, perms in regions):
            raise ValueError('decoder output or scratch is not writable')
        if any(start < right and left < end for left, right in protected):
            raise ValueError('decoder buffers overlap input, state, code or arguments')
    for index, (start, end) in enumerate(writes):
        if any(start < right and left < end for left, right in writes[index + 1:]):
            raise ValueError('decoder output buffers overlap')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[filters(lc, lp, pb, capacity)])
    compressed = bytes(uc.mem_read(source, source_size))
    output = decoder.decompress(compressed, max_length=capacity + 1)
    if not decoder.eof or len(output) > capacity:
        raise ValueError('LZMA stream exceeds available buffers')
    if len(output) >= output_limit:
        raise ValueError('output-limited decoding requires Unicorn')
    consumed = len(compressed) - len(decoder.unused_data)
    if any(start < source + consumed and source < end for start, end in writes):
        raise ValueError('decoder output overlaps compressed input')
    if state < sp + 0x40 and sp - candidate.stack_size < state + 24:
        raise ValueError('decoder state overlaps call frame')
    if source < sp + 0x40 and sp - candidate.stack_size < source + consumed:
        raise ValueError('compressed input overlaps call frame')
    uc.mem_write(destination, output)
    uc.mem_write(input_processed, encode_u64(consumed))
    uc.mem_write(output_processed, encode_u64(len(output)))
    uc.reg_write(ux.UC_X86_REG_RAX, 0)
    uc.reg_write(ux.UC_X86_REG_RSP, sp + 8)
    uc.reg_write(ux.UC_X86_REG_RIP, return_address)
    return {'decoder': candidate.address, 'source': source, 'destination': destination,
            'compressed_size': consumed, 'uncompressed_size': len(output), 'section': section[2],
            'properties': {'lc': lc, 'lp': lp, 'pb': pb}, 'return_address': return_address}


class DecoderAccelerator:
    def __init__(self, pe, sites):
        self.candidates = discover_decoders(pe, sites)
        self.validated = set()
        self.rejected = {}
        self.reported = set()

    def try_decode(self, uc, address, image_start, image_end, destination_ranges):
        if address in self.rejected:
            return None, None
        candidate = self.candidates[address]
        if address not in self.validated:
            try:
                accepted, reason = validate_decoder(candidate)
            except (ValueError, UcError, lzma.LZMAError, OverflowError) as exc:
                accepted, reason = False, str(exc)
            if not accepted:
                self.rejected[address] = reason
                return None, reason
            self.validated.add(address)
        try:
            return decode_call(uc, candidate, image_start, image_end, destination_ranges), None
        except (ValueError, UcError, lzma.LZMAError, OverflowError) as exc:
            if address in self.reported:
                return None, None
            self.reported.add(address)
            return None, str(exc)
