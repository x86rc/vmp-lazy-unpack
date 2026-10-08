import struct

from unicorn import UcError
import unicorn.x86_const as ux


REGISTERS = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip')
AREA = 0x33000000000
SIZE = 0x10000
CONTEXT = AREA + 0x1000
RECORD = AREA + 0x2000
DISPATCHER = AREA + 0x2100
RETURN = AREA + 0x3000


class SingleStep:

    def __init__(self, tracer, pe):
        self.tracer = tracer
        self.uc = tracer.uc
        self.base = tracer.image_start
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        self.directory = (directory.VirtualAddress, directory.Size)
        self.active = False
        self.mapped = False

    def interrupt(self, uc, number, _):
        rip = uc.reg_read(ux.UC_X86_REG_RIP)
        flags = uc.reg_read(ux.UC_X86_REG_EFLAGS)
        if number != 1 or not flags & 0x100 or self.active:
            self.tracer.stop('unhandled_interrupt', rip, interrupt=number)
            return
        try:
            self.start(rip, flags)
        except (ValueError, UcError) as exc:
            self.tracer.stop('single_step_unsupported', rip, error=str(exc))

    def start(self, rip, flags):
        uc = self.uc
        rva, size = self.directory
        if not size or size % 12 or size > 12 * 1000000:
            raise ValueError('invalid exception directory')
        table = bytes(uc.mem_read(self.base + rva, size))
        matches = [(i, row) for i, row in enumerate(struct.iter_unpack('<III', table))
                   if row[0] <= rip - self.base < row[1]]
        if len(matches) != 1:
            raise ValueError('single step address must match exactly one runtime function')
        index, (begin, end, unwind) = matches[0]
        version_flags, prologue, count, frame = uc.mem_read(self.base + unwind, 4)
        if version_flags & 7 != 1 or version_flags >> 3 not in (1, 3):
            raise ValueError('single step requires an unchained exception handler')
        frame_register = frame & 15
        if frame_register not in (3, 5, 6, 7, 12, 13, 14, 15) or rip - self.base < begin + prologue:
            raise ValueError('single step requires an established nonvolatile frame register')
        frame_names = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                       'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
        establisher = uc.reg_read(getattr(ux, 'UC_X86_REG_' + frame_names[frame_register].upper())) - (frame >> 4) * 16
        tail = self.base + unwind + 4 + ((count + 1) & ~1) * 2
        handler = self.base + struct.unpack('<I', uc.mem_read(tail, 4))[0]
        if not self.tracer.in_module(handler):
            raise ValueError('exception handler outside image')
        if not self.mapped:
            uc.mem_map(AREA, SIZE)
            self.mapped = True
        blob = bytearray(0x4d0)
        struct.pack_into('<I', blob, 0x30, 0x10001f)
        struct.pack_into('<I', blob, 0x34, uc.reg_read(ux.UC_X86_REG_MXCSR))
        struct.pack_into('<I', blob, 0x44, flags)
        for i, name in enumerate(REGISTERS):
            struct.pack_into('<Q', blob, 0x78 + i * 8, uc.reg_read(getattr(ux, 'UC_X86_REG_' + name.upper())))
        for i in range(16):
            blob[0x1a0 + i*16:0x1b0 + i*16] = uc.reg_read(getattr(ux, f'UC_X86_REG_XMM{i}')).to_bytes(16, 'little')
        uc.mem_write(CONTEXT, bytes(blob))
        record = bytearray(0x98)
        struct.pack_into('<I', record, 0, 0x80000004)
        struct.pack_into('<Q', record, 0x10, rip)
        uc.mem_write(RECORD, bytes(record))
        dispatch = struct.pack('<QQQQQQQQQII', rip, self.base, self.base + rva + index * 12,
                               establisher, 0, CONTEXT, handler, tail + 4, 0, 0, 0)
        uc.mem_write(DISPATCHER, dispatch)
        self.saved = uc.context_save()
        self.original = bytes(blob)
        self.original_rip = rip
        self.establisher = establisher
        self.function_range = (self.base + begin, self.base + end)
        self.handler_data = tail + 4
        self.active = True
        stack = AREA + SIZE - 0x108
        uc.mem_write(stack, struct.pack('<Q', RETURN))
        for register, value in ((ux.UC_X86_REG_RCX, RECORD), (ux.UC_X86_REG_RDX, establisher),
                                (ux.UC_X86_REG_R8, CONTEXT), (ux.UC_X86_REG_R9, DISPATCHER),
                                (ux.UC_X86_REG_RSP, stack), (ux.UC_X86_REG_EFLAGS, flags & ~0x100),
                                (ux.UC_X86_REG_RIP, handler)):
            uc.reg_write(register, value)
        self.tracer.add_event('single_step_dispatch', rip, handler=handler, establisher_frame=establisher)

    def on_block(self, address):
        if not self.active:
            return False
        if address != RETURN:
            return self.tracer.in_module(address)
        disposition = self.uc.reg_read(ux.UC_X86_REG_RAX) & 0xffffffff
        self.active = False
        if disposition != 0:
            self.tracer.stop('single_step_unsupported', self.original_rip, disposition=disposition)
            return True
        blob = bytes(self.uc.mem_read(CONTEXT, len(self.original)))
        self.uc.context_restore(self.saved)
        changes = {}
        for i, name in enumerate(REGISTERS):
            value = struct.unpack_from('<Q', blob, 0x78 + i * 8)[0]
            if blob[0x78+i*8:0x80+i*8] != self.original[0x78+i*8:0x80+i*8]:
                changes[name] = value
            self.uc.reg_write(getattr(ux, 'UC_X86_REG_' + name.upper()), value)
        flags = struct.unpack_from('<I', blob, 0x44)[0]
        self.uc.reg_write(ux.UC_X86_REG_EFLAGS, flags)
        self.uc.reg_write(ux.UC_X86_REG_MXCSR, struct.unpack_from('<I', blob, 0x34)[0])
        for i in range(16):
            self.uc.reg_write(getattr(ux, f'UC_X86_REG_XMM{i}'), int.from_bytes(blob[0x1a0+i*16:0x1b0+i*16], 'little'))
        self.tracer.add_event('single_step_return', self.original_rip, changes=changes, eflags=flags)
        return True

    def unwind(self):
        uc = self.uc
        target_frame = uc.reg_read(ux.UC_X86_REG_RCX)
        target_ip = uc.reg_read(ux.UC_X86_REG_RDX)
        return_value = uc.reg_read(ux.UC_X86_REG_R9)
        try:
            count = struct.unpack('<I', uc.mem_read(self.handler_data, 4))[0]
            if not 0 < count <= 256:
                raise ValueError('invalid scope table')
            scopes = list(struct.iter_unpack('<IIII', bytes(uc.mem_read(self.handler_data + 4, count * 16))))
            supported_scope = (all(jump for _, _, _, jump in scopes) and
                               any(begin <= self.original_rip - self.base < end and
                                   self.base + jump == target_ip for begin, end, _, jump in scopes))
        except (UcError, ValueError):
            supported_scope = False
        if (not supported_scope or target_frame != self.establisher or
                not self.function_range[0] <= target_ip < self.function_range[1]):
            self.tracer.stop('single_step_unsupported', self.original_rip,
                             target_frame=target_frame, target_ip=target_ip)
            return
        uc.context_restore(self.saved)
        uc.reg_write(ux.UC_X86_REG_RSP, target_frame)
        uc.reg_write(ux.UC_X86_REG_RIP, target_ip)
        uc.reg_write(ux.UC_X86_REG_RAX, return_value)
        uc.reg_write(ux.UC_X86_REG_EFLAGS, uc.reg_read(ux.UC_X86_REG_EFLAGS) & ~0x100)
        self.active = False
        self.tracer.add_event('single_step_unwind', self.original_rip,
                             target_frame=target_frame, target_ip=target_ip)
