import struct

from unicorn import UcError, UC_HOOK_BLOCK
import unicorn.x86_const as ux

from ..arch import MODE32
from ..binary import encode_u32, read_u32, write_u32


CONTEXT_REGISTERS = {
    'edi': 0x9C, 'esi': 0xA0, 'ebx': 0xA4, 'edx': 0xA8, 'ecx': 0xAC,
    'eax': 0xB0, 'ebp': 0xB4, 'eip': 0xB8, 'eflags': 0xC0, 'esp': 0xC4,
}
SEGMENTS = {'gs': 0x8C, 'fs': 0x90, 'es': 0x94, 'ds': 0x98, 'cs': 0xBC, 'ss': 0xC8}
DEBUG_REGISTERS = {'dr0': 4, 'dr1': 8, 'dr2': 12, 'dr3': 16, 'dr6': 20, 'dr7': 24}


class SingleStep32:
    def __init__(self, tracer):
        self.tracer = tracer
        self.uc = tracer.uc
        self.active = False
        self.mapped = False
        self.monitor = None
        self.area = MODE32.step_area
        self.area_context = self.area + 0x1000
        self.area_record = self.area + 0x2000
        self.area_dispatcher = self.area + 0x2100
        self.area_return = self.area + 0x3000
        self.unwind_return = self.area_return + 0x10

    def context(self):
        data = bytearray(0x2CC)
        write_u32(data, 0, 0x10017)
        for name, offset in (CONTEXT_REGISTERS | SEGMENTS | DEBUG_REGISTERS).items():
            write_u32(data, offset, self.uc.reg_read(getattr(ux, 'UC_X86_REG_' + name.upper())))
        return bytes(data)

    def interrupt(self, uc, number, user_data):
        ip = uc.reg_read(MODE32.ip)
        flags = uc.reg_read(ux.UC_X86_REG_EFLAGS)
        if number != 1 or not flags & 0x100 or self.active:
            self.tracer.stop('unhandled_interrupt', ip, interrupt=number)
            return
        try:
            self.start(ip)
        except (ValueError, UcError) as exc:
            self.fail(str(exc))

    def start(self, ip):
        if not self.mapped:
            self.uc.mem_map(self.area, MODE32.step_size)
            self.mapped = True
        self.original_ip = ip
        self.original_sp = self.uc.reg_read(MODE32.sp)
        self.saved = self.uc.context_save()
        self.original = self.context()
        self.uc.mem_write(self.area_context, self.original)
        record = struct.pack('<5I', 0x80000004, 0, 0, ip, 0) + bytes(60)
        self.uc.mem_write(self.area_record, record)
        self.uc.mem_write(self.area_dispatcher, bytes(4))
        self.frame = read_u32(self.uc.mem_read(MODE32.teb_base, 4))
        self.visited = set()
        self.phase = 'dispatch'
        self.active = True
        self.monitor = self.uc.hook_add(UC_HOOK_BLOCK, self.observe_handler)
        self.dispatch()

    def frame_fields(self, frame, visited):
        low = read_u32(self.uc.mem_read(MODE32.teb_base + 8, 4))
        high = read_u32(self.uc.mem_read(MODE32.teb_base + 4, 4))
        if frame in visited or frame & 3 or not low <= frame <= high - 8:
            raise ValueError('invalid 32 bit exception chain')
        visited.add(frame)
        next_frame, handler = struct.unpack('<II', self.uc.mem_read(frame, 8))
        if not self.tracer.in_module(handler):
            raise ValueError('32 bit exception handler outside image')
        return next_frame, handler

    def invoke(self, handler, frame, record, context, return_address, stack):
        self.uc.mem_write(stack, struct.pack('<5I', return_address, record, frame,
                                           context, self.area_dispatcher))
        self.uc.reg_write(MODE32.sp, stack)
        self.uc.reg_write(MODE32.ip, handler)
        self.uc.reg_write(ux.UC_X86_REG_EFLAGS, self.uc.reg_read(ux.UC_X86_REG_EFLAGS) & ~0x100)

    def dispatch(self):
        if self.frame == 0xFFFFFFFF:
            raise ValueError('unhandled 32 bit single step')
        self.next_frame, handler = self.frame_fields(self.frame, self.visited)
        self.uc.context_restore(self.saved)
        self.invoke(handler, self.frame, self.area_record, self.area_context,
                    self.area_return, self.original_sp - 0x100)
        self.tracer.add_event('single_step_dispatch', self.original_ip,
                              handler=handler, establisher_frame=self.frame)

    def close(self):
        self.active = False
        if self.monitor is not None:
            self.uc.hook_del(self.monitor)
            self.monitor = None

    def fail(self, error):
        self.close()
        self.tracer.stop('single_step_unsupported', self.uc.reg_read(MODE32.ip), error=error)

    def observe_handler(self, uc, address, size, user_data):
        if (self.active and self.phase == 'dispatch' and self.tracer.in_module(address)
                and uc.reg_read(MODE32.sp) >= self.original_sp):
            self.close()
            self.tracer.add_event('single_step_unwind', self.original_ip,
                                  target_ip=address, target_frame=uc.reg_read(MODE32.bp))

    def on_block(self, address):
        if not self.active:
            return False
        try:
            if address == self.unwind_return and self.phase == 'unwind':
                disposition = self.uc.reg_read(MODE32.ax)
                if disposition == 3:
                    self.unwind_frame = read_u32(self.uc.mem_read(self.area_dispatcher, 4))
                elif disposition == 1:
                    self.unwind_frame = self.unwind_next
                else:
                    raise ValueError('unsupported 32 bit unwind')
                self.uc.mem_write(MODE32.teb_base, encode_u32(self.unwind_frame))
                self.advance_unwind()
                return True
            if address == self.area_return:
                disposition = self.uc.reg_read(MODE32.ax)
                if disposition == 0:
                    self.resume()
                elif disposition == 1:
                    self.frame = self.next_frame
                    self.dispatch()
                else:
                    raise ValueError('unsupported 32 bit exception')
                return True
            self.observe_handler(self.uc, address, 0, None)
            return self.active and self.tracer.in_module(address)
        except (ValueError, UcError) as exc:
            self.fail(str(exc))
            return True

    def resume(self):
        data = bytes(self.uc.mem_read(self.area_context, len(self.original)))
        self.uc.context_restore(self.saved)
        changes = {}
        for name, offset in (CONTEXT_REGISTERS | SEGMENTS | DEBUG_REGISTERS).items():
            value = read_u32(data, offset)
            if value != read_u32(self.original, offset):
                changes[name] = value
            self.uc.reg_write(getattr(ux, 'UC_X86_REG_' + name.upper()), value)
        self.close()
        self.tracer.add_event('single_step_return', self.original_ip, changes=changes,
                              eflags=self.uc.reg_read(ux.UC_X86_REG_EFLAGS))

    def unwind(self):
        try:
            sp = self.uc.reg_read(MODE32.sp)
            ret, target, _, record, result = struct.unpack('<5I', self.uc.mem_read(sp, 20))
            self.unwind_saved = self.uc.context_save()
            self.unwind_sp, self.unwind_ip, self.unwind_result = sp + 20, ret, result
            self.unwind_target = target
            self.unwind_frame = read_u32(self.uc.mem_read(MODE32.teb_base, 4))
            self.unwind_visited = set()
            self.unwind_context = self.area_context + 0x400
            self.uc.mem_write(self.unwind_context, self.context())
            if not record:
                record = self.area_record + 0x100
                self.uc.mem_write(record, struct.pack('<5I', 0xC0000027, 0, 0, ret, 0) + bytes(60))
            flags = read_u32(self.uc.mem_read(record + 4, 4)) | 2 | (4 if not target else 0)
            self.uc.mem_write(record + 4, encode_u32(flags))
            self.unwind_record = record
            self.phase = 'unwind'
            self.advance_unwind()
        except (ValueError, UcError) as exc:
            self.fail(str(exc))

    def advance_unwind(self):
        if self.unwind_frame == self.unwind_target:
            self.uc.context_restore(self.unwind_saved)
            self.uc.reg_write(MODE32.sp, self.unwind_sp)
            self.uc.reg_write(MODE32.ip, self.unwind_ip)
            self.uc.reg_write(MODE32.ax, self.unwind_result)
            self.phase = 'dispatch'
            return
        if self.unwind_frame == 0xFFFFFFFF:
            raise ValueError('32 bit unwind target not in exception chain')
        self.unwind_next, handler = self.frame_fields(self.unwind_frame, self.unwind_visited)
        self.invoke(handler, self.unwind_frame, self.unwind_record, self.unwind_context,
                    self.unwind_return, self.unwind_sp - 0x114)
