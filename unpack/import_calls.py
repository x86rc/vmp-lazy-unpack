import json

from unicorn import UcError
import unicorn.x86_const as ux

from .arch import MODE64


class ImportCallLog:
    def __init__(self, path, arch=MODE64):
        self.arch = arch
        self.stream = path.open('w+', encoding='ascii', newline='\n')
        self.stream.write('[\n]\n')
        self.stream.flush()
        self.tail = 2
        self.sequence = 0

    def begin(self, uc, address, name, blocks):
        self.stream.seek(self.tail)
        if self.sequence:
            self.stream.write(',\n')
        self.start = self.stream.tell()
        self.sequence += 1
        sp = uc.reg_read(self.arch.sp)
        if self.arch.bits == 64:
            arguments = {name: hex(uc.reg_read(register)) for name, register in (
                ('rcx', ux.UC_X86_REG_RCX), ('rdx', ux.UC_X86_REG_RDX),
                ('r8', ux.UC_X86_REG_R8), ('r9', ux.UC_X86_REG_R9))}
        else:
            arguments = {}
        self.row = dict(sequence=self.sequence, blocks=blocks, import_name=name,
                        address=hex(address), rsp=hex(sp), arguments=arguments,
                        outcome='entered')
        try:
            if self.arch.bits == 32:
                for index, argument in enumerate(('stack0', 'stack1', 'stack2', 'stack3')):
                    arguments[argument] = hex(int.from_bytes(uc.mem_read(sp + 4 + index * 4, 4), 'little'))
            self.row['return_address'] = hex(int.from_bytes(uc.mem_read(sp, self.arch.ptr), 'little'))
            if self.arch.bits == 64:
                self.row['stack_arguments'] = [hex(int.from_bytes(uc.mem_read(sp + offset, 8), 'little'))
                                               for offset in (0x28, 0x30, 0x38, 0x40)]
            else:
                self.row['stack_arguments'] = [hex(int.from_bytes(uc.mem_read(sp + offset, 4), 'little'))
                                               for offset in (0x14, 0x18, 0x1C, 0x20)]
        except UcError as exc:
            self.row['stack_error'] = str(exc)
        self.write()

    def finish(self, outcome, result=None, **details):
        self.row.update(outcome=outcome, result=hex(result) if result is not None else None, **details)
        self.write()

    def write(self):
        self.stream.seek(self.start)
        self.stream.write(json.dumps(self.row, separators=(',', ':')))
        self.tail = self.stream.tell()
        self.stream.write('\n]\n')
        self.stream.truncate()
        self.stream.flush()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()
