from unicorn import UcError


class ProcessHandlers32:
    def _nt_query_information_process(self, symbol, process, information_class, output, length):
        information_class &= 0xFFFFFFFF
        if self.wow64 and self.arch.bits == 32 and information_class in (7, 30):
            return self.query_wow64_debug_information(process, information_class, output, length)
        if information_class != 12:
            return super()._nt_query_information_process(symbol, process, information_class, output, length)
        details = dict(handle=process, information_class=12, output_address=hex(output), output_length=length)
        if length and output & 3:
            return 0x80000002, details
        try:
            returned = self.stack_slot(4)
        except UcError:
            return 0xC0000005, details
        if returned and not self.writable_range(returned, 4):
            return 0xC0000005, details
        if (length & 0xFFFFFFFF) != 4:
            return 0xC0000004, details
        if process != self.arch.mask:
            return 0xC0000008, details
        if not self.writable_range(output, 4):
            return 0xC0000005, details
        self.uc.mem_write(output, bytes(4))
        self.write_u32_if_mapped(returned, 4)
        return 0, details

    def query_wow64_debug_information(self, process, information_class, output, length):
        length &= 0xFFFFFFFF
        details = dict(handle=process, information_class=information_class,
                       output_address=hex(output), output_length=length)
        try:
            returned = self.stack_slot(4)
        except UcError:
            return 0xC0000005, details
        details['return_length_address'] = hex(returned)
        if returned and not self.writable_range(returned, 4):
            return 0xC0000005, details
        if length != 4:
            result = 0xC0000004
        elif process != self.arch.mask:
            result = (0xC0000024 if process == self.arch.mask - 1 or process in self.files.handles
                      else 0xC0000008)
        elif not self.writable_range(output, 4):
            result = 0xC0000005
        elif information_class == 30:
            result = 0xC0000353
        else:
            self.uc.mem_write(output, bytes(4))
            result = 0
        return_length = 4 if result in (0, 0xC0000353) else 0xFFFFFFFC
        self.write_u32_if_mapped(returned, return_length)
        details['return_length'] = return_length
        return result, details
