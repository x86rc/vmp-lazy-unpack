from unicorn import UcError

from ..arch import encode_ptr, read_ptr
from ..binary import encode_u32, read_u32


class ThreadHandlers32:
    def _nt_open_thread(self, symbol, output, access, attributes, client_id):
        details = dict(desired_access=access & 0xFFFFFFFF)
        if not self.writable_range(output, self.arch.ptr):
            return 0xC0000005, details
        attribute_size = 24 if self.arch.bits == 32 else 48
        try:
            attrs = self.uc.mem_read(attributes, attribute_size)
            client = self.uc.mem_read(client_id, self.arch.ptr * 2)
        except UcError:
            return 0xC0000005, details
        if read_u32(attrs) != attribute_size:
            return 0xC000000D, details
        if read_ptr(self.arch, attrs, 8 if self.arch.bits == 32 else 16):
            return 0xC0000030, details
        process_id = read_ptr(self.arch, client)
        thread_id = read_ptr(self.arch, client, self.arch.ptr)
        details.update(process_id=process_id, thread_id=thread_id)
        if process_id not in (0, 0x1337) or thread_id != 0x7331:
            return 0xC000000B, details
        handle = self.files.handle({'kind': 'thread'})
        self.write_ptr_if_mapped(output, handle)
        details['handle'] = handle
        return 0, details

    def thread_reference(self, handle):
        if handle == self.arch.mask - 1:
            return 0, handle
        if handle == self.arch.mask:
            return 0xC0000024, None
        record = self.files.handles.get(handle)
        if record is None:
            return 0xC0000008, None
        if record['kind'] != 'thread':
            return 0xC0000024, None
        return 0, self.arch.mask - 1

    def _nt_query_information_thread(self, symbol, handle, information_class, output, length):
        status, reference = self.thread_reference(handle)
        information_class &= 0xFFFFFFFF
        details = dict(handle=handle, information_class=information_class,
                       output_address=output, output_length=length)
        if status:
            return status, details
        if information_class not in (9, 16):
            result, details = super()._nt_query_information_thread(symbol, reference, information_class, output, length)
            details['handle'] = handle
            return result, details
        info = encode_ptr(self.arch, self.entry_address) if information_class == 9 else encode_u32(0)
        try:
            returned = self.stack_slot(4)
        except UcError:
            return 0xC0000005, details
        if returned and not self.writable_range(returned, 4):
            return 0xC0000005, details
        if (length & 0xFFFFFFFF) != len(info):
            result = 0xC0000004
        elif not self.writable_range(output, len(info)):
            result = 0xC0000005
        else:
            self.uc.mem_write(output, info)
            result = 0
        self.write_u32_if_mapped(returned, len(info))
        return result, details

    def _nt_set_information_thread(self, symbol, handle, information_class, data, length):
        status, reference = self.thread_reference(handle)
        if status:
            return status, dict(handle=handle, information_class=information_class & 0xFFFFFFFF)
        result, details = super()._nt_set_information_thread(symbol, reference, information_class, data, length)
        details['handle'] = handle
        return result, details

    def _set_thread_affinity_mask(self, symbol, handle, mask, unused1, unused2):
        status, reference = self.thread_reference(handle)
        if status:
            self.last_error = 6
            return 0, {}
        return super()._set_affinity_mask(symbol, reference, mask, unused1, unused2)
