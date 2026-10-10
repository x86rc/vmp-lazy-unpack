import struct

from unicorn import UcError

from ..arch import encode_ptr
from ..binary import encode_u32, read_u16
from ..pe import align_up


class FileHandlers32:
    def io_status(self, address, status, information=0):
        if not self.writable_range(address, self.arch.ptr * 2):
            return 0xC0000005
        self.uc.mem_write(address, encode_ptr(self.arch, status) + encode_ptr(self.arch, information))
        return status

    def object_file_name(self, attributes):
        descriptor = self.read_ptr_mem(attributes + (16 if self.arch.bits == 64 else 8))
        length = read_u16(self.uc.mem_read(descriptor, 2))
        buffer = self.read_ptr_mem(descriptor + (8 if self.arch.bits == 64 else 4))
        return bytes(self.uc.mem_read(buffer, length)).decode('utf-16-le', errors='replace')

    def open_existing_file(self, output, access, attributes, status_block, options):
        details = {}
        if not self.writable_range(output, self.arch.ptr) or not self.writable_range(status_block, self.arch.ptr * 2):
            return 0xC0000005, details
        try:
            name = self.object_file_name(attributes)
        except UcError:
            return 0xC0000005, details
        details['requested_file'] = name
        handle = self.files.open(name)
        if handle is None:
            return self.io_status(status_block, 0xC0000034), details
        self.files.handles[handle].update(position=0, access=access & 0xFFFFFFFF, mode=options & 0x3E)
        self.write_ptr_if_mapped(output, handle)
        return self.io_status(status_block, 0, 1), details

    def _nt_open_file(self, symbol, output, access, attributes, status_block):
        return self.open_existing_file(output, access, attributes, status_block, self.stack_slot(5))

    def _nt_create_file(self, symbol, output, access, attributes, status_block):
        disposition = self.stack_slot(7) & 0xFFFFFFFF
        if disposition not in (1, 3):
            return self.io_status(status_block, 0xC0000022), dict(create_disposition=disposition)
        return self.open_existing_file(output, access, attributes, status_block, self.stack_slot(8))

    def _nt_read_file(self, symbol, handle, event, apc_routine, apc_context):
        status_block, buffer = self.stack_slot(4), self.stack_slot(5)
        length, offset_pointer = self.stack_slot(6) & 0xFFFFFFFF, self.stack_slot(7)
        details = dict(handle=handle, buffer=buffer, requested_size=length)
        record = self.files.handles.get(handle)
        if record is None or record['kind'] != 'file':
            return self.io_status(status_block, 0xC0000008 if record is None else 0xC0000024), details
        if event or apc_routine:
            return self.io_status(status_block, 0xC00000BB), details
        if not self.writable_range(status_block, self.arch.ptr * 2):
            return 0xC0000005, details
        try:
            offset = struct.unpack('<q', self.uc.mem_read(offset_pointer, 8))[0] if offset_pointer else -2
        except UcError:
            return self.io_status(status_block, 0xC0000005), details
        if offset == -2:
            offset = record.get('position', 0)
        if offset < 0:
            return self.io_status(status_block, 0xC000000D), details
        details.update(file=record['name'], offset=offset)
        if not length:
            return self.io_status(status_block, 0), details
        if offset >= len(record['data']):
            return self.io_status(status_block, 0xC0000011), details
        data = record['data'][offset:offset + length]
        if not self.writable_range(buffer, len(data)):
            return self.io_status(status_block, 0xC0000005), details
        self.uc.mem_write(buffer, data)
        if buffer < self.image_end and self.image_start < buffer + len(data):
            self.on_image_write(self.uc, None, buffer, len(data), 0, None)
        record['position'] = offset + len(data)
        details['bytes_read'] = len(data)
        return self.io_status(status_block, 0, len(data)), details

    @staticmethod
    def basic_file_information():
        return struct.pack('<4QI4x', 0, 0, 0, 0, 1)

    def file_information(self, record, information_class):
        size = len(record['data'])
        standard = struct.pack('<QQIBB2x', align_up(size, 0x1000), size, 1, 0, 0)
        position = struct.pack('<Q', record.get('position', 0))
        name = record['name'].encode('utf-16-le')
        name_info = encode_u32(len(name)) + name
        if information_class == 4:
            return self.basic_file_information()
        if information_class == 5:
            return standard
        if information_class == 9:
            return name_info
        if information_class == 14:
            return position
        if information_class == 18:
            return (self.basic_file_information() + standard + bytes(12) +
                    encode_u32(record.get('access', 0)) + position +
                    struct.pack('<II', record.get('mode', 0), 0) + name_info)
        return None

    def _nt_query_information_file(self, symbol, handle, status_block, output, length):
        information_class = self.stack_slot(4) & 0xFFFFFFFF
        details = dict(handle=handle, information_class=information_class)
        record = self.files.handles.get(handle)
        if record is None or record['kind'] != 'file':
            return self.io_status(status_block, 0xC0000008 if record is None else 0xC0000024), details
        data = self.file_information(record, information_class)
        if data is None:
            return self.io_status(status_block, 0xC0000003), details
        length &= 0xFFFFFFFF
        minimum = {9: 4, 18: 104}.get(information_class, len(data))
        if length < minimum:
            return self.io_status(status_block, 0xC0000004), details
        if not self.writable_range(status_block, self.arch.ptr * 2) or not self.writable_range(output, min(length, len(data))):
            return 0xC0000005, details
        self.uc.mem_write(output, data[:length])
        status = 0 if length >= len(data) else 0x80000005
        return self.io_status(status_block, status, min(length, len(data))), details

    def _nt_set_information_file(self, symbol, handle, status_block, data, length):
        information_class = self.stack_slot(4) & 0xFFFFFFFF
        details = dict(handle=handle, information_class=information_class)
        record = self.files.handles.get(handle)
        if record is None or record['kind'] != 'file':
            return self.io_status(status_block, 0xC0000008 if record is None else 0xC0000024), details
        if information_class != 14:
            return self.io_status(status_block, 0xC0000003), details
        if (length & 0xFFFFFFFF) < 8:
            return self.io_status(status_block, 0xC0000004), details
        if not self.writable_range(status_block, self.arch.ptr * 2):
            return 0xC0000005, details
        try:
            offset = struct.unpack('<q', self.uc.mem_read(data, 8))[0]
        except UcError:
            return self.io_status(status_block, 0xC0000005), details
        if offset < 0:
            return self.io_status(status_block, 0xC000000D), details
        record['position'] = offset
        return self.io_status(status_block, 0), details

    def _nt_query_attributes_file(self, symbol, attributes, output, unused1, unused2):
        try:
            name = self.object_file_name(attributes)
        except UcError:
            return 0xC0000005, {}
        details = dict(requested_file=name)
        if name.replace('\\', '/').rsplit('/', 1)[-1].lower() not in self.files.files:
            return 0xC0000034, details
        info = self.basic_file_information()
        if not self.writable_range(output, len(info)):
            return 0xC0000005, details
        self.uc.mem_write(output, info)
        return 0, details
