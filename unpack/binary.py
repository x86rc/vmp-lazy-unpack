from operator import index


def _buffer_offset(data, offset, size):
    view = memoryview(data).cast('B')
    offset = index(offset)
    if offset < 0:
        offset += len(view)
    if offset < 0 or offset + size > len(view):
        raise ValueError(f"Integer read/write exceeds buffer: offset={offset}, size={size}")
    return view, offset


def _read_integer(data, offset, size, signed=False):
    view, offset = _buffer_offset(data, offset, size)
    return int.from_bytes(view[offset:offset + size], 'little', signed=signed)


def _write_integer(data, offset, encoded):
    view, offset = _buffer_offset(data, offset, len(encoded))
    view[offset:offset + len(encoded)] = encoded


def read_u16(data, offset=0):
    return _read_integer(data, offset, 0x02)


def read_u32(data, offset=0):
    return _read_integer(data, offset, 0x04)


def read_u64(data, offset=0):
    return _read_integer(data, offset, 0x08)


def read_i32(data, offset=0):
    return _read_integer(data, offset, 0x04, signed=True)


def encode_u16(value):
    return index(value).to_bytes(0x02, 'little')


def encode_u32(value):
    return index(value).to_bytes(0x04, 'little')


def encode_u64(value):
    return index(value).to_bytes(0x08, 'little')


def encode_i32(value):
    return index(value).to_bytes(0x04, 'little', signed=True)


def write_u16(data, offset, value):
    _write_integer(data, offset, encode_u16(value))


def write_u32(data, offset, value):
    _write_integer(data, offset, encode_u32(value))


def write_u64(data, offset, value):
    _write_integer(data, offset, encode_u64(value))
