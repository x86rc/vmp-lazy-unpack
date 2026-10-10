import pefile

from ..arch import MODE32
from ..binary import encode_u32
from ..pe import align_up


def initialize_tls(state, pe):
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']])
    directory = getattr(pe, 'DIRECTORY_ENTRY_TLS', None)
    if directory is None:
        return
    tls = directory.struct
    size = tls.EndAddressOfRawData - tls.StartAddressOfRawData
    if size < 0:
        raise ValueError('invalid tls size')
    alignment_code = (tls.Characteristics >> 20) & 0xF
    if alignment_code == 15:
        raise ValueError('invalid tls alignment')
    alignment = 1 << (alignment_code - 1) if alignment_code else 16
    data = align_up(state.heap_allocate(size + tls.SizeOfZeroFill + alignment - 1), alignment)
    if size:
        state.uc.mem_write(data, bytes(state.uc.mem_read(tls.StartAddressOfRawData, size)))
    vector = state.heap_allocate(4)
    state.uc.mem_write(vector, encode_u32(data))
    state.uc.mem_write(tls.AddressOfIndex, encode_u32(0))
    state.uc.mem_write(MODE32.teb_base + 0x2C, encode_u32(vector))
