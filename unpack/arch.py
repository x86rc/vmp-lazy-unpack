from dataclasses import dataclass

from capstone import CS_MODE_32, CS_MODE_64
from unicorn import UC_MODE_32, UC_MODE_64
import unicorn.x86_const as ux

from .binary import read_u32, read_u64, encode_u32, encode_u64, write_u32, write_u64


@dataclass(frozen=True)
class Arch:
    bits: int
    machine: int
    magic: int
    optional_size: int
    uc_mode: int
    cs_mode: int
    ptr: int
    mask: int
    ordinal_flag: int
    user_top: int
    ax: int
    cx: int
    dx: int
    bx: int
    sp: int
    bp: int
    si: int
    di: int
    ip: int
    gpr: tuple
    stack_base: int
    stack_size: int
    return_sentinel: int
    emu_module_base: int
    emu_module_stride: int
    emu_module_size: int
    emu_file_view_base: int
    peb_ldr_base: int
    peb_ldr_size: int
    teb_base: int
    peb_base: int
    host_image_base: int
    emu_heap_base: int
    emu_heap_size: int
    file_view_base: int
    step_area: int
    step_size: int


MODE64 = Arch(
    bits=64,
    machine=0x8664,
    magic=0x20B,
    optional_size=240,
    uc_mode=UC_MODE_64,
    cs_mode=CS_MODE_64,
    ptr=8,
    mask=(1 << 64) - 1,
    ordinal_flag=1 << 63,
    user_top=1 << 47,
    ax=ux.UC_X86_REG_RAX,
    cx=ux.UC_X86_REG_RCX,
    dx=ux.UC_X86_REG_RDX,
    bx=ux.UC_X86_REG_RBX,
    sp=ux.UC_X86_REG_RSP,
    bp=ux.UC_X86_REG_RBP,
    si=ux.UC_X86_REG_RSI,
    di=ux.UC_X86_REG_RDI,
    ip=ux.UC_X86_REG_RIP,
    gpr=(
        ("rax", ux.UC_X86_REG_RAX),
        ("rbx", ux.UC_X86_REG_RBX),
        ("rcx", ux.UC_X86_REG_RCX),
        ("rdx", ux.UC_X86_REG_RDX),
        ("rsi", ux.UC_X86_REG_RSI),
        ("rdi", ux.UC_X86_REG_RDI),
        ("rbp", ux.UC_X86_REG_RBP),
        ("rsp", ux.UC_X86_REG_RSP),
        ("r8", ux.UC_X86_REG_R8),
        ("r9", ux.UC_X86_REG_R9),
        ("r10", ux.UC_X86_REG_R10),
        ("r11", ux.UC_X86_REG_R11),
        ("r12", ux.UC_X86_REG_R12),
        ("r13", ux.UC_X86_REG_R13),
        ("r14", ux.UC_X86_REG_R14),
        ("r15", ux.UC_X86_REG_R15),
        ("rip", ux.UC_X86_REG_RIP),
    ),
    stack_base=0x60000000,
    stack_size=0x200000,
    return_sentinel=0x00007FF900001000,
    emu_module_base=0x00007FFA00000000,
    emu_module_stride=0x200000,
    emu_module_size=0x80000,
    emu_file_view_base=0x0000030000000000,
    peb_ldr_base=0x7FF720000000,
    peb_ldr_size=0x10000,
    teb_base=0x7FF700000000,
    peb_base=0x7FF710000000,
    host_image_base=0x00007FF900000000,
    emu_heap_base=0x0000020000000000,
    emu_heap_size=0x1000000,
    file_view_base=0x31000000000,
    step_area=0x33000000000,
    step_size=0x10000,
)

MODE32 = Arch(
    bits=32,
    machine=0x14C,
    magic=0x10B,
    optional_size=224,
    uc_mode=UC_MODE_32,
    cs_mode=CS_MODE_32,
    ptr=4,
    mask=(1 << 32) - 1,
    ordinal_flag=1 << 31,
    user_top=0x80000000,
    ax=ux.UC_X86_REG_EAX,
    cx=ux.UC_X86_REG_ECX,
    dx=ux.UC_X86_REG_EDX,
    bx=ux.UC_X86_REG_EBX,
    sp=ux.UC_X86_REG_ESP,
    bp=ux.UC_X86_REG_EBP,
    si=ux.UC_X86_REG_ESI,
    di=ux.UC_X86_REG_EDI,
    ip=ux.UC_X86_REG_EIP,
    gpr=(
        ("eax", ux.UC_X86_REG_EAX),
        ("ebx", ux.UC_X86_REG_EBX),
        ("ecx", ux.UC_X86_REG_ECX),
        ("edx", ux.UC_X86_REG_EDX),
        ("esi", ux.UC_X86_REG_ESI),
        ("edi", ux.UC_X86_REG_EDI),
        ("ebp", ux.UC_X86_REG_EBP),
        ("esp", ux.UC_X86_REG_ESP),
        ("eip", ux.UC_X86_REG_EIP),
    ),
    stack_base=0x60000000,
    stack_size=0x200000,
    return_sentinel=0x7FFF1000,
    emu_module_base=0x70000000,
    emu_module_stride=0x200000,
    emu_module_size=0x80000,
    emu_file_view_base=0x02000000,
    peb_ldr_base=0x7FFC0000,
    peb_ldr_size=0x10000,
    teb_base=0x7FFDE000,
    peb_base=0x7FFDF000,
    host_image_base=0x01000000,
    emu_heap_base=0x50000000,
    emu_heap_size=0x1000000,
    file_view_base=0x52000000,
    step_area=0x4F000000,
    step_size=0x10000,
)


def arch_of(pe):
    header = getattr(pe, 'FILE_HEADER', None)
    if header is None or getattr(header, 'Machine', MODE64.machine) != MODE32.machine:
        return MODE64
    return MODE32


def for_machine(machine):
    for arch in (MODE64, MODE32):
        if arch.machine == machine:
            return arch
    raise ValueError(f"unsupported machine 0x{machine:X}")


def for_pe(pe):
    return for_machine(pe.FILE_HEADER.Machine)


def encode_ptr(arch, value):
    return encode_u32(value) if arch.bits == 32 else encode_u64(value)


def read_ptr(arch, data, offset=0):
    return read_u32(data, offset) if arch.bits == 32 else read_u64(data, offset)


def write_ptr(arch, data, offset, value):
    if arch.bits == 32:
        write_u32(data, offset, value)
    else:
        write_u64(data, offset, value)
