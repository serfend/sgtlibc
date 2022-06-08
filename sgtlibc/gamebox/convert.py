import pwn
from .client import is_64_or_86


def pc(data: bytes):
    '''
    same as `p32`/`p64` determined by elf.arch
    '''
    return p64(data) if is_64_or_86() else p32(data)

# p00 = pc


def p00(data: bytes):
    '''
    same as `p32`/`p64` determined by elf.arch
    '''
    return pc(data)


def uc(data: bytes):
    '''
    same as `u32`/`u64` determined by elf.arch
    '''
    return u64(data) if is_64_or_86() else u32(data)


def u00(data: bytes):
    '''
    same as `u32`/`u64` determined by elf.arch
    '''
    return uc(data)


def u16(data: bytes):
    '''
    unpack data to unsign-int32
    usually use in leak-address convert
    '''
    return pwn.u16(data.ljust(2, b'\0'))


def u32(data: bytes):
    '''
    unpack data to unsign-int32
    usually use in leak-address convert
    '''
    return pwn.u32(data.ljust(4, b'\0'))


def u64(data: bytes):
    '''
    unpack data to unsign-int64
    usually use in leak-address convert
    '''
    return pwn.u64(data.ljust(8, b'\0'))


def p16(value: int):
    '''
    pack a int value to bytes-16
    have a same effect as `struct.pack('<H',value)`
    '''
    return pwn.p16(value)


def p32(value: int):
    '''
    pack a int value to bytes-32
    have a same effect as `struct.pack('<I',value)`
    '''
    return pwn.p32(value)


def p64(value: int):
    '''
    pack a int value to bytes-64
    have a same effect as `struct.pack('<Q',value)`
    '''
    return pwn.p64(value)
