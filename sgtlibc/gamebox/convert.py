import pwn
from .client import is_64_or_86


def __get_arch(specify_arch: int = None):
    if specify_arch == None:
        return is_64_or_86()
    elif specify_arch == 32:
        return False
    elif specify_arch == 64:
        return True
    raise(Exception('invalid specify_arch'))


def fakeebp(specify_arch: int = None) -> bytes:
    '''
    return a p00(0xdeadbeef)

    specify_arch:str `32`/`64`/None. 
                if none is set ,will use auto-by-elf else use p32/p64
    '''
    data = 0xdeadbeef
    return pc(data=data, specify_arch=specify_arch)


def pc(data: bytes, specify_arch: int = None) -> bytes:
    '''
    same as `p32`/`p64` determined by elf.arch

    specify_arch:str `32`/`64`/None. 
                if none is set ,will use auto-by-elf else use p32/p64
    '''
    return p64(data) if __get_arch(specify_arch) else p32(data)

# p00 = pc


def p00(data: bytes, specify_arch: int = None) -> bytes:
    '''
    same as `p32`/`p64` determined by elf.arch

    specify_arch:str `32`/`64`/None. 
                if none is set ,will use auto-by-elf else use p32/p64
    '''
    return pc(data = data, specify_arch = specify_arch)


def uc(data: bytes, specify_arch: int = None) -> int:
    '''
    same as `u32`/`u64` determined by elf.arch

    specify_arch:str `32`/`64`/None. 
                if none is set ,will use auto-by-elf else use u32/u64
    '''
    return u64(data) if __get_arch(specify_arch) else u32(data)


def u00(data: bytes, specify_arch: int = None) -> int:
    '''
    same as `u32`/`u64` determined by elf.arch

    specify_arch:str `32`/`64`/None. 
                if none is set ,will use auto-by-elf else use u32/u64
    '''
    return uc(data=data, specify_arch=specify_arch)


def u16(data: bytes) -> int:
    '''
    unpack data to unsign-int32
    usually use in leak-address convert
    '''
    return pwn.u16(data.ljust(2, b'\0'))


def u32(data: bytes) -> int:
    '''
    unpack data to unsign-int32
    usually use in leak-address convert
    '''
    return pwn.u32(data.ljust(4, b'\0'))


def u64(data: bytes) -> int:
    '''
    unpack data to unsign-int64
    usually use in leak-address convert
    '''
    return pwn.u64(data.ljust(8, b'\0'))


def p16(value: int) -> bytes:
    '''
    pack a int value to bytes-16
    have a same effect as `struct.pack('<H',value)`
    '''
    return pwn.p16(value)


def p32(value: int) -> bytes:
    '''
    pack a int value to bytes-32
    have a same effect as `struct.pack('<I',value)`
    '''
    return pwn.p32(value)


def p64(value: int) -> bytes:
    '''
    pack a int value to bytes-64
    have a same effect as `struct.pack('<Q',value)`
    '''
    return pwn.p64(value)
