import struct
from typing import Callable
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
    result = pc(data=data, specify_arch=specify_arch)
    # padding with reversed-data with '>I'pip
    result = result.replace(b'\x00'*4, struct.pack('>I', data))
    return result


def flat(*args, preprocessor: Callable = None, length: int = None, filler: bytes = None, word_size: int = None, endianness: str = None, sign: bool = None) -> bytes:
    '''
    same as pwn.flat

    Arguments:
      args: Values to flatten
      preprocessor (function): Gets called on every element to optionally
         transform the element before flattening. If :const:`None` is
         returned, then the original value is used.
      length: The length of the output.
      filler: Iterable to use for padding.
      word_size (int): Word size of the converted integer.
      endianness (str): Endianness of the converted integer ("little"/"big").
      sign (bool): Signedness of the converted integer (False/True)
    '''
    kwargs = {}
    if not preprocessor is None:
        kwargs['preprocessor'] = preprocessor
    if not length is None:
        kwargs['length'] = length
    if not filler is None:
        kwargs['filler'] = filler
    if not word_size is None:
        kwargs['word_size'] = word_size
    if not endianness is None:
        kwargs['endianness'] = endianness
    if not sign is None:
        kwargs['sign'] = sign
    return pwn.flat(
        *args,
        **kwargs
    )


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
    return pc(data=data, specify_arch=specify_arch)


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
