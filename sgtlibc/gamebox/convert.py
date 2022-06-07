import pwn


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
