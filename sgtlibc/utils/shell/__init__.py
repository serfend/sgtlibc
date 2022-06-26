import sgtlibc.gamebox
import random


def check_shell_validate(gb: sgtlibc.gamebox):
    v = b'success_me'
    s = b'echo ' + v
    records = []
    for i in range(10):
        r = random.randint(0, int(1e9))
        cmd = s + str(r).encode()
        to_match = v + str(r).encode()
        gb.sl(to_match)
        data = gb.rc()
        records.append(data)
        success = to_match in data and not cmd in data
        if success:
            return True
    raise Exception('fail to check shell-owner', records)


def shellcode86() -> bytes:
    '''
    get a simple shellcode run by /bin/sh and int80
    '''
    return shellcode(is_x86_or_64=True)


def shellcode86_short() -> bytes:
    '''
    return a linux shellcode with length 17 bytes
    get a simple shellcode run by /bin/sh and int80
    '''
    from .shellcodes import shellcode86_int80_17b
    return shellcode86_int80_17b.shellcode


def shellcode64() -> bytes:
    '''
    get a simple shellcode run by /bin/sh and int59
    '''
    return shellcode(is_x86_or_64=False)


def shellcode64_short() -> bytes:
    '''
    return a linux shellcode with length 21 bytes
    get a simple shellcode run by /bin/sh and int59
    '''
    from .shellcodes import shellcode64_syscall59_21b
    return shellcode64_syscall59_21b.shellcode


def shellcode(is_x86_or_64: bool = True) -> bytes:
    '''
    get a simple shellcode run by /bin/sh and int80/int59
    is_x86_or_64: bool : if True return x86
    '''
    if is_x86_or_64:
        from .shellcodes import shellcode86_int80
        return shellcode86_int80.shellcode
    from .shellcodes import shellcode64_syscall59
    return shellcode64_syscall59.shellcode
