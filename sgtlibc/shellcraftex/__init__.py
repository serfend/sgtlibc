from types import ModuleType
import sys

from ..utils.shell import shellcode, shellcode64, shellcode86, check_shell_validate
from pwnlib.shellcraft import sh as __sh, registers, i386_to_amd64


def sh() -> bytes:
    '''
    get a shellcode from pwnlib
    '''
    return __sh()
