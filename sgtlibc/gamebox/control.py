from typing import List, overload
from .client import check_client
import pwn


@overload
def se(data_list: List):
    '''
    you can direct use se(['/bin/bash',addr]) instead of se(p00(b'/bin/sh') + p00(addr))
    equal to se(flat(data_list))
    '''
    ...


@overload
def se(data: bytes):
    '''
    GameBox::control send data (NOT contains \n)
    data: what content to send , can be `str` or `bytes`
    '''
    ...


@overload
def sa(data_list: List):
    '''
    you can direct use sa(['/bin/bash',addr]) instead of sa(p00(b'/bin/sh') + p00(addr))
    equal to sa(flat(data_list))
    '''
    ...


@overload
def sa(data: bytes):
    '''
    GameBox::control send data AFTER `delim` received (NOT contains \n)
    delims: can use str or bytes , for what to watting for
    data: what content to send , can be `str` or `bytes`
    timeout: default is tube.default
    '''
    ...


@overload
def sl(data_list: List):
    '''
    you can direct use sl(['/bin/bash',addr]) instead of sl(p00(b'/bin/sh') + p00(addr))
    equal to sl(flat(data_list))
    '''
    ...


@overload
def sl(data: bytes):
    '''
    GameBox::control send data (contains \n)
    data: what content to send , can be `str` or `bytes`
    '''
    ...


@overload
def sla(delim: List, data: List, timeout: int = None):
    '''
    you can direct use sla(xxx,['/bin/bash',addr]) instead of sla(xxx,p00(b'/bin/sh') + p00(addr))
    equal to sla(flat(delim_list),flat(data))
    '''
    ...


@overload
def sla(delim: bytes, data: List, timeout: int = None):
    '''
    you can direct use sla(xxx,['/bin/bash',addr]) instead of sla(xxx,p00(b'/bin/sh') + p00(addr))
    equal to sla(delim_list,flat(data))
    '''
    ...


@overload
def sla(delim: List, data: bytes, timeout: int = None):
    '''
    you can direct use sla(['/bin/bash',addr],xxx) instead of sla(p00(b'/bin/sh',xxx) + p00(addr))
    equal to sla(flat(delim_list),data)
    '''
    ...


@overload
def sla(delim: bytes, data: bytes, timeout: int = None):
    '''
    GameBox::control send a line with data after `delim` received (contains \n)
    delims: can use str or bytes , for what to watting for
    data: what content to send , can be `str` or `bytes`
    timeout: default is tube.default
    '''
    ...


@overload
def sea(delim: List, data: List, timeout: int = None):
    '''
    you can direct use sea(xxx,['/bin/bash',addr]) instead of sea(xxx,p00(b'/bin/sh') + p00(addr))
    equal to sea(flat(delim_list),flat(data))
    '''
    ...


@overload
def sea(delim: bytes, data: List, timeout: int = None):
    '''
    you can direct use sea(xxx,['/bin/bash',addr]) instead of sea(xxx,p00(b'/bin/sh') + p00(addr))
    equal to sea(delim_list,flat(data))
    '''
    ...


@overload
def sea(delim: List, data: bytes, timeout: int = None):
    '''
    you can direct use sea(xxx,['/bin/bash',addr]) instead of sea(xxx,p00(b'/bin/sh') + p00(addr))
    equal to sea(flat(delim_list),data)
    '''
    ...


@overload
def sea(delim: bytes, data: bytes, timeout: int = None):
    '''
    GameBox::control send data after `delim` received  (NOT contains \n)
    delims: can use str or bytes , for what to watting for
    data: what content to send , can be `str` or `bytes`
    timeout: default is tube.default
    '''
    ...


@overload
def ru(delims_list: List, drop: bool = False, timeout: int = None):
    '''
    you can direct use ru(['/bin/bash',addr]) instead of ri(p00(b'/bin/sh') + p00(addr))
    equal to ru(flat(delim_list),drop,timeout)
    '''
    ...


@overload
def ru(delims: bytes, drop: bool = False, timeout: int = None):
    '''
    GameBox::control receive data until `delims` comes
    delims: can use str or bytes , for what to watting for
    drop: if set True , the ending content will be drop
    timeout: default is tube.default
    '''
    ...


def interactive(prompt: str = pwn.term.text.bold_red('$') + ' '):
    """
    interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')

    Does simultaneous reading and writing to the tube. In principle this just
    connects the tube to standard in and standard out, but in practice this
    is much more usable, since we are using :mod:`pwnlib.term` to print a
    floating prompt.

    Thus it only works in while in :data:`pwnlib.term.term_mode`.
    """
    c = check_client()
    return c.interactive(prompt)


def se(data: bytes):
    '''
    GameBox::control send data (NOT contains \n)
    data: what content to send , can be `str` or `bytes`
    '''
    
    c = check_client()
    return c.send(pwn.flat(data))


def sa(delim: bytes, data: bytes, timeout: int = None):
    '''
    GameBox::control send data AFTER `delim` received (NOT contains \n)
    delims: can use str or bytes , for what to watting for
    data: what content to send , can be `str` or `bytes`
    timeout: default is tube.default
    '''

    c = check_client()
    return c.sendafter(pwn.flat(delim), pwn.flat(data), timeout=timeout or c.default)


def sl(data: bytes):
    '''
    GameBox::control send data (contains \n)
    data: what content to send , can be `str` or `bytes`
    '''

    c = check_client()
    return c.sendline(pwn.flat(data))


def sla(delim: bytes, data: bytes, timeout: int = None):
    '''
    GameBox::control send a line with data after `delim` received (contains \n)
    delims: can use str or bytes , for what to watting for
    data: what content to send , can be `str` or `bytes`
    timeout: default is tube.default
    '''
    c = check_client()
    return c.sendlineafter(pwn.flat(delim), pwn.flat(data), timeout=timeout or c.default)


def sea(delim: bytes, data: bytes, timeout: int = None):
    '''
    GameBox::control send data after `delim` received  (NOT contains \n)
    delims: can use str or bytes , for what to watting for
    data: what content to send , can be `str` or `bytes`
    timeout: default is tube.default
    '''

    c = check_client()
    return c.sendafter(pwn.flat(delim), pwn.flat(data), timeout=timeout or c.default)


def rc(numb: int = 4096, timeout: int = None):
    '''
    GameBox::control receive data with specified length of content
    data: what content to send , can be `str` or `bytes`
    timeout: default is tube.default
    '''
    c = check_client()
    return c.recv(numb, timeout=timeout or c.default)


def rl(timeout: int = None):
    '''
    GameBox::control receive a line
    '''
    c = check_client()
    return c.recvline(timeout or c.default)


def ru(delims: bytes, drop: bool = False, timeout: int = None):
    '''
    GameBox::control receive data until `delims` comes
    delims: can use str or bytes , for what to watting for
    drop: if set True , the ending content will be drop
    timeout: default is tube.default
    '''

    c = check_client()
    return c.recvuntil(pwn.flat(delims), drop=drop, timeout=timeout or c.default)


def info_addr(tag: str, addr: int):
    '''
    GameBox::control log info of a address
    '''
    c = check_client()
    return c.info(tag + ': {:#x}'.format(addr))


def close():
    '''
    GameBox::control close connection
    '''
    c = check_client()
    return c.close()
