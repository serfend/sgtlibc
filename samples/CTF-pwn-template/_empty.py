import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
set_config(GameBoxConfig(
    is_local=True,
    file='./fm',
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