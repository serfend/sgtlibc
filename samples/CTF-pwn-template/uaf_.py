import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./fastbin',
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


def add(data: bytes, size: int = -1):
    if size == -1:
        size = len(data)
    warning(f'add({size}):{data}')
    sla('>', '1')
    sla('Size:', str(size))
    sa('Data:', data)


def delete(idx: int):
    warning(f'delete({idx})')
    sla('>', '2')
    sla('Idx:', str(idx))


def show(idx: int):
    warning(f'delete({idx})')
    sla('>', '3')
    sla('Idx:', str(idx))
    


def edit(idx: int, data: bytes, size: int = -1):
    if size == -1:
        size = len(data)


SIZE_EXP = 0x60
POP_OFFSET = 0 
interactive()
