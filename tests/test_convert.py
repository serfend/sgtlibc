from sgtlibc import gamebox


def test_packs():
    assert gamebox.p16(123) == b'{\x00'
    assert gamebox.p32(123) == b'{\x00\x00\x00'
    assert gamebox.p64(123) == b'{\x00\x00\x00\x00\x00\x00\x00'
    assert gamebox.u16(b'{') == 123
    assert gamebox.u32(b'{\x00\x00\x00') == 123
    assert gamebox.u32(b'{\x00') == 123
    assert gamebox.u64(b'{\x00\x00\x00\x00\x00\x00\x00') == 123
    assert gamebox.u64(b'{\x00') == 123
def test_flat():
    gamebox.context = 'i386'
    assert gamebox.flat([1,2,3]) == gamebox.p32(1) + gamebox.p32(2) + gamebox.p32(3)

def test_flat64():
    gamebox.context.arch = 'amd64'
    assert gamebox.flat([1,2,3]) == gamebox.p64(1) + gamebox.p64(2) + gamebox.p64(3)
    assert gamebox.flat([1,2,3],length=0x20) == gamebox.p64(1) + gamebox.p64(2) + gamebox.p64(3) + gamebox.cyclic(0x20)[0x18:]