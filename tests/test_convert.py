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