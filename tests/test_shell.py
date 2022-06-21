import sgtlibc


def test_shellcode():
    assert sgtlibc.shellcraftex.shellcode64() != None
    assert sgtlibc.shellcraftex.shellcode86() != None
    assert sgtlibc.shellcraft.sh() != None
    assert sgtlibc.shellcraftex.sh() != None
