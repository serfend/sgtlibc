import sgtlibc


def test_shellcode():
    assert sgtlibc.shellcraftex.shellcode64() != None
    assert sgtlibc.shellcraftex.shellcode86() != None
    assert sgtlibc.shellcraft.sh() != None
    # user should direct use shellcraft for its behavior base on user call-function-name dynamically
    # assert sgtlibc.shellcraftex.sh() != None
