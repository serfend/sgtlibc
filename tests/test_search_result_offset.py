import sgtlibc

def test_auto_load_function():
    s = sgtlibc.Searcher()
    s.add_condition('puts', 0xaa0)
    s.dump(['puts'])
    s.set_offset_by_function('puts', 0xf7123450000)
    assert s.get_address('system') != None, 'should auto load function address'

def test_simple_libc_main_with7fd():
    s = sgtlibc.Searcher()
    s.add_condition('__libc_start_main_ret', 0xf77fd)
    data = s.dump()
    assert s.get_address('system') != None, 'should auto load function address'
