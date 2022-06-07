import sgtlibc

def test_auto_load_function():
    s = sgtlibc.Searcher()
    s.add_condition('puts', 0xaa0)
    s.dump(['puts'])
    s.set_offset_by_function('puts', 0x7f123450000)
    assert s.get_address('system') != None, 'should auto load function address'
