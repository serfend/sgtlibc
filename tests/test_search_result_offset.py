import sgtlibc


def test_check_offset_status():
    s = sgtlibc.Searcher()
    s.add_condition('puts', 0xaa0)
    s.dump(['puts'])
    assert s.get_address('system') == False, 'should set offset first'


def test_auto_load_function():
    s = sgtlibc.Searcher()
    s.add_condition('puts', 0xaa0)
    s.dump(['puts'])
    s.set_offset('puts', 0x7f123450000)
    assert s.get_address('system'), 'should auto load function address'
