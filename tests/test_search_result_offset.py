import re
from typing import Pattern
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


def test_search_reg():
    s = sgtlibc.Searcher()
    s.add_condition('puts', 0x007)
    reg: Pattern[str] = s.condition_reg['puts']
    tests = [
        'str_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nputs = f007\r\nprintf = 006',
        'str_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nputs\t= f007\r\nprintf = 006',
        'str_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006\r\nputs = f007\r\n',
        'str_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006\r\nputs = f007',
        'str_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006\r\nputs = f007 ',
        'str_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006\r\nputs = f007\t',
        'puts = f007\r\nstr_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006\r\n',
        'puts = f007\nstr_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006\r\n',
        'puts = 123456f007\nstr_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006\r\n',
    ]
    for index, i in enumerate(tests):
        assert next(reg.finditer(
            i), None), f'match {index} should return RE-result'

    tests = [
        'str_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006',
        'str_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006\r\nputs = f123',
        'str_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006\r\nputs = f007123',
        'str_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006\r\nfputs = f007',
        'str_bin_sh = 001\r\nsystem = 002\r\ndup2 = 003\r\nread = 004\r\nwrite = 005\r\nprintf = 006\r\nputsfake = f007',
    ]
    for index, i in enumerate(tests):
        assert not next(reg.finditer(
            i), None), f'match {index} should return None'
