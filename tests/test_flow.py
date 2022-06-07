from typing import List
import sgtlibc


def start_dump_normal(functions: List = None):
    s = sgtlibc.Searcher()
    s.add_condition('puts', 0xe10)
    s.add_condition('read', 0x550)
    return s.dump(functions)


def test_dump_normal():
    result = start_dump_normal()
    assert len(list(result)) > 3, 'result should be valid'


def test_dump_normal_with_reference():
    r = ['system', 'str_bin_sh']
    result = start_dump_normal(r)
    assert len(list(result)) >= 2, 'result should be same or more than input'
    for i in r:
        assert i in result, f'result should have function:{i}'
