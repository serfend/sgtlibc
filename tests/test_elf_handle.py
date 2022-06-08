import sgtlibc.ROPgadgets
import platform
import pytest
from .common import get_demo_ELF


@pytest.mark.skipif(platform.uname()[0] == 'Windows', reason='skip windows')
@pytest.mark.skipif(platform.uname()[0] == 'Darwin', reason='skip mac')
def test_string_search():
    elf = get_demo_ELF()
    assert 1 == elf.search_string(b'ELF')['ELF'], 'elf file first 4bytes should be \x7fELF'


@pytest.mark.skipif(platform.uname()[0] == 'Windows', reason='skip windows')
@pytest.mark.skipif(platform.uname()[0] == 'Darwin', reason='skip mac')
def test_string_search():
    elf = get_demo_ELF()

    result = elf.search_string(b'/bin/sh')
    assert not [x for x in result if result[x]]

    result = elf.search_string([b'/bin/sh', b'/bin/bash'])
    assert not [x for x in result if result[x]]

    result = elf.search_string()
    assert result == 0x60109f # direct return result on single request

    result = elf.search_string(b'/bin/sh', search_all=True)
    assert not [x for x in result if result[x]]

    result = elf.search_string([b'/bin/sh', b'/bin/bash'], search_all=True)
    assert not [x for x in result if result[x]]

    result = elf.search_string(search_all=True)
    assert b'sh' in result
    assert result[b'sh'] == [0x60109f]

    result = elf.search_string(b'buf')
    assert result == 0x400430 # direct return result on single request

    result = elf.search_string(['buf', 'nptr'])
    assert b'buf' in result
    assert result[b'buf'] == 0x400430
    assert not result[b'nptr']

    result = elf.search_string(b'buf', search_all=True)
    assert b'buf' in result
    assert result[b'buf'] == [0x400430]
    assert not result[b'nptr']

    result = elf.search_string(['buf', 'nptr'], search_all=True)
    assert b'buf' in result
    assert result[b'buf'][0] == [0x400430]
    assert not result[b'nptr']
