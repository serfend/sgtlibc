import os
import random
from sgtlibc.utils import configuration as config
from .common import get_resources_by_path
from sgtlibc.LibcSearcher import LibcSearcher
from sgtlibc.main import do_symbols

def init_libc_database():
    r = random.randint(int(1e7), int(1e8-1))
    p = f'.test.{r}.tmp'
    config.load(p)
    lib_path = get_resources_by_path('libc_database')
    config.set(config.extension_database_path, lib_path)

def test_use_user_libc():
    init_libc_database()
    s = LibcSearcher('puts', 0xf7007)
    s.decided()
    result = s.db
    target = [x for x in result if x[1] == 'test.symbols']
    assert len(target) > 0

    info = s.pmore(target[0])
    assert 'This_Is_A_Test_Libc_Name' in info
    os.remove(config.get_config_path())

def test_add_user_libc():
    init_libc_database()
    elf_libc_file = get_resources_by_path(f'libc{os.sep}libc.so.6')
    path = do_symbols(f'{elf_libc_file}:test_libc_elf_file')
    assert path

    
    elf_libc_file = get_resources_by_path(f'libc{os.sep}libc.so.6')
    path_duplicate = do_symbols(f'{elf_libc_file}:test_libc_elf_file')
    assert path_duplicate is None

    os.remove(f'{path}.symbols')
    os.remove(f'{path}.info')
    

