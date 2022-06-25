import os
import random
from sgtpyutils import configuration
from .common import get_resources_by_path
from sgtlibc.LibcSearcher import LibcSearcher


def test_use_user_libc():
    r = random.randint(int(1e7), int(1e8-1))
    p = f'.test.{r}.tmp'
    configuration.load(p)
    lib_path = get_resources_by_path('libs')
    configuration.set('extension_database_path', lib_path)
    s = LibcSearcher('puts', 0x007)
    s.decided()
    result = s.db
    target = [x for x in result if x[1] == 'test.symbols']
    assert len(target) > 0

    info = s.pmore(target[0])
    assert 'This_Is_A_Test_Libc_Name' in info
    os.remove(configuration.get_config_path())
