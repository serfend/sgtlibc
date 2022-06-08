from .common import get_demo_ELF

import platform
import pytest


@pytest.mark.skipif(platform.uname()[0] == 'Windows', reason='skip windows')
@pytest.mark.skipif(platform.uname()[0] == 'Darwin', reason='skip mac')
def test_elf_load_resouces():
    assert not get_demo_ELF() is None
