import os
from sgtpyutils.logger import logger
from sgtlibc.gamebox import *
from sgtlibc import gamebox
from sgtpyutils.network.SimpleCaculateService import SimpleCaculateService


def test_remote_connection():
    s = SimpleCaculateService()

    config = GameBoxConfig(
        is_local=False,
        file=None,
        remote=f'127.0.0.1:{s.port}',
    )
    set_config(config)
    return s


def start_remote_start():
    test_remote_connection()
    sl(b'str("test")')
    data = rc()
    assert data == b'test\n'

def test_remote_start():
    start_remote_start()

def test_remote_run():
    start_remote_start()

    se(b'str("Hello:")')
    ru(b'Hello:\n', timeout=1)

    sl(b'''
a = str("Hello:")
b = 1+1
    ''')
    sla(b'{"a": "Hello:", "b": 2}\n', b'str("Hello:")')

    sa(b'Hello:\n', b'str("Hello:")')
    sl(b'str("Hello:")')
    data = rl()
    assert b'Hello:\n' == data
    data = rl()
    assert b'Hello:\n' == data

    se(b'print(invalid')
    se(b'print(invalid')
    se(b'print(invalid')
    sl(b'str("Hello:")')
    rl()
    rl()
    rl()
    data = rc()
    data = b'Hello:\n'
