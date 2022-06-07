import os
from re import L
from sgtpyutils.logger import logger
import sgtlibc.gamebox as gb
from sgtlibc import gamebox
from sgtpyutils.network.SimpleCaculateService import SimpleCaculateService


def test_remote_connection():
    s = SimpleCaculateService()

    config = gb.GameBoxConfig(
        is_local=False,
        file=None,
        remote=f'127.0.0.1:{s.port}',
    )
    gb.set_config(config)
    return s


def start_remote_start():
    test_remote_connection()
    gb.sl(b'str("test")')
    data = gb.rc()
    assert data == b'test\n'


def test_remote_start():
    start_remote_start()


def test_remote_ten_times():
    for i in range(10):
        start_remote_start()


def test_remote_recv_until():
    start_remote_start()
    gb.se(b'str("Hello:")')
    gb.ru(b'Hello:\n', timeout=1)


def test_remote_sendafter():
    start_remote_start()
    gb.sl(b'''
a = str("Hello:")
b = 1+1
    ''')
    gb.sla(b'{"a": "Hello:", "b": 2}\n', b'str("Hello:")')

    gb.sa(b'Hello:\n', b'str("Hello:")')
    gb.sl(b'str("Hello:")')
    data = gb.rl()
    assert b'Hello:\n' == data
    data = gb.rl()
    assert b'Hello:\n' == data


def test_exception():
    start_remote_start()
    gb.se(b'print(invalid')
    logger.debug(gb.rl())
    gb.se(b'print(invalid')
    logger.debug(gb.rl())
    gb.se(b'print(invalid')
    logger.debug(gb.rl())
    gb.sl(b'str("Hello:")')
    data = gb.rc()
    assert data == b'Hello:\n'
