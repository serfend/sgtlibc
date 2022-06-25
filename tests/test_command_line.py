import sys
import sgtlibc.main


def test_run_by_command():
    sys.argv = [sys.argv[0], 'puts:0xf71234bc']
    sgtlibc.main.run()


def test_run_exec_command():
    pass
