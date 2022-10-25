import sys
import sgtlibc.main


def test_run_update():
    sys.argv = [sys.argv[0], '--update']
    sgtlibc.main.run()

