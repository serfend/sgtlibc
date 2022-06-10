import sgtlibc.gamebox
import random

def check_shell_validate(gb: sgtlibc.gamebox):
    v = b'success_me'
    s = b'echo ' + v
    records = []
    for i in range(10):
        r = random.randint(0, int(1e9))
        cmd = s + str(r).encode()
        to_match = v + str(r).encode()
        gb.sl(to_match)
        data = gb.rc()
        records.append(data)
        success = to_match in data and not cmd in data
        if success:
            return True
    raise Exception('fail to check shell-owner', records)
