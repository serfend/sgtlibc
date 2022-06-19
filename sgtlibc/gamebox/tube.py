import pwn


class tube(pwn.tube):
    '''
    a class overwrite pwnlib.tube 
    for ignore Pylance warning `Unreachable Code`
    '''

    def recv_raw(self, numb):
        return None

    def send_raw(self, data):
        return None

    def settimeout_raw(self, timeout):
        return None

    def can_recv_raw(self, timeout):
        return None

    def connected_raw(self, direction):
        return None

    def fileno(self):
        return None

    def shutdown_raw(self):
        return None
