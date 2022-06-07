class GameBoxConfig:
    def __init__(self, is_local: bool = True, file: str = None, remote: str = None, arch: str = 'amd64', os: str = 'linux', log_level: str = 'debug'):
        self.is_local = is_local
        self.file = file
        self.remote = remote
        self.arch = arch
        self.os = os
        self.log_level = log_level
        pass

    @property
    def tube_remote(self):
        r = self.remote
        if not r:
            return None
        host, port = r.split(':')
        return (host, port)
