from ..ROPgadgets import ELF


class GameBoxConfig:
    def __init__(self, is_local: bool = True, file: str = None, remote: str = None, arch: str = 'amd64', os: str = 'linux', log_level: str = 'debug', elf: ELF = None):
        '''
        if elf is specified it would auto load its context.amd you can use `pc`/`uc` also, instead of `p32`/`u32` or `p64`/`u64`.
        '''
        self.is_local = is_local
        self.file = file
        self.remote = remote
        self.elf = elf
        if elf:
            self.arch = elf.arch
        else:
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
