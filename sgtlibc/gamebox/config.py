from ..ROPgadgets import ELF


class GameBoxConfig:
    def __init__(self, is_local: bool = True, file: str = None, remote: str = None, arch: str = 'amd64', os: str = 'linux', log_level: str = 'debug', auto_load: bool = False):
        '''
        if auto_load is True, it would auto load its context.amd you can use `pc`/`uc` also, instead of `p32`/`u32` or `p64`/`u64`.
        '''
        self.is_local = is_local
        self.file = file
        self.remote = remote
        self.auto_load = auto_load
        self.elf = ELF(file) if auto_load else None
        self.arch = self.elf.arch if self.elf else arch
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
