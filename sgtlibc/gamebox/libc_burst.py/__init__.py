from typing import Callable
from ..client import GameBoxConfig
from ...LibcSearcher import LibcSearcher
from ... import logger, gamebox as gb
from ...gamebox import ELF


class LibcBursterExp:
    def __init__(self, leak_method: Callable, exp_before_leak: Callable, exp_after_leak: Callable):
        '''
        leak_method: Callable[function_name:str] -> int
        exp_before_leak: Callable -> None
        exp_after_leak: Callable[libc_dump_dict:dict[str:int]] -> None
        '''
        self.leak_method = leak_method
        self.exp_before_leak = exp_before_leak
        self.exp_after_leak = exp_after_leak

    def start_leak(self, default_function: str):
        # TODO implement it
        if self.exp.exp_before_leak:
            self.exp.exp_before_leak()
        self.exp.leak_method()


class LibcBurster:
    # TODO implement it
    '''
    you can input your payload for burster
    with libc-database search result
    '''

    def __init__(self, config: GameBoxConfig, searcher: LibcSearcher, exp: LibcBursterExp):
        self.exp = exp
        self.searcher = searcher
        self.config = config

    def run_single(self, index: int):
        name = self.searcher.db[index]
        logger.debug(f'try libc[{index}] {name}')
        gb.set_config(self.config)

        libc_data = self.searcher.dump(db_index=index)

    def run(self):
        self.start_leak()
        for index, name in enumerate(self.searcher.db):
            try:
                self.run_single(index)
            except:
                pass
