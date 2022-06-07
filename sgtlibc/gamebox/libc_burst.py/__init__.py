from typing import Callable
from ..client import GameBoxConfig
from ...LibcSearcher import LibcSearcher
from ... import logger, gamebox as gb


class LibcBursterExp:
    def __init__(self, callback: Callable):
        '''
        callback: Callable[libc_dump_dict]
        '''
        self.callback = callback


class LibcBurster:
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
        libc_data = self.searcher.dump(db_index = index)
        

    def run(self):
        for index, name in enumerate(self.searcher.db):
            try:
                self.run_single(index)
            except:
                pass
