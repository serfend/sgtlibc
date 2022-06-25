#!/usr/bin/env python
from __future__ import print_function
import time

from sgtlibc.utils.compat import deprecated
from sgtpyutils.logger import logger
import os
import re
import sys
from typing import Callable, List, Tuple
from sgtpyutils.xls_txt import dict2sheet, list2sheet
import sgtpyutils.configuration as config


class LibcSearcher(object):
    def __init__(self, func=None, address=None):
        self.files = []
        self.conditions = {}
        self.condition_reg = {}
        # is_found,db_description,db_count
        self.__db_result = [False, None, None]
        self.dump_result = {}
        self.offset = None
        if func is not None and address is not None:
            self.add_condition(func, address)
        database_path = os.path.join(
            os.path.realpath(os.path.dirname(__file__)), os.pardir, f"libc-database{os.sep}db{os.sep}")
        self.libc_database_path = [os.path.realpath(database_path)]
        ext_data_path = config.get('extension_database_path', './ext_libs')
        if not ext_data_path is None and os.path.isdir(ext_data_path):
            logger.info(f'load user libc-database :{ext_data_path}')
            self.libc_database_path.append(ext_data_path)
        self.__db = []
        self.current_focus_db = 0
        self.current_filter = None
        self.is_first_filter = True
        self.init_db()

    def __get_db_path(self, db: Tuple) -> str:
        return f'{self.libc_database_path[db[0]]}{os.sep}{db[1]}'

    def init_db(self):
        self.files = []
        # only read "*.symbols" file to find
        symbol_re = re.compile('^.*symbols$')

        def load_single(index: int, db: str):
            for _, _, f in os.walk(db):
                for i in f:
                    i = symbol_re.findall(i)
                    if i:
                        self.files.append([index, i[0]])
        [load_single(index, db)
         for index, db in enumerate(self.libc_database_path)]

    @property
    def db_result(self):
        '''
        Tuple[is_found,db_description,db_count]
        '''
        return self.__db_result

    def add_condition(self, func, address):
        if not isinstance(func, str):
            logger.error("The function should be a string")
            sys.exit()
        if not isinstance(address, int):
            logger.error("The address should be an int number")
            sys.exit()
        addr_last12 = address & 0xfff
        content = f"(\r?\n|(?<!\n)\r|^){func}\s.*{addr_last12:03x}(?!\d| |\w\W)(\r?\n|(?<!\n)\r)"
        re_compile = re.compile(content)
        self.conditions[func] = address
        self.condition_reg[func] = re_compile

    def decided(self, max_show_count: int = 5, filter: Callable = None) -> Tuple:
        '''
        matching libc-database with condition(s)
        return is_found,db_description,db_count
        '''
        if len(self.conditions) == 0:
            logger.error(
                "No leaked info provided.\nPlease supply more info using add_condition(leaked_func, leaked_address).")
            sys.exit(0)

        self.list_conditions()
        self.search_db()
        return self.list_db(
            max_show_count=max_show_count,
            filter=filter
        )

    def list_conditions(self):
        result_header = {
            'Condition Function': 'Address In ELF',
            '-'*20: '-'*10
        }
        content = '\n'.join(dict2sheet(
            data=self.conditions, header=result_header))
        a = f'finding matchable libc in {len(self.files)} files'
        b = f'with {len(self.conditions)} condition(s)'
        logger.debug(f'{a} , {b}\n{content}')
        return self.conditions

    def search_db(self):
        result = []
        for symbol_file in self.files:
            with open(self.__get_db_path(symbol_file), "rb") as fd:
                data = fd.read().decode(errors='ignore')
                fitted_libc = True
                for x in self.condition_reg:
                    if next(self.condition_reg[x].finditer(data), None) is None:
                        fitted_libc = False
                        break
                if fitted_libc:
                    result.append(symbol_file)
        self.__db = result

    @property
    @deprecated("Use all_db([filter]) to get databases")
    def db(self):
        return self.all_db()

    def all_db(self, filter: Callable = None):
        '''
        get all database searched from condition.
        return Tuple[
            lib_path_index:int libc-database-path-index,
            db_name:str
            ]
        '''
        db_list = self.__db

        if not db_list:
            return []
        if not filter:
            def filter(x): return True
        result = [x for x in db_list if filter(x[1])]
        filter_count = len(db_list) - len(result)
        if filter_count > 0:
            notice = f'{filter_count} db(s) is filtered by user-setting.'
            if self.is_first_filter:
                self.is_first_filter = False
                db_names = [x[1] for x in db_list]
                result_names = [x[1] for x in result]
                hidden = list(set(db_names).difference(set(result_names)))
                hidden = '\n'.join(list2sheet(hidden))
                notice = f'{notice}\n{hidden}'
            logger.warning(notice)
        return result

    def list_db(self, max_show_count: int = 5, filter: Callable = None):
        '''
        return is_found,db_description,db_count
        '''
        result = self.all_db(filter=filter)
        count = len(result)
        if count == 0:
            logger.error(
                "No matched libc, please add more libc or try others elf.got.")
            return False, None, 0
        result = '\n'.join(list2sheet(
            lines=result,
            line_renderer=lambda x: self.pmore(x),
            max_show_count=max_show_count
        ))
        logger.info(f'{count} db(s) is found:\n{result}')
        return True, result, count

    def pmore(self, db: Tuple):
        result = self.__get_db_path(db)[:-8]  # .strip(".symbols")
        target = f'{result}.info'
        if os.path.exists(target):
            with open(target) as f:
                info = f.read().strip()
        else:
            info = 'noalias'
        return f'{info} ({result})'

    def dump(self, func: List = None, db_index: int = -1, max_show_count: int = 5, filter: Callable = None):
        '''
        dump libc-addr from search-result
        func: List[str] the function address to get
        db_index: from 0 to n , default use `current_focus_db`
        filter: Callable[libc_name:str]->bool , filter result with this predict
        '''
        if not filter:
            filter = self.current_filter
        else:
            self.current_filter = filter
            self.is_first_filter = True
        if db_index < 0:
            db_index = self.current_focus_db
        elif self.current_focus_db != db_index:
            self.current_focus_db = db_index
            self.dump_result = {}  # reset if db modified

        if not isinstance(db_index, int):
            db_index = int(db_index)
        # check if no result been calculated
        db_list = self.all_db(filter=filter)
        if not self.__db:
            self.__db_result = self.decided(
                max_show_count=max_show_count,
                filter=filter
            )
            # if no matched , return none
            if not self.__db_result[0]:
                return None
            db_list = self.all_db(filter=filter)

        if len(db_list) < db_index + 1:
            logger.error(
                f'only have {len(db_list)} to select.index-{db_index} not exist.\n')
            self.list_db(
                max_show_count=max_show_count,
                filter=filter
            )
            return None
        db_item: Tuple = db_list[db_index]
        db_name = db_item[1]
        logger.debug(f'dumping db[{db_index}]:{self.pmore(db_item)}')
        db: str = self.__get_db_path(db_item)
        with open(db, 'rb') as fd:
            data = fd.read().decode(errors='ignore').strip("\n").split("\n")
            if not func:
                from . import commons
                self.dump_result = {}  # reset if user pass none funcs
                func = [commons.__dict__[x]
                        for x in commons.__dict__ if x.startswith('SYMBOL_')]

            for d in data:
                desc = d.split(' ')
                f = desc[0]
                addr = desc[1]
                if f in func:
                    self.dump_result[f] = int(addr, 16)
            result_header = {
                'Function Name': 'Address In Libc',
                '-'*20: '-'*10
            }
            output = '\n'.join(dict2sheet(
                data=self.dump_result,
                header=result_header,
            ))
            logger.info(f'function(s) in libc {db_name}:\n{output}')

            self.sync_offset()
            return self.dump_result

    def sync_offset(self):
        '''
        sync offset from dump-result
        '''
        if not self.dump_result:
            return logger.error('should dump a result first')
        if not self.conditions:
            return logger.error('invalid dump.no any condition is specify')
        user_leak = [x for x in self.conditions][0]
        self.set_offset_by_function(user_leak, self.conditions[user_leak])

    def set_offset_by_function(self, target_function: str, elf_address: int):
        logger.debug(
            f'set offset by function:{target_function},address:{hex(elf_address)}')
        check_sign = int(f'0x{hex(int(elf_address))[2:4]}', 16)
        if check_sign ^ 0xf7:
            logger.warning(
                'function offset\'s expected to be start with 0xf7,current offset may NOT RIGHT.')

        if not self.check_dumped_function(target_function):
            return
        if elf_address == self.dump_result[target_function]:
            return logger.warning(f'elf_address is equal to dump_result,check if you pass a wrong value({hex(elf_address)})')
        return self.set_offset_direct(elf_address - self.dump_result[target_function])

    def set_offset_direct(self, offset: int):
        logger.debug(f'set_offset: is set to:{hex(offset)}')
        self.offset = offset
        check_sign = self.offset & 0xfff
        if check_sign ^ 0:
            logger.warning(
                'offset\'s expected to be end with 0x000,current offset may NOT RIGHT.')
            time.sleep(5)

    def check_dumped_function(self, target_function: str) -> bool:
        if not target_function in self.dump_result:
            r = self.dump([target_function], self.current_focus_db)
            if not r:
                logger.error('dump result is empty')
                return False
            if not target_function in r:
                logger.warning(
                    f'target function [{target_function}] not found')
                return False
        return True

    def get_address(self, target_function: str) -> int:
        if not self.check_dumped_function(target_function):
            return None
        if self.offset == None:
            logger.warning(
                'offset haven\'t been set,please use `set_offset` before get_address')
            return None
        return self.offset + self.dump_result[target_function]


if __name__ == "__main__":
    obj = LibcSearcher("gets", 0xaa0)
    obj.dump()
