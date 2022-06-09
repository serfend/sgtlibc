#!/usr/bin/env python
from __future__ import print_function
from .. import logger
import os
import re
import sys
from typing import Callable, List, Tuple
from sgtpyutils.xls_txt import dict2sheet, list2sheet


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
        self.libc_database_path = os.path.join(
            os.path.realpath(os.path.dirname(__file__)), os.pardir, f"libc-database{os.sep}db{os.sep}")
        self.libc_database_path = os.path.realpath(self.libc_database_path)
        self.db = ""
        self.current_focus_db = 0
        self.init_db()

    def init_db(self):
        db = self.libc_database_path
        self.files = []
        # only read "*.symbols" file to find
        symbol_re = re.compile('^.*symbols$')
        for _, _, f in os.walk(db):
            for i in f:
                i = symbol_re.findall(i)
                if i:
                    self.files.append(i[0])

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
        content = f"[\s\S]*?{func}\s.*{addr_last12:x}[\s\S]*?"
        re_compile = re.compile(content)
        self.conditions[func] = address
        self.condition_reg[func] = re_compile

    def decided(self) -> Tuple:
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
        return self.list_db()

    def list_conditions(self):
        result_header = {
            'Condition Function': 'Address In ELF',
            '-'*20: '-'*10
        }
        content = '\n'.join(dict2sheet(data=self.conditions, header=result_header))
        a = f'finding matchable libc in {len(self.files)} files'
        b = f'with {len(self.conditions)} condition(s)'
        logger.debug(f'{a} , {b}\n{content}')
        return self.conditions

    def search_db(self):
        result = []
        for symbol_file in self.files:
            with open(f'{self.libc_database_path}{os.sep}{symbol_file}', "rb") as fd:
                data = fd.read().decode(errors='ignore')
                fitted_libc = True
                for x in self.condition_reg:
                    if not self.condition_reg[x].match(data):
                        fitted_libc = False
                        break
                if fitted_libc:
                    result.append(symbol_file)
        self.db = result

    def list_db(self):
        '''
        return is_found,db_description,db_count
        '''
        result = self.db
        count = len(result)
        if count == 0:
            logger.error("No matched libc, please add more libc or try others")
            return False, None, 0
        result = '\n'.join(list2sheet(
            lines=self.db,
            line_renderer=lambda x: self.pmore(x)
        ))
        logger.info(f'{count} db(s) is found:\n{result}')
        return True, result, count

    def pmore(self, result):
        result = result[:-8]  # .strip(".symbols")
        target = f'{self.libc_database_path}{os.sep}{result}.info'
        if os.path.exists(target):
            with open(target) as f:
                info = f.read().strip()
        else:
            info = 'noalias'
        return f'{info} ({result})'

    def dump(self, func: List = None, db_index: int = -1):
        '''
        dump libc-addr from search-result
        func: List[str] the function address to get
        db_index: from 0 to n , default use `current_focus_db`
        '''
        if db_index < 0:
            db_index = self.current_focus_db
        elif self.current_focus_db != db_index:
            self.current_focus_db = db_index
            self.dump_result = {}  # reset if db modified

        if not isinstance(db_index, int):
            db_index = int(db_index)
        if not self.db:
            self.__db_result = self.decided()
            if not self.__db_result[0]:
                return False
        if len(self.db) < db_index + 1:
            logger.error(
                f'db[{db_index}] not exist.\n')
            self.list_db()
            return
        db_name = self.db[db_index]
        logger.debug(f'dumping db[{db_index}]:{self.pmore(db_name)}')
        db = f'{self.libc_database_path}{os.sep}{db_name}'
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
            output = '\n'.join(dict2sheet(data=self.dump_result, header=result_header))
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
        if not self.check_dumped_function(target_function):
            return
        if elf_address == self.dump_result[target_function]:
            return logger.warning(f'elf_address is equal to dump_result,check if you pass a wrong value({hex(elf_address)})')
        return self.set_offset_direct(elf_address - self.dump_result[target_function])

    def set_offset_direct(self, offset: int):
        logger.debug(f'set_offset: is set to:{hex(offset)}')
        self.offset = offset

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
