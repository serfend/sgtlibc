#!/usr/bin/env python
from __future__ import print_function
from .. import logger
import os
import re
import sys
from typing import List
logger = logger.logger


class LibcSearcher(object):
    def __init__(self, func=None, address=None):
        self.condition = {}
        if func is not None and address is not None:
            self.add_condition(func, address)
        self.libc_database_path = os.path.join(
            os.path.realpath(os.path.dirname(__file__)), os.pardir, f"libc-database{os.sep}db{os.sep}")
        self.libc_database_path = os.path.realpath(self.libc_database_path)
        self.db = ""

    def add_condition(self, func, address):
        if not isinstance(func, str):
            print("The function should be a string")
            sys.exit()
        if not isinstance(address, int):
            print("The address should be an int number")
            sys.exit()
        self.condition[func] = address

    # Wrapper for libc-database's find shell script.
    def decided(self):
        if len(self.condition) == 0:
            logger.error(
                "No leaked info provided.\nPlease supply more info using add_condition(leaked_func, leaked_address).")
            sys.exit(0)

        conditions = []
        for name, address in self.condition.items():
            addr_last12 = address & 0xfff
            # content = f"{addr_last12:x}"
            content = f"[\s\S]*?{name}\s.*{addr_last12:x}[\s\S]*?"
            conditions.append(re.compile(content))

        db = self.libc_database_path
        files = []
        # only read "*.symbols" file to find
        symbol_re = re.compile('^.*symbols$')
        for _, _, f in os.walk(db):
            for i in f:
                i = symbol_re.findall(i)
                if i:
                    files.append(i[0])
        logger.debug(
            f'finding matchable libc in {len(files)} files , with {len(conditions)} condition(s)')
        result = []
        for symbol_file in files:
            with open(f'{db}{os.sep}{symbol_file}', "rb") as fd:
                data = fd.read().decode(errors='ignore')
                fitted_libc = True
                for x in conditions:
                    if not x.match(data):
                        fitted_libc = False
                        break
                if fitted_libc:
                    result.append(symbol_file)
        self.db = result
        return self.list_db()

    def list_db(self):
        result = self.db
        count = len(result)
        if count == 0:
            logger.error("No matched libc, please add more libc or try others")
            return False
        result = [f"{x+1:3d}: {self.pmore(result[x])}" for x in range(count)]
        result = "\n".join(result)
        logger.info(f'db found:\n{result}')
        return True

    def pmore(self, result):
        result = result[:-8]  # .strip(".symbols")
        target = f'{self.libc_database_path}{os.sep}{result}.info'
        if os.path.exists(target):
            with open(target) as f:
                info = f.read().strip()
        else:
            info = 'noalias'
        return f'{info} ({result})'

    # Wrapper for libc-database's dump shell script.
    def dump(self, func: List = None, db_index: int = 0):
        if not isinstance(db_index, int):
            db_index = int(db_index)
        if not self.db:
            if not self.decided():
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
                func = [commons.__dict__[x]
                        for x in commons.__dict__ if x.startswith('SYMBOL_')]
            result_header = {
                'Function Name': 'Address In Libc',
                '-'*20: '-'*10
            }
            result = dict(result_header)

            for d in data:
                desc = d.split(' ')
                f = desc[0]
                addr = desc[1]
                if f in func:
                    result[f] = int(addr, 16)

            def left_just(x: str):
                return x.ljust(30, ' ')
            output = [
                f'{left_just(x)}\t{hex(result[x]) if isinstance(result[x],int) else result[x]}' for x in result]
            output = '\n'.join(output)
            logger.info(f'function(s) in libc {db_name}:\n{output}')
            for i in result_header:
                del result[i]
            return result


if __name__ == "__main__":
    obj = LibcSearcher("gets", 0xaa0)
    obj.dump()
