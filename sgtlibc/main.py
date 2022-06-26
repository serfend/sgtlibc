import os
import time
from typing import List

from sgtlibc.utils import configuration
from .LibcSearcher import LibcSearcher
from . import __version__
from sgtpyutils.logger import logger
from sgtpyutils.extensions import flat
import argparse


def update_database():
    from .libc_database import update
    logger.debug('updating database use libc-database wheel')
    return update()


usage = 'puts:aa0+read:140 , its means func-puts address = 0xaa0;func-read address = 0x140'


def build_parser():
    parser = argparse.ArgumentParser(description=__version__.__description__)
    global usage
    parser.add_argument(
        'funcs_with_addresses',
        nargs=argparse.OPTIONAL,
        default=None,
        help=f'specify `func-name` and `func address` , split by `|`,eg: {usage}  (default: %(default)s).',
    )
    parser.add_argument(
        '-d',
        '--dump',
        default=["__libc_start_main_ret", "system", "dup2", "read", "write",
                 "str_bin_sh"],
        nargs=argparse.ZERO_OR_MORE,
        dest='dump',
        help='select funcs to dump its info (default: %(default)s).',
    )

    parser.add_argument(
        '-i',
        '--index',
        default=0,
        nargs=argparse.OPTIONAL,
        dest='index',
        help='db index on multi-database found occation (default: %(default)s).',
    )

    parser.add_argument(
        '-s',
        '--symbols',
        default=False,
        nargs=argparse.OPTIONAL,
        dest='symbols',
        help='convert libc-elf file to symbols-file,use `libc_path [alias]` to convert.',
    )
    parser.add_argument(
        '-u',
        '--update',
        default=False,
        nargs=argparse.OPTIONAL,
        dest='update',
        help='update current libc database from internet , need non-microsoft-windows environment  (default: %(default)s).',
    )
    parser.add_argument(
        '-v',
        '--version',
        default=False,
        nargs=argparse.OPTIONAL,
        dest='version',
        help='show version',
    )
    args = parser.parse_args()
    return args


def do_symbols(libc_and_name: str):
    data = libc_and_name.split(':')
    if len(data) > 1:
        libc_path = data[0]
        libc_alias = data[1]
    else:
        libc_path = data[0]
        libc_alias = None
    from .libc_database.libc_handle import run, check_exist
    database_path = configuration.get(configuration.extension_database_path)
    if not os.path.exists(libc_path):
        logger.error(f'invalid path:{libc_path}')
        return
    to_handle = []
    if os.path.isdir(libc_path):
        to_handle = [x[2] for x in os.walk(libc_path)] # get all files
        to_handle = flat(to_handle)
        files_desc = '\n'.join(to_handle)
        logger.info(
            f'{files_desc}\ntarget path {libc_path} is a directory,will handle {len(to_handle)} file(s)...')
        time.sleep(5)
    else:
        to_handle.append(libc_path)
    def handle_single(elf_path_single: str) -> str:
        description_exist = check_exist(
            elf_file_path=elf_path_single
        )
        if not description_exist is None:
            logger.debug(
                f'this libc found in previous database:\n{description_exist}')
            return
        logger.info('this is a new elf-file,move to user-lib')
        save_path = run(
            elf_file_path=elf_path_single,
            output_path=database_path,
            alias=libc_alias
        )
        logger.info(f'libc been saved to : {save_path}')
        return save_path

    save_paths = []
    for elf_path_single in to_handle:
        r = handle_single(elf_path_single)
        if r:
            save_paths.append(r)
    if len(to_handle) > 1:
        return save_paths
    return None if len(save_paths) == 0 else save_paths[0]


def do_dump(searcher: LibcSearcher, funcs_with_addresses: str, dump: List, index: int):
    if not funcs_with_addresses:
        funcs_with_addresses = ''
    funcs_with_addresses = funcs_with_addresses.split('+')
    if funcs_with_addresses:
        for i in funcs_with_addresses:
            if not i:
                logger.error(
                    f'empty input is a invalid config. please do as:{usage}')
                continue
            items = i.split(':')
            if len(items) < 2:
                logger.error(f'invalid input with `{i}`,please do as:{usage}')
                continue
            if not items[1].startswith('0x'):
                items[1] = f'0x{items[1]}'
            addr = int(items[1], 16)
            func = items[0]
            searcher.add_condition(func, addr)
            logger.debug(f'function:{func},address:{hex(addr)}')
    else:
        logger.error(f'no func-addr pair is specify , please do as:{usage}')
        return
    searcher.dump(dump, index)


def run():
    global usage
    searcher = LibcSearcher()
    args = build_parser()
    if args.update or args.update == None:
        return update_database()
    if args.version or args.version == None:
        logger.info(__version__.__version__)
        return
    if args.symbols:
        return do_symbols(
            libc_and_name=args.symbols
        )
    return do_dump(
        searcher=searcher,
        funcs_with_addresses=args.funcs_with_addresses,
        dump=args.dump,
        index=args.index,
    )


if __name__ == '__main__':
    run()
