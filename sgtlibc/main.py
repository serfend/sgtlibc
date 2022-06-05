from .LibcSearcher import LibcSearcher
from . import __version__
import argparse
from .logger import logger


def run():
    logger.debug('program start')
    parser = argparse.ArgumentParser(description=__version__.__description__)
    usage = 'puts:aa0+read:140 , its means func-puts address = 0xaa0;func-read address = 0x140'
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
        '-u',
        '--update',
        default=False,
        nargs=argparse.OPTIONAL,
        dest='update',
        help='update current libc database from internet , need non-microsoft-windows environment  (default: %(default)s).',
    )
    searcher = LibcSearcher()
    args = parser.parse_args()
    if args.update or args.update == None:
        from libc_database import update
        logger.debug('updating database use libc-database wheel')
        return update()
    funcs_with_addresses = args.funcs_with_addresses
    dump = args.dump
    index = args.index
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
        searcher.dump(dump, index)
    else:
        logger.error(f'no func-addr pair is specify , please do as:{usage}')


if __name__ == '__main__':
    run()
