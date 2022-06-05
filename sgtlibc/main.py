from .LibcSearcher import LibcSearcher
from . import __version__, logger
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
        help='show version (default: %(default)s).',
    )
    args = parser.parse_args()
    return args


def run():
    global usage
    searcher = LibcSearcher()
    args = build_parser()
    if args.update or args.update == None:
        return update_database()
    if args.version or args.version == None:
        logger.info(__version__.__version__)
        return
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
    else:
        logger.error(f'no func-addr pair is specify , please do as:{usage}')
        return
    searcher.dump(dump, index)


if __name__ == '__main__':
    run()
