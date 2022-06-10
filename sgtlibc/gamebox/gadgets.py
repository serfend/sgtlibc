from argparse import ArgumentError
from typing import Dict, List, Tuple, overload
from . import convert
from ..ROPgadgets.gadgets_exploit import *


@overload
def build(gadgets: List) -> bytes:
    '''
    build data from gadgets generate from `ROPgadgets.gadgets_exploit`
    '''
    ...


@overload
def build(gadget_name: str, *params):
    '''
    direct use gadget from `ROPgadgets.gadgets_exploit` and input its params
    '''
    ...


valid_functions: Dict = None


def init_functions():
    global valid_functions
    if valid_functions:
        return
    g = globals()
    k = [x for x in g if x.startswith('gadget_')]
    v = [g[x] for x in k]
    valid_functions = dict(zip(k, v))


def build(*params) -> bytes:
    global valid_functions
    if isinstance(params[0], str):
        init_functions()
        func_name = params[0]
        if not func_name in valid_functions:
            raise ImportError(f'{func_name} not found')
        func = valid_functions[func_name]
        gadgets = func(*params[1:])
    elif isinstance(params[0], List):
        gadgets = params[0]
    else:
        raise ArgumentError('invalid type of gadgets')

    def renderer(item) -> bytes:
        if isinstance(item, Tuple) or isinstance(item, List):
            return getattr(convert, item[0])(item[1])
        return item
    return b''.join([renderer(x) for x in gadgets])
