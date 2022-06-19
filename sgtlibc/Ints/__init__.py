# int overflow
from enum import Enum


class TypeInt(Enum):
    BYTE = 2
    SHORT = 4
    INT16 = 16
    INT32 = 32
    INT64 = 64


class TypeFLOAT(Enum):
    FLOAT = 32
    DOUBLE = 64


def __int_get_max_value(type: TypeInt, with_sign: bool = False):
    max_value = 1 << type.value
    if with_sign:
        max_value >>= 1
    return max_value


def __int_get_value(type: TypeInt, with_sign: bool = False, value: int = 0):
    max_value = 1 << type.value
    if with_sign:
        max_value >>= 1

# ff
# 7f
