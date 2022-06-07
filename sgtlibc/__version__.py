__title__ = "sgtlibc"
__description__ = f"a offline python-lib for search libc function.for search version of libc.you can use like:`{__title__} puts:aa0+read:140 --dump system binsh` or in python , like : `py:import {__title__};s = {__title__}.LibcSearcher();s.add_condition('puts',0xaa0)`"
__keywords__ = ['libcsearcher']
__url__ = "https://github.com/serfend/sgtlibc"
__version__ = "1.7.49"
__author__ = "serfend"
__author_email__ = "serfend@foxmail.com"
__license__ = "MIT Licence"

__public_path__ = './dist'