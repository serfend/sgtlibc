# use pwntools ELF for read ROP and return its context
from typing import Dict, List, Tuple, overload
import pwn
from pwnlib.rop.gadgets import Gadget
from .. import logger
from sgtpyutils.xls_txt import list2sheet
# if you want direct run this script , comment above and uncomment following
# class A:
#     pass
# logger = A()
# logger.__setattr__('info', lambda x: print(x))


class ELF(pwn.ELF):
    def gadget_tostring(self, x: Gadget):
        detail = ';'.join(x.insns)
        actions = '_'.join([r for r in x.regs])
        is_pop = True
        if not actions:
            actions = 'ret' if detail == 'ret' else 'unknown'
            is_pop = False
        name = f'rop_pop_{actions}'
        description = f'{name} = 0x{x.address:x} # {detail}'
        return (actions, description, is_pop, x.address)

    def get_rop(self, show_banner: bool = True):
        r = ['ELF::get_rop']
        rop = pwn.ROP(self)
        banner = 'SHOW ROP INFO'
        if show_banner:
            r.append(banner.center(40, '#'))
        c = rop.chain()
        if len(c):
            r.append(f'# chains:\n{rop.chain()}')
        else:
            r.append(f'# chains not found')
        g = rop.gadgets
        rop_pops = sorted([self.gadget_tostring(g[x])
                          for x in g], key=lambda x: x[2])
        description = '\n'.join([x[1] for x in rop_pops])
        result = [[x[0], x[3]] for x in rop_pops]
        r.append(f'rop on pop_register:\n{description}')
        result = dict(result)
        self.rop = result
        if show_banner:
            r.append(banner.center(40, '#'))
        logger.info('\n'.join(r))
        return result
    StringDefault = [b'/bin/bash', b'bash', b'sh']

    def show_symbols(self):
        def renderer(name: str):
            if isinstance(name, List):
                excludes = name[1:]
                name = name[0]
                data = getattr(self, name)
                lines = [x for x in data if all(
                    [not x.startswith(des) for des in excludes])]
                for ex in excludes:
                    dic = getattr(self, ex)
                    lines = [x for x in lines if not x in dic]
            else:
                data = getattr(self, name)
                lines = list(data)
            r = [f'# {name}'.center(30, '#')]
            r += list2sheet(
                lines=lines,
                line_renderer=lambda i: f'{name}_{i} = {hex(data[i])}'
            )
            return '\n'.join(r)
        r = ['\n', f'# show_symbols of {self.path[-20:]}'.center(35)]
        export = [['symbols', 'got', 'plt'], 'got', 'plt']
        r += [renderer(x) for x in export]
        content = '\n'.join(r)
        logger.info(content)

    @overload
    def search_string(self):
        ...

    @overload
    def search_string(self, target_string: bytes = StringDefault[0]) -> int:
        ...

    @overload
    def search_string(self, target_strings: List = StringDefault) -> int:
        ...

    @overload
    def search_string(self, target_string: bytes = StringDefault[0], search_all: bool = False) -> List:
        ...

    @overload
    def search_string(self, target_strings: List = StringDefault, search_all: bool = False) -> List:
        ...

    def search_string(self, strs: List = None, search_all: bool = False):
        self.result_string = {}
        if strs is None:
            strs = ELF.StringDefault
        if isinstance(strs, List):
            for i in strs:
                self.__search_string(i, search_all)
            return self.result_string
        else:
            self.__search_string(strs, search_all)
        if (isinstance(strs, str) or isinstance(strs, bytes)) and not search_all:
            # user seems expected only one result , than directly return
            result = [self.result_string[x] for x in self.result_string]
            if not result:
                return None
            return result[0]
        return self.result_string

    def __search_string(self, target: bytes, all: bool):
        if isinstance(target, str):
            logger.warning(
                f'require target-strings to be a bytes-like,assuming ascii encode:{target}')
            target = target.encode('ascii')
        result = self.search(target)
        r = None
        if not all:
            # r = next(result)
            for i in result:
                r = i
                break
        else:
            r = [x for x in result]
        if r:
            info = hex(r) if isinstance(r, int) else [hex(x) for x in r]
            logger.info(f'found strings {target} in {info}')
        self.result_string[target] = r
        return True


# a = ELF('./pwn1')
# print(a.get_rop())
