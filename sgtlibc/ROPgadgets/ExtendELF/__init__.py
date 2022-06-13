# use pwntools ELF for read ROP and return its context
from typing import Dict, List, Tuple, overload
import pwn
from pwnlib.rop.gadgets import Gadget
from ... import logger
from sgtpyutils.xls_txt import list2sheet, dict2sheet
# if you want direct run this script , comment above and uncomment following
# class A:
#     pass
# logger = A()
# logger.__setattr__('info', lambda x: print(x))


class ELF(pwn.ELF):
    def gadget_tostring(self, x: Gadget):
        detail = ';'.join(x.insns)
        # actions = '_'.join([r for r in x.regs])
        is_pop = True
        if not x.regs:
            name = 'ret' if detail == 'ret' else 'unknown'
            is_pop = False
            order = '50'
        elif any(['add' in x for x in x.insns]):
            is_pop = False
            order = '10'
            name = 'add_action'
        else:
            name = '_'.join(x.insns).replace('pop ', '')
            name = f'rop_{name}'
            if name.endswith('_ret'):
                name = name[:-4]
            order = '90'
        description = f'{name} = 0x{x.address:x} # {detail}'
        order += detail
        return (name, description, is_pop, x.address, order)

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
                          for x in g], key=lambda x: x[4])
        description = '\n'.join([x[1] for x in rop_pops])
        result = [[x[0], x[3]] for x in rop_pops]
        r.append(f'rop on pop_register:\n{description}')
        result = dict(result)
        result_with_no_prefix = [[x[4:] if x.startswith(
            'rop') else x, result[x]] for x in result]
        result.update(result_with_no_prefix)
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
                line_renderer=lambda i: f'{name}_{i} = {hex(data[i])}',
                show_line_number=False
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
        self.last_string_target = strs
        if isinstance(strs, List):
            for i in strs:
                self.__search_string(i, search_all)
        else:
            self.__search_string(strs, search_all)
            if (isinstance(strs, str) or isinstance(strs, bytes)) and not search_all:
                # user seems expected only one result , than directly return
                return self.list_result(only_return_one=True)
        return self.list_result()

    @overload
    def list_result(self) -> Dict:
        ...

    @overload
    def list_result(self, only_return_one: bool) -> int:
        ...

    def list_result(self, only_return_one: bool = False) -> Dict:
        r = self.result_string
        str_targets = ','.join([str(x) for x in self.last_string_target]) if isinstance(
            self.last_string_target, Dict) else self.last_string_target
        if not r or (isinstance(r, Dict) and all([not r[x] for x in r])):
            logger.warning(f'not found any strings in {str_targets}')
            return None if only_return_one else r

        output = dict2sheet(r)
        output = '\n'.join(output)
        logger.info(f'\nfound strings in {str_targets}.\n{output}')
        if only_return_one:
            return r[list(r)[0]]
        return r

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
        self.result_string[target] = r
        return True


# a = ELF('./pwn1')
# print(a.get_rop())
