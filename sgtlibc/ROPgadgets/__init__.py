# use pwntools ELF for read ROP and return its context
import pwn
from pwnlib.rop.gadgets import Gadget
from .. import logger

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

    def get_rop(self):
        rop = pwn.ROP(self)
        logger.info('dump rop chain and registers')
        logger.info(f'chains:\n{rop.chain()}')
        g = rop.gadgets
        rop_pops = sorted([self.gadget_tostring(g[x])
                          for x in g], key=lambda x: x[2])
        description = '\n'.join([x[1] for x in rop_pops])
        result = [[x[0], x[3]] for x in rop_pops]
        logger.info(f'rop on pop_register:\n{description}')
        return dict(result)


# a = ELF('./pwn1')
# print(a.get_rop())
