import os
import sgtlibc.ROPgadgets
from .shell import check_shell_validate


def get_resources_by_path(child_path: str):
    resource_path = os.path.dirname(
        os.path.realpath(os.path.join(__file__, os.pardir)))
    resource_path = os.path.join(resource_path, 'resources')
    return os.path.realpath(os.path.join(resource_path, child_path))


def get_elf_resources(resource_name: str):
    '''
    return resouces
    '''
    return get_resources_by_path(f'elf{os.path.sep}{resource_name}')


def get_demo_elf():
    '''
    direct return pwn1
    '''
    return get_elf_resources('pwn1')


def get_demo_ELF():
    '''
    direct return ELF object of pwn1
    '''
    path = get_demo_elf()
    elf = sgtlibc.ROPgadgets.ELF(path)
    return elf
