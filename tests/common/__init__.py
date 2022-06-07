import os


def get_resources_by_path(child_path: str):
    resource_path = os.path.dirname(
        os.path.realpath(os.path.join(__file__, os.pardir)))
    resource_path = os.path.join(resource_path, 'resources')
    return os.path.realpath(os.path.join(resource_path, child_path))


def get_elf_resources(resource_name: str):
    return get_resources_by_path(f'elf{os.path.sep}{resource_name}')
