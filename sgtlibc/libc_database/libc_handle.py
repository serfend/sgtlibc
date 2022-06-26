from subprocess import Popen, PIPE
import os
import sys
import time
from typing import Dict

from sgtlibc.LibcSearcher import LibcSearcher
from ..ROPgadgets.ExtendELF import ELF


def run_cmd(cmd: str) -> str:
    return Popen(cmd, stdout=PIPE, shell=True).stdout.read().decode()


def load_symbols_by_cmd(elf_path: str):
    func_addresses = run_cmd(f'nm {elf_path} | awk \'{{print $3 " " $1}}\'')
    binsh_address = run_cmd(
        f'ROPgadget --string "/bin/sh" --binary {elf_path}').split('\n')
    binsh_address = binsh_address[2].split(' ')  # line-3
    binsh_address = f'str_bin_sh {binsh_address[0]}'  # space-0
    return f'{func_addresses}{binsh_address}'


def load_symbols_by_pwntools(elf_path: str):
    elf = ELF(elf_path)
    r = {}
    except_func = ['got.', 'plt.']

    def check_except(func: str):
        if len(func) < 2:
            return True
        for exc in except_func:
            if func.startswith(exc):
                return True
            return False
    for func in elf.symbols:
        if check_except(func):
            continue
        r[func] = elf.symbols[func]
    s = elf.search_string(b'/bin/sh')
    if not s:
        print('binsh not found')
    r['str_bin_sh'] = s
    return r


def load_symbos_line_by_pwntools(elf_path: str):
    r = load_symbols_by_pwntools(elf_path)
    lines = [f'{x} {r[x]:03x}' for x in r]
    return '\n'.join(lines)


def load_symbos_line(elf_path: str):
    return load_symbos_line_by_pwntools(elf_path)


def get_elf_version(elf_path: str) -> str:
    elf = ELF(elf_path)

    result = run_cmd(f'strings {elf_path} | grep "(.*GLIBC.*)" -o')
    if len(result) < 5:
        return None
    result = result.replace(' ', '_')
    result = result.replace('\n', '')
    result = result.replace('(', '')
    result = result.replace(')', '')
    return f'{result}_{elf.arch}'


def save(output_path: str, data: str, alias: str = None):
    file_name_or_dir_name = os.path.basename(output_path)
    # if contains . , then output to file , else use dirname-to-filename
    should_append_file_name = not '.' in file_name_or_dir_name
    file_path = os.path.dirname(output_path)
    if file_name_or_dir_name.endswith('.symbols'):
        file_name_or_dir_name = file_name_or_dir_name[0:len(
            file_name_or_dir_name)-len('.symbols')]
    # if not specify alias , use file_name
    alias = alias or file_name_or_dir_name
    path = f'{file_path}{os.sep}{file_name_or_dir_name}'
    if not os.path.exists(path):
        os.makedirs(path)

    if should_append_file_name:
        import datetime
        n = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        generate_file = f'{alias}_{n}'
        path += f'{os.sep}{generate_file}'
    with open(f'{path}.symbols', 'w') as f:
        f.write(data)
    with open(f'{path}.info', 'w') as f:
        f.write(alias)
    return path


def load_symbols(file: str) -> Dict:
    print(f'load_ symbols:{file}')
    r = {}
    with open(file, 'r') as f:
        lines = f.read().split('\n')
    for line in lines:
        content = line.split(' ')
        print(content)


def check_exist(elf_file_path: str) -> bool:
    data = load_symbols_by_pwntools(elf_file_path)
    data_len_raw = len(data)
    data_len = 20 if data_len_raw > 20 else data_len_raw
    data_list = list(data)
    step = 10
    while True:
        s = LibcSearcher()
        for i in range(data_len):
            func = data_list[i]
            s.add_condition(func, data[func])
        s.decided()
        same_count = s.db_result[2]
        if same_count > 1:
            if data_len == data_len_raw:
                print('multi fit libc found.')
                return s.db_result[1]
            data_len += step
            step = step * 2 + 10
            if data_len > data_len_raw:
                data_len = data_len_raw
            continue
        if same_count == 0:
            return None
        return s.db_result[1]


def run(elf_file_path: str, output_path: str = None, alias: str = None):
    if alias is None:
        alias = 'user'
    elf_version = get_elf_version(elf_file_path)
    print(
        f'lic_converter:\nelf_version:{elf_version}\nelf_file_path:{elf_file_path}\noutput_path:{output_path}\nalias:{alias}')
    data = load_symbos_line(elf_file_path)
    if not output_path:
        print(data)
        return data
    path = save(output_path=output_path, data=data,
                alias=f'{alias}_{elf_version}')
    return path


if __name__ == '__main__':
    elf_file_path = sys.argv[1]

    if len(sys.argv) == 2:
        run(elf_file_path=elf_file_path)
        sys.exit(0)
    output_path = sys.argv[2]
    alias = sys.argv[3] if len(sys.argv) >= 4 else None
    run(elf_file_path=elf_file_path, output_path=output_path, alias=alias)
