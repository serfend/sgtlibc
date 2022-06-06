

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
usage: main.py [-h] [-d [DUMP ...]] [-i [INDEX]] [-u [UPDATE]] [funcs_with_addresses]

for search version of libc.you can use like:`sgtlibc puts:aa0+read:140 --dump system binsh` or in python , like : `py:import sgtlibc;s = sgtlibc.LibcSearcher();s.add_condition('puts',0xaa0)`

positional arguments:
  funcs_with_addresses  specify `func-name` and `func address` , split by `|`,eg: puts:aa0+read:140 , its means func-put's address = 0xaa0;func-read addr = 0x140 (default: None).

options:
  -h, --help            show this help message and exit
  -d [DUMP ...], --dump [DUMP ...]
                        select funcs to dump its info (default: ['__libc_start_main_ret', 'system', 'dup2', 'read', 'write', 'str_bin_sh']).
  -i [INDEX], --index [INDEX]
                        db index on multi-database found occation (default: 0).
  -u [UPDATE], --update [UPDATE]
                        update current libc database from internet , need non-microsoft-windows environment (default: False).
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



- run [python code above](/#/Quick Start) , you'll get output-result like following shows:

![image-20220605212842313](https://raw.githubusercontent.com/serfend/res.image.reference/main/image-20220605212842313.png)

- run command in terminal , you'll get output-result like following shows:

  ![image-20220605213023151](https://raw.githubusercontent.com/serfend/res.image.reference/main/image-20220605213023151.png)

- use in `pwntools`

```python
from pwn import * # should run pip install pwntools before
import sgtlibc
s = libc.Searcher()
puts_addr = 0xff1234567aa0 # from leak data
s.add_condition('puts',puts_addr)
libc = s.dump() # search libc , if returns multi-result ,default use index-0's result
offset = puts_addr - libc[sgtlibc.s_puts]  # puts_write
system_addr = p64(libc[sgtlibc.s_system] + offset)
binsh_addr = p64(libc[sgtlibc.s_binsh] + offset)
```





## Notice

> default libc database is update long-time ago , we fully recommanded to update it by run `sgtlibc --update`



## Status

![Alt](https://repobeats.axiom.co/api/embed/7d8920fddffed00ee7feb8d172bc7b48c86da3b8.svg "Repobeats analytics image")
