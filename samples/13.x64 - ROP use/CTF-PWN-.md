# CTF-PWN

**来源**：

**内容**：

**附件**：

**答案**：



## 总体思路

> 

## 详细步骤

- 查看文件信息
  - 



## 参考文档

- 常见知识点

  - 汇编

    `leave` equal `mov esp,ebp; pop ebp;`

    `ret` equal `pop eip`

  - 函数参数

    x86函数传参：直接从栈上读

    x64函数传参：按 rdi, rsi, rdx, rcx, r8, r9顺序读，后续的从栈上读

    故x64需要调用ROP实现pop将参数从栈中传入寄存器

- 常用工具

  - pwntools逆向python库
    - [工具的基本使用方法](https://zhuanlan.zhihu.com/p/83373740)，注意安装要使用`pip install pwntools`
    - [官方文档](http://docs.pwntools.com/en/latest/)
    - [官方使用教程](https://github.com/Gallopsled/pwntools-tutorial#readme)
  - Kali
    - checksec：检查样本的基本信息也可以是通过设置 pwntool.context.log_level = 'debug'得到
    - ROPgadget：检查文件中可以利用的`gadget`或`rop-chain`
      - 注意在`python3`版本中，生成的chain需要在所有的字符串前面加上`b`表示十六进制值，否则会出现`str`不能合并`bytes`的报错
    - gdb：程序动态调试工具，也可以直接使用[ida的远程调试功能](https://blog.csdn.net/m0_37157335/article/details/124091097)
  - libc_searcher：用于retlibc题时候查询其libc版本
    - 在线web查询 [推荐的查询器](https://libc.rip/) [稍菜一点的查询器](https://libc.blukat.me/)
    - 离线python `pip install sgtlibcsearcher` ，使用 sgtlibcsearcher ./binary_file func_name:addr+func2_name:addr... --dump binsh 
    - docker部署离线外部查询环境 `docker pull libcyber/srpnode `注意需要更新

- 教程
  - [2019 北航 CTF Pwn入门培训课程（一）](https://www.bilibili.com/video/BV1JV411m7PC?p=1)
    - 基础的rop使用方法
  - [2019 北航 CTF Pwn入门培训课程（二）](https://www.bilibili.com/video/BV1JV411m7PC?p=2)
    - 为什么main的返回地址被替换为`system_addr`后 a=system_ret ;b=p	aram_1
      - ret2libc使用pil节区中的`system`和`/bin/sh`
      - 如果没有的话就看其他函数的地址以查到libc版本，以及其各值的地址
    - 如果是静态编译则使用int80调用rop链
      - ROPgadget
        - 通过`ROPgadget --binary rop --ropchain`获取可以直接使用的rop链
        - 通过`ROPgadget --binary rop --only "pop|ret"`获取可以存值的地方
  - [2019 北航 CTF Pwn入门培训课程（三）](https://www.bilibili.com/video/BV1JV411m7PC?p=3)
    - 待解析
  - [2019 北航 CTF Pwn入门培训课程（四）](https://www.bilibili.com/video/BV1JV411m7PC?p=4)
    - 待解析

- 常见知识点
  - [[CTF pwn]傻傻分不清的execve、int80、syscall、system及shellcode](https://blog.csdn.net/weixin_43363675/article/details/117944212)
  - [C 运算符重载](https://blog.csdn.net/king13059595870/article/details/102647033)
