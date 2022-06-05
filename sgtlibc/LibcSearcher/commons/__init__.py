commons = ["__libc_start_main_ret", "str_bin_sh",
           "system", "dup2", "read", "write", "puts"]

for i in commons:
    globals()[f'SYMBOL_{i}'] = i

libc_start_main = SYMBOL___libc_start_main_ret
str_bin_sh = SYMBOL_str_bin_sh
system = SYMBOL_system
dup2 = SYMBOL_dup2
read = SYMBOL_read
write = SYMBOL_write
puts = SYMBOL_puts
