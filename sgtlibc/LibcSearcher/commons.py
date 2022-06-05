commons = ["__libc_start_main_ret", "str_bin_sh",
           "system", "dup2", "read", "write"]

for i in commons:
    globals()[f'SYMBOL_{i}'] = i
