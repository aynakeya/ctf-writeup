---
title: "[Pwn] how2pwn [CSAW CTF Qual 2022]"
date: 2022-09-11 16:35:00
---

# 0x0 Introduction

how2pwn is a series of beginner-friendly pwn challenges to make pwning and shellcoding more approachable.

Servers:

nc how2pwn.chal.csaw.io 60001

nc how2pwn.chal.csaw.io 60002

nc how2pwn.chal.csaw.io 60003

nc how2pwn.chal.csaw.io 60004

Files: [public.zip](public.zip)


# 0x2 Vuln & Exploits

Each step have restriction in some way.

Each step require you to write a shellcode that print out the flag.


## Step1

no restriction, just send a `execve('/bin/sh')` shellcode to get a shell and get the flag

exploit: [exploit-1.py](chal1.py)

## Step2

only allow 0x10 bytes shellcode.

solution is pretty simple, since it calls `read(0, buf, 0x10)`. And `rsi` hasn't change since that read call.

we can craft a shellcode that call `read` again and allow us to read more bytes into the memory. 

Therefore, we got enough space for the get shell payload.

exploit: [exploit-2.py](chal2.py)

## Step3

binary uses seccomp to block most of syscall. However, it doesn't block syscall in x86.

therefore, we can use `retf` return to x86 shellcode, use x86 shellcode to bypass the restriction and get the flag

use the hint you get from step2, you can craft the payload pretty easily

**hint from step2**
```
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# 1. In this challenge, you can't open a file because of the strict sandbox
# 2. But there is a vul about the sanbox, it doesn't check the syscall arch.
# 3. We can use x86 syscalls to bypass it. All x86 syscalls: https://syscalls32.paolostivanin.com/
# 4. You may find x86 can't visite x64 address because x64 address is too long to be stored in the x86 register. However, we still have syscall_mmap, which could allocate a chunk of memory, for example 0xcafe000, so we can visite this address in x86 mode.
# 5. There is a demo for retf: https://github.com/n132/n132.github.io/blob/master/code/GoogleCTF/S2/XxX/pwn.S
```

exploit: [exploit-3.py](chal3.py)

## Step4

a `copied` version of [https://n132.github.io/2022/07/04/S2.html](https://n132.github.io/2022/07/04/S2.html)

The program have a sandbox that only allows __NR_seccomp __NR_fork __NR_ioctl __NR_exit

simple version of the solution

1. create a listener using seccomp
2. in the child process, listen to all the syscall. And change the syscall status from denied to allow whenever a syscall is called by user
3. in the parent process, wait until child process started.  ret to x86 and print out the flag using shellcode.

rewrite the exploit in [exp.cc](https://github.com/n132/n132.github.io/blob/master/code/GoogleCTF/S2/XxX/exp.cc) asm and get the shell


exploits: [chal4struct.c](chal4struct.c) (for getting the value that will be used in shellcode), [exploit-4.py](chal4.py)

# 0x4 Flag

`flag{8d13cfa357978684be9809172d3033ce739015f5}`