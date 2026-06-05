#!/usr/bin/env python3

from pwn import *

elf = ELF("libc_32.so.6")
libc = ELF("./libc_32.so.6")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()

def conn():
    if args.REMOTE:
        p = remote("addr", 1337)
    else:
        if args.GDB:
            p = gdb.debug([elf.path], aslr=True, api=False, gdbscript="""
                b *0x080487d4 
                b *0x08048863
                b *0x08048879
                b *0x08048646
                b *0x0804869a
                b *0x0804872c
                """)
        else:
            p = process([elf.path])

    return p

def main():
    p = conn()

    # pwn it

    p.interactive()

if __name__ == '__main__':
    main()

