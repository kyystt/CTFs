#!/usr/bin/env python3

from pwn import *

elf = ELF("./hacknote_patched")
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

def recv_menu(p):
    p.recvuntil("Your choice :")

def add_note(p, size, content):
    recv_menu(p)
    p.send(b"1")
    p.sendafter(b"Note size :", str(size).encode())
    p.sendafter(b"Content :", content)

def delete_note(p, idx):
    recv_menu(p)
    p.send(b"2")
    p.sendafter(b"Index :", str(idx).encode())
    return p.recvline()

def print_note(p, idx):
    recv_menu(p)
    p.send(b"3")
    p.sendafter(b"Index :", str(idx).encode())
    return p.recvline()

def main():
    p = conn()

    # pwn it

    p.interactive()

if __name__ == '__main__':
    main()

