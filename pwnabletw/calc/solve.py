from pwn import *

elf = ELF("./calc")

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

def main():
    p = conn()

    # pwn it

    p.interactive()

if __name__ == '__main__':
    main()

