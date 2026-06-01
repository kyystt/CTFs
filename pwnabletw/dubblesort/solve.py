from pwn import *

elf = ELF("./dubblesort_patched")
libc = ELF("./libc.so.6")

context.binary = elf
context.terminal = "kitty @ launch --location=vsplit --cwd=current".split()
context.log_level = 'debug'

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
    p.sendafter(b"name :", b"sexo sem parar")


    p.interactive()

if __name__ == '__main__':
    main()

