import gdb

class PrintList(gdb.Command):
    def __init__(self):
        super(PrintList, self).__init__("printlist", gdb.COMMAND_USER)

    def parse(self, src):
        return int.from_bytes(src[0:4], byteorder='little'), int.from_bytes(src[4:8], byteorder='little'), int.from_bytes(src[8:12], byteorder='little'), int.from_bytes(src[12:16], byteorder='little')


    def invoke(self, arg, from_tty):
        print()
        print("="*50)
        try:
            inferior = gdb.selected_inferior()
            head = 0x0804b068
            i = 1
            head_bytes = inferior.read_memory(head, 0x10)
            _, _, next_node, _ = self.parse(head_bytes)

            while next_node != 0:
                node = inferior.read_memory(next_node, 0x10)

                actual_node = next_node
                name_addr, price, next_node, prev_node = self.parse(node)

                try:
                    char_ptr = gdb.parse_and_eval(f"(char *){name_addr}")
                    name_str = char_ptr.string(encoding='utf-8', errors='ignore')

                except gdb.MemoryError:
                    name_str = "<Invalid Memory Read>"

                print(f"[{i}] Node              @ {hex(actual_node)}")
                print(f"        |- name_address @ {hex(name_addr)} -> {name_str}")
                print(f"        |- price        : {price}")
                print(f"        |- next_node    @ {hex(next_node)}")
                print(f"        |- prev_node    @ {hex(prev_node)}")

                i += 1

        except gdb.MemoryError:
            print("[!] Memory Error")

        print("="*50)

PrintList()
