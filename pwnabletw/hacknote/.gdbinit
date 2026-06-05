b *0x080487d4 
b *0x08048863
b *0x08048879
b *0x08048646
b *0x0804869a
b *0x0804872c

define shownotes
    set $note_pool = 0x0804a050
    set $i = 0

    printf "\n============= notas ativas =============\n"

    while $i < 6
        set $note_addr = *(int *)($note_pool + ($i * 4))

        if $note_addr != 0
            set $func_ptr = *(int *)$note_addr
            set $content_ptr = *(int *)($note_addr + 4)

            printf "[%d] Note  Struct @ 0x%08x\n", $i, $note_addr
            printf "    |- func_ptr   : 0x%08x\n", $func_ptr
            printf "    |- content    : 0x%08x\n", $content_ptr
        else
            printf "[%d] (Empty)\n", $i
        end

        set $i = $i + 1
    end

    printf "===========================================\n\n"
end

document shownotes
    Traverses the note_pool array at 0x0804a050 and prints the Note structure
end

define hook-stop
    shownotes
end
