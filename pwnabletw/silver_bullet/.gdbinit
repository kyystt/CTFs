define bullet
    set $bullet = $ebp - 0x34
    
    set $desc_start  = $bullet
    set $desc_end    = $bullet + 47
    set $power_start = $bullet + 48
    set $power_end   = $bullet + 51

    printf "\n================== BULLET MEMORY MAP ==================\n"
    printf "  [ Struct Base ]    0x%08x\n", $bullet
    printf "  |-- desc start :   0x%08x\n", $desc_start
    printf "  |-- desc end   :   0x%08x  (Index 47)\n", $desc_end
    printf "  |-- power start:   0x%08x  (Index 48)\n", $power_start
    printf "  |-- power end  :   0x%08x  (Index 51)\n", $power_end
    printf "-------------------------------------------------------\n"
    
    x/16wx $bullet
    
    printf "=======================================================\n\n"
end

define hook-stop
    bullet
end
