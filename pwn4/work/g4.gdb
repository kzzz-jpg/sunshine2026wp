set pagination off
set confirm off
set debuginfod enabled off
b *0x401b21
run < work/in2.txt
printf "src=%p dst=%p\n", $rbx, $rbp
printf "dst ledger=%p size=%lu\n", *(void**)($rbp+0x18), *(unsigned long*)($rbp+0x20)
info proc mappings
x/40gx 0x405000
