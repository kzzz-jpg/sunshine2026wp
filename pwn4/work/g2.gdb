set pagination off
set confirm off
set debuginfod enabled off
b *0x401b21
run < work/in1.txt
printf "SRC=%p DST=%p\n", $rbx, $rbp
printf "src ledger=%p size=%lu active=%d\n", *(void**)($rbx+0x18), *(unsigned long*)($rbx+0x20), *(int*)($rbx+0x28)
printf "dst ledger=%p size=%lu active=%d\n", *(void**)($rbp+0x18), *(unsigned long*)($rbp+0x20), *(int*)($rbp+0x28)
p/x $rbp
info proc mappings
x/32gx 0x405000
x/12gx 0x4062a0
x/12gx 0x406370
x/8gx 0x405290
