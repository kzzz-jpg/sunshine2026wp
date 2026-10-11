set pagination off
set confirm off
set debuginfod enabled off
b *0x401b21
run < work/in1.txt
printf "SRC(rbx)=%p DST(rbp)=%p\n", $rbx, $rbp
printf "src: bal=%lu ledger=%p size=%lu active=%d\n", *(unsigned long*)($rbx+0x10), *(void**)($rbx+0x18), *(unsigned long*)($rbx+0x20), *(int*)($rbx+0x28)
printf "dst: bal=%lu ledger=%p size=%lu active=%d\n", *(unsigned long*)($rbp+0x10), *(void**)($rbp+0x18), *(unsigned long*)($rbp+0x20), *(int*)($rbp+0x28)
info proc mappings
p/x *(void**)0x4040c0
p/x *(void**)0x4040c8
