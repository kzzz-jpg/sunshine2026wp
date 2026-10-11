set pagination off
set confirm off
set debuginfod enabled off
b *0x401b21
run < work/in3.txt
printf "\n===== wallets before/after Transfer(0->1) =====\n"
printf "slot0 = %p\n", *(void**)0x4040c0
printf "slot1 = %p\n", *(void**)0x4040c8
printf "heap base: see mappings\n"
info proc mappings
printf "\n===== tcache_perthread_struct @ 0x405010 =====\n"
x/16hx 0x405010
printf "entries[0..15] @ 0x405090:\n"
x/16gx 0x405090
printf "\n===== freed S ledger (0x90 chunk) =====\n"
x/6gx 0x4062e0
