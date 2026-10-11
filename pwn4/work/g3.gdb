set pagination off
set confirm off
set debuginfod enabled off
b *0x401b21
run < work/in1.txt
x/6gx 0x405280
x/4gx 0x4062a0
x/8gx 0x4062e0
x/4gx 0x406370
x/6gx 0x4063b0
printf "heap base guess 0x405000, tcache struct at 0x405010\n"
p/x *(unsigned long*)0x405010
