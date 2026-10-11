set pagination off
set confirm off
set debuginfod enabled off
b *0x401b21
run < work/in3.txt
set $p = 0x4062a0
while $p < 0x406a00
  printf "%p  size=%#lx\n", $p, *(unsigned long*)($p+8)
  set $p = $p + (*(unsigned long*)($p+8) & ~0xf)
end
