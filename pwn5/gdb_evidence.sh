#!/bin/bash
# reproducible gdb evidence for the writeup (run from this directory, ASLR off)
cd "$(dirname "$0")"
gdb -q -batch \
 -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
 -ex 'b *0x555555554000+0x1797' \
 -ex 'b *0x555555554000+0x1810' \
 -ex 'b *0x555555554000+0x1a76' \
 -ex 'run < exploit_input.bin' \
 -ex 'printf "@0x1797 append#1: n=%#lx capacity=%#lx  -> n<=cap passes, loop writes n+1 bytes\n", *(unsigned short*)($rbp-0x12), *(unsigned short*)(*(unsigned long*)($rbp-0x28)+0x100)' \
 -ex 'continue' \
 -ex 'printf "@0x1810 send_state: state=%p capacity=%#lx\n", $rdi, *(unsigned short*)($rdi+0x100)' \
 -ex 'printf "  state[0x108]=%#lx  <- stack canary\n", *(unsigned long*)($rdi+0x108)' \
 -ex 'printf "  state[0x110]=%#lx  <- saved rbp\n", *(unsigned long*)($rdi+0x110)' \
 -ex 'printf "  state[0x118]=%#lx  <- return addr into main (PIE+0x1a9f)\n", *(unsigned long*)($rdi+0x118)' \
 -ex 'continue' \
 -ex 'printf "@0x1797 append#2: n=%#lx capacity=%#lx  -> writes 0x200 bytes over canary/rbp/ret\n", *(unsigned short*)($rbp-0x12), *(unsigned short*)(*(unsigned long*)($rbp-0x28)+0x100)' \
 -ex 'continue' \
 -ex 'printf "@0x1a76 loop epilogue (canary check): rbp=%p state=%p rsp=%p\n", $rbp, $rbp-0x110, $rsp' \
 -ex 'x/8gx $rbp-8' \
 ./homemaker > gdb_evidence_raw.txt 2>&1
grep -a -E '^@|^0x' gdb_evidence_raw.txt
